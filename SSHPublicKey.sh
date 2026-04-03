#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME=$(basename "$0")
DRY_RUN=0
ASSUME_YES=0
SSH_USER=""
AUTHORIZED_KEY_FILE=""
AUTHORIZED_KEY=""
ONLY_LIST=0
ONLY_DELETE=0
ONLY_HARDEN_SSH=0
DELETE_USER=""
SKIP_SERVICE_RESTART=0
CUSTOM_PORT=""

print_usage() {
  cat <<USAGE
用法:
  sudo ./$SCRIPT_NAME [选项]

功能:
  1. 列出系统中的本地用户
  2. 删除指定用户及其常见残留信息（家目录、邮件、crontab、sudoers片段等）
  3. 为指定用户配置 SSH 公钥登录
  4. 随机选择一个未被占用的高位端口并写入 sshd 配置

常用示例:
  sudo ./$SCRIPT_NAME --list-users
  sudo ./$SCRIPT_NAME --delete-user alice
  sudo ./$SCRIPT_NAME --ssh-user alice --authorized-key 'ssh-ed25519 AAAA... alice@host'
  sudo ./$SCRIPT_NAME --delete-user bob --ssh-user admin --authorized-key 'ssh-ed25519 AAAA... admin@host'
  sudo ./$SCRIPT_NAME --ssh-user admin --authorized-key-file /root/admin.pub --port 40222

选项:
  --list-users                 仅列出本地用户
  --delete-user USER          删除指定用户及其常见残留
  --ssh-user USER             为该用户配置 SSH 公钥登录
  --authorized-key TEXT       直接写入一条公钥字符串
  --authorized-key-file ARG   兼容旧参数；若 ARG 是文件则读取文件，否则按公钥字符串处理
  --port PORT                 指定 SSH 监听端口；不指定则随机挑选未占用高位端口
  --only-delete               仅执行删除用户逻辑
  --only-harden-ssh           仅执行 SSH 加固逻辑
  --dry-run                   只打印将执行的动作，不实际修改
  --yes                       跳过交互确认
  --skip-service-restart      修改 sshd 配置后不重载服务
  -h, --help                  显示帮助

说明:
  - 需要 root 权限运行。
  - 脚本会在 /etc/ssh/codex_sshd_config.d 下写入 00-codex-hardening.conf。
  - 脚本不会直接改写 /etc/ssh/sshd_config 里的 Port 等原有配置，只会确保一个 Include 引导行存在。
  - 执行删除用户前会尝试停止该用户进程并删除家目录、邮件文件和常见 sudoers 片段。
USAGE
}

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

warn() {
  printf '[%s] [WARN] %s\n' "$(date '+%F %T')" "$*" >&2
}

die() {
  printf '[%s] [ERROR] %s\n' "$(date '+%F %T')" "$*" >&2
  exit 1
}

run_cmd() {
  if (( DRY_RUN )); then
    printf '[DRY-RUN] '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

confirm() {
  local prompt="$1"
  if (( ASSUME_YES )); then
    return 0
  fi
  read -r -p "$prompt [y/N]: " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

passdb_get() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd "$1"
  else
    awk -F: -v user="$1" '$1 == user {print; exit}' /etc/passwd 2>/dev/null
  fi
}

passdb_all() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd
  else
    cat /etc/passwd
  fi
}

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "请使用 root 或 sudo 运行。"
  fi
}

user_exists() {
  [[ -n "$(passdb_get "$1")" ]]
}

uid_min() {
  local value
  value=$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/ {print $2; exit}' /etc/login.defs 2>/dev/null || true)
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$value"
  else
    printf '1000\n'
  fi
}

list_users() {
  local min_uid
  min_uid=$(uid_min)
  printf '%-20s %-8s %-35s %s\n' 'USER' 'UID' 'HOME' 'SHELL'
  printf '%-20s %-8s %-35s %s\n' '----' '---' '----' '-----'
  passdb_all | awk -F: -v min_uid="$min_uid" '
    {
      shell=$7
      uid=$3
      if (uid == 0 || uid >= min_uid) {
        printf "%-20s %-8s %-35s %s\n", $1, $3, $6, shell
      }
    }
  '
}

get_user_home() {
  passdb_get "$1" | awk -F: 'NR==1 {print $6}'
}

get_user_group() {
  if command -v id >/dev/null 2>&1; then
    id -gn "$1"
  else
    passdb_get "$1" | awk -F: 'NR==1 {print $1}'
  fi
}

is_safe_home_dir() {
  local home_dir="$1"
  [[ -n "$home_dir" ]] || return 1
  [[ "$home_dir" != "/" ]] || return 1
  [[ "$home_dir" != "/root" ]] || return 1
  [[ "$home_dir" == /* ]] || return 1
}

ensure_ssh_user() {
  local user="$1"
  user_exists "$user" || die "用户不存在: $user"
}

kill_user_processes() {
  local user="$1"
  if pgrep -u "$user" >/dev/null 2>&1; then
    warn "发现用户 $user 的活动进程，尝试终止。"
    run_cmd pkill -TERM -u "$user" || true
    sleep 2
    if pgrep -u "$user" >/dev/null 2>&1; then
      warn "仍有进程存活，发送 KILL。"
      run_cmd pkill -KILL -u "$user" || true
    fi
  fi
}

cleanup_user_artifacts() {
  local user="$1"
  local home_dir
  home_dir=$(get_user_home "$user" || true)

  if [[ -n "$home_dir" && -d "$home_dir" ]]; then
    if is_safe_home_dir "$home_dir"; then
      log "删除家目录: $home_dir"
      run_cmd rm -rf "$home_dir"
    else
      die "检测到不安全的家目录路径，已停止删除: $home_dir"
    fi
  fi

  if command -v crontab >/dev/null 2>&1; then
    run_cmd crontab -r -u "$user" 2>/dev/null || true
  fi

  run_cmd rm -f "/var/spool/mail/$user" "/var/mail/$user"
  run_cmd rm -f "/etc/sudoers.d/$user" "/etc/sudoers.d/90-$user" "/etc/sudoers.d/${user}-sudo"
  run_cmd rm -rf "/var/spool/cron/$user" "/var/spool/cron/crontabs/$user"
}

delete_user() {
  local user="$1"
  local group_name=""
  local home_dir=""
  [[ "$user" != "root" ]] || die "禁止删除 root。"
  user_exists "$user" || die "用户不存在: $user"
  group_name=$(get_user_group "$user" 2>/dev/null || true)
  home_dir=$(get_user_home "$user" 2>/dev/null || true)

  if [[ -n "$home_dir" && ! -d "$home_dir" ]]; then
    warn "用户 $user 的家目录不存在: $home_dir"
  elif [[ -n "$home_dir" ]] && ! is_safe_home_dir "$home_dir"; then
    die "用户 $user 的家目录路径异常，已拒绝删除: $home_dir"
  fi

  if ! confirm "确认删除用户 $user 及其常见残留信息吗？"; then
    log "已取消删除用户。"
    return 0
  fi

  kill_user_processes "$user"
  cleanup_user_artifacts "$user"

  if command -v userdel >/dev/null 2>&1; then
    log "执行 userdel -r $user"
    run_cmd userdel -r "$user" || {
      warn "userdel -r 失败，尝试 userdel 后手动清理。"
      run_cmd userdel "$user"
    }
  else
    die "当前系统没有 userdel，无法安全删除用户。"
  fi

  if [[ -n "$group_name" && "$group_name" == "$user" ]] && command -v groupdel >/dev/null 2>&1; then
    run_cmd groupdel "$group_name" 2>/dev/null || true
  fi

  log "用户 $user 删除流程完成。"
}

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn '( sport = :'"$port"' )' 2>/dev/null | grep -q .
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 1
  fi
}

choose_random_port() {
  local candidate
  local attempts=0
  while (( attempts < 200 )); do
    if command -v shuf >/dev/null 2>&1; then
      candidate=$(shuf -i 20000-60999 -n 1)
    else
      candidate=$(( ((RANDOM << 15) ^ RANDOM) % 41000 + 20000 ))
    fi
    if ! port_in_use "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
    attempts=$((attempts + 1))
  done
  die "无法找到空闲高位端口，请手动指定 --port。"
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] || die "端口必须是数字: $port"
  (( port >= 1024 && port <= 65535 )) || die "端口需在 1024-65535 之间: $port"
  if port_in_use "$port"; then
    die "端口已被占用: $port"
  fi
}

ensure_authorized_key_source() {
  if [[ -n "$AUTHORIZED_KEY_FILE" && -n "$AUTHORIZED_KEY" ]]; then
    die "--authorized-key 与 --authorized-key-file 只能二选一。"
  fi
  if [[ -z "$AUTHORIZED_KEY_FILE" && -z "$AUTHORIZED_KEY" ]]; then
    die "配置 SSH 公钥登录时，必须提供 --authorized-key 或 --authorized-key-file。"
  fi
}

resolve_authorized_key() {
  if [[ -n "$AUTHORIZED_KEY" ]]; then
    printf '%s' "$AUTHORIZED_KEY"
  elif [[ -n "$AUTHORIZED_KEY_FILE" ]]; then
    if [[ -f "$AUTHORIZED_KEY_FILE" ]]; then
      cat "$AUTHORIZED_KEY_FILE"
    else
      printf '%s' "$AUTHORIZED_KEY_FILE"
    fi
  fi
}

ensure_sshd_include() {
  local config_file="/etc/ssh/sshd_config"
  local include_line='Include /etc/ssh/codex_sshd_config.d/*.conf'
  local tmp_file

  if (( DRY_RUN )); then
    log "将确保 $include_line 位于 $config_file 顶部"
    return 0
  fi

  tmp_file=$(mktemp)
  {
    printf '%s\n' "$include_line"
    awk '!/^[[:space:]]*#?[[:space:]]*Include[[:space:]]+\/etc\/ssh\/codex_sshd_config\.d\/\*\.conf([[:space:]]+.*)?$/' "$config_file"
  } > "$tmp_file"
  cat "$tmp_file" > "$config_file"
  rm -f "$tmp_file"
}

write_authorized_key() {
  local user="$1"
  local home_dir ssh_dir auth_file key_content group_name
  home_dir=$(get_user_home "$user")
  [[ -n "$home_dir" && -d "$home_dir" ]] || die "找不到用户家目录: $user"
  group_name=$(get_user_group "$user")

  ssh_dir="$home_dir/.ssh"
  auth_file="$ssh_dir/authorized_keys"

  key_content=$(resolve_authorized_key)

  [[ "$key_content" =~ ^(ssh-|ecdsa-|sk-ssh-) ]] || warn "提供的内容看起来不像标准 SSH 公钥，请再次确认。"

  if (( DRY_RUN )); then
    log "将创建目录 $ssh_dir 并写入 authorized_keys"
  else
    install -d -m 700 -o "$user" -g "$group_name" "$ssh_dir"
    touch "$auth_file"
    grep -qxF "$key_content" "$auth_file" 2>/dev/null || printf '%s\n' "$key_content" >> "$auth_file"
    chown "$user:$group_name" "$auth_file"
    chmod 600 "$auth_file"
  fi
}

write_sshd_dropin() {
  local port="$1"
  local dropin_dir="/etc/ssh/codex_sshd_config.d"
  local dropin_file="$dropin_dir/00-codex-hardening.conf"

  if (( DRY_RUN )); then
    log "将写入 SSH 加固配置到 $dropin_file"
    return 0
  fi

  mkdir -p "$dropin_dir"
  cat > "$dropin_file" <<CFG
# Managed by $SCRIPT_NAME on $(date '+%F %T')
Port $port
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PermitRootLogin prohibit-password
X11Forwarding no
AllowAgentForwarding no
MaxAuthTries 3
LoginGraceTime 30
AuthorizedKeysFile .ssh/authorized_keys
CFG
}

warn_legacy_codex_dropin() {
  local legacy_file="/etc/ssh/sshd_config.d/99-codex-hardening.conf"
  if [[ -f "$legacy_file" ]]; then
    warn "检测到旧版 drop-in: $legacy_file。若其中包含 Port，sshd 可能同时监听旧端口；建议手动检查或删除该文件。"
  fi
}

effective_sshd_value() {
  local key="$1"
  sshd -T 2>/dev/null | awk -v key="$key" '$1 == key { $1=""; sub(/^ /, "", $0); print; exit }'
}

verify_effective_sshd_settings() {
  local expected_port="$1"
  local password_auth pubkey_auth root_login auth_keys
  local ports=()
  local extra_ports=()
  local found_port=0

  if ! command -v sshd >/dev/null 2>&1; then
    warn "未找到 sshd，跳过实际生效值校验。"
    return 0
  fi

  if (( DRY_RUN )); then
    log "将校验 SSH drop-in 是否实际生效。"
    return 0
  fi

  while IFS= read -r port; do
    [[ -n "$port" ]] || continue
    ports+=("$port")
    if [[ "$port" == "$expected_port" ]]; then
      found_port=1
    else
      extra_ports+=("$port")
    fi
  done < <(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }')

  (( found_port )) || die "新的 SSH 端口 $expected_port 未实际生效，请检查 Include 顺序和其他 sshd 配置。"
  if (( ${#extra_ports[@]} > 0 )); then
    die "检测到其他 SSH 端口仍在生效: ${extra_ports[*]}。当前脚本遵循“只新增 drop-in、不改原 Port”的策略，请手动清理旧 Port 配置。"
  fi

  password_auth=$(effective_sshd_value passwordauthentication)
  pubkey_auth=$(effective_sshd_value pubkeyauthentication)
  root_login=$(effective_sshd_value permitrootlogin)
  auth_keys=$(effective_sshd_value authorizedkeysfile)

  [[ "$password_auth" == "no" ]] || die "PasswordAuthentication 未生效，当前值: ${password_auth:-<empty>}"
  [[ "$pubkey_auth" == "yes" ]] || die "PubkeyAuthentication 未生效，当前值: ${pubkey_auth:-<empty>}"
  [[ "$root_login" == "prohibit-password" ]] || die "PermitRootLogin 未生效，当前值: ${root_login:-<empty>}"
  [[ "$auth_keys" == *".ssh/authorized_keys"* ]] || die "AuthorizedKeysFile 未生效，当前值: ${auth_keys:-<empty>}"
}

validate_sshd_config() {
  if command -v sshd >/dev/null 2>&1; then
    if (( DRY_RUN )); then
      log "将执行 sshd -t 校验配置。"
    else
      sshd -t || die "sshd 配置校验失败，请检查 /etc/ssh/sshd_config 与 drop-in 文件。"
    fi
  else
    warn "未找到 sshd，跳过配置校验。"
  fi
}

reload_sshd_service() {
  if (( SKIP_SERVICE_RESTART )); then
    warn "已跳过 ssh 服务重载，请手动执行 systemctl reload sshd 或对应命令。"
    return 0
  fi

  if (( DRY_RUN )); then
    log "将尝试重载 sshd/ssh 服务。"
    return 0
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled sshd >/dev/null 2>&1 || systemctl status sshd >/dev/null 2>&1; then
      systemctl reload sshd || systemctl restart sshd
      return 0
    fi
    if systemctl is-enabled ssh >/dev/null 2>&1 || systemctl status ssh >/dev/null 2>&1; then
      systemctl reload ssh || systemctl restart ssh
      return 0
    fi
  fi

  if command -v service >/dev/null 2>&1; then
    service sshd reload >/dev/null 2>&1 && return 0
    service ssh reload >/dev/null 2>&1 && return 0
    service sshd restart >/dev/null 2>&1 && return 0
    service ssh restart >/dev/null 2>&1 && return 0
  fi

  warn "未能自动重载 ssh 服务，请手动重载或重启。"
}

harden_ssh() {
  local user="$1"
  local port="$CUSTOM_PORT"

  ensure_ssh_user "$user"
  ensure_authorized_key_source

  if [[ -z "$port" ]]; then
    port=$(choose_random_port)
  else
    validate_port "$port"
  fi

  log "将为用户 $user 配置密钥登录，SSH 端口设为 $port"

  write_authorized_key "$user"
  ensure_sshd_include
  write_sshd_dropin "$port"
  warn_legacy_codex_dropin
  validate_sshd_config
  verify_effective_sshd_settings "$port"
  reload_sshd_service

  log "SSH 加固完成。请使用以下方式登录：ssh -p $port $user@<服务器IP>"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --list-users)
        ONLY_LIST=1
        shift
        ;;
      --delete-user)
        [[ $# -ge 2 ]] || die "--delete-user 需要一个用户名参数。"
        DELETE_USER="$2"
        shift 2
        ;;
      --ssh-user)
        [[ $# -ge 2 ]] || die "--ssh-user 需要一个用户名参数。"
        SSH_USER="$2"
        shift 2
        ;;
      --authorized-key)
        [[ $# -ge 2 ]] || die "--authorized-key 需要一个公钥内容。"
        AUTHORIZED_KEY="$2"
        shift 2
        ;;
      --authorized-key-file)
        [[ $# -ge 2 ]] || die "--authorized-key-file 需要一个文件路径或公钥内容。"
        AUTHORIZED_KEY_FILE="$2"
        shift 2
        ;;
      --authorized-key-text)
        [[ $# -ge 2 ]] || die "--authorized-key-text 需要一个公钥内容。"
        AUTHORIZED_KEY="$2"
        shift 2
        ;;
      --port)
        [[ $# -ge 2 ]] || die "--port 需要一个端口号。"
        CUSTOM_PORT="$2"
        shift 2
        ;;
      --only-delete)
        ONLY_DELETE=1
        shift
        ;;
      --only-harden-ssh)
        ONLY_HARDEN_SSH=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --yes)
        ASSUME_YES=1
        shift
        ;;
      --skip-service-restart)
        SKIP_SERVICE_RESTART=1
        shift
        ;;
      -h|--help)
        print_usage
        exit 0
        ;;
      *)
        die "未知参数: $1"
        ;;
    esac
  done
}

main() {
  parse_args "$@"

  if (( ONLY_LIST )); then
    list_users
    exit 0
  fi

  if [[ -z "$DELETE_USER" && -z "$SSH_USER" ]]; then
    print_usage
    exit 0
  fi

  require_root

  command -v awk >/dev/null 2>&1 || die "缺少命令: awk"
  command -v grep >/dev/null 2>&1 || die "缺少命令: grep"
  command -v sed >/dev/null 2>&1 || die "缺少命令: sed"

  if (( ONLY_DELETE && ONLY_HARDEN_SSH )); then
    die "--only-delete 与 --only-harden-ssh 不能同时使用。"
  fi

  if [[ -n "$DELETE_USER" && -n "$SSH_USER" && "$DELETE_USER" == "$SSH_USER" ]]; then
    die "同一轮执行中，不能既删除用户又为该用户配置 SSH。"
  fi

  if (( ONLY_DELETE )); then
    [[ -n "$DELETE_USER" ]] || die "使用 --only-delete 时必须提供 --delete-user USER。"
    delete_user "$DELETE_USER"
    exit 0
  fi

  if (( ONLY_HARDEN_SSH )); then
    [[ -n "$SSH_USER" ]] || die "使用 --only-harden-ssh 时必须提供 --ssh-user USER。"
    harden_ssh "$SSH_USER"
    exit 0
  fi

  list_users

  if [[ -n "$DELETE_USER" ]]; then
    delete_user "$DELETE_USER"
  fi

  if [[ -n "$SSH_USER" ]]; then
    harden_ssh "$SSH_USER"
  fi
}

main "$@"
