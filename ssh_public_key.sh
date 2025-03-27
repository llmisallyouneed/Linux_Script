#!/usr/bin/env bash
#=============================================================
# Modified version of SSH Key Installer
# Original: https://github.com/P3TERX/SSH_Key_Installer
# Description: Install SSH keys via GitHub, URL or local files
# Version: 3.0
#=============================================================

VERSION=3.0
RED_FONT_PREFIX="\033[31m"
LIGHT_GREEN_FONT_PREFIX="\033[1;32m"
YELLOW_FONT_PREFIX="\033[33m"
FONT_COLOR_SUFFIX="\033[0m"
INFO="[${LIGHT_GREEN_FONT_PREFIX}INFO${FONT_COLOR_SUFFIX}]"
WARN="[${YELLOW_FONT_PREFIX}WARN${FONT_COLOR_SUFFIX}]"
ERROR="[${RED_FONT_PREFIX}ERROR${FONT_COLOR_SUFFIX}]"
[ $EUID != 0 ] && SUDO=sudo

# Check OS type
check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif [ $(uname -o) == "Android" ]; then
        OS="termux"
    elif type -p sw_vers >/dev/null 2>&1; then
        OS="macos"
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        OS="unknown"
    fi
    echo -e "${INFO} Detected OS: ${OS}"
}

# Check dependencies
check_dependencies() {
    if ! command -v curl &>/dev/null; then
        echo -e "${WARN} curl not found. Attempting to install..."
        if [ "$OS" = "debian" ] || [ "$OS" = "ubuntu" ]; then
            $SUDO apt-get update
            $SUDO apt-get install -y curl
        elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ]; then
            $SUDO yum install -y curl
        elif [ "$OS" = "termux" ]; then
            pkg install -y curl
        elif [ "$OS" = "macos" ]; then
            brew install curl
        else
            echo -e "${ERROR} Please install curl manually."
            exit 1
        fi
    fi
}

USAGE() {
    echo "
SSH Key Installer $VERSION

Usage:
  bash <(curl -fsSL git.io/key.sh) [options...] <arg>

Options:
  -o    Overwrite mode, this option is valid at the top
  -g    Get the public key from GitHub, the arguments is the GitHub ID
  -u    Get the public key from the URL, the arguments is the URL
  -f    Get the public key from the local file, the arguments is the local file path
  -p    Change SSH port, the arguments is port number
  -d    Disable password login
  -b    Create backup of original SSH configuration
  -h    Display this help message"
}

backup_config() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_dir="${HOME}/.ssh/backups"
    mkdir -p "$backup_dir"
    
    if [ $(uname -o) == "Android" ]; then
        if [ -f "$PREFIX/etc/ssh/sshd_config" ]; then
            cp "$PREFIX/etc/ssh/sshd_config" "${backup_dir}/sshd_config.${timestamp}"
            echo -e "${INFO} Backup created at ${backup_dir}/sshd_config.${timestamp}"
        fi
    else
        if [ -f "/etc/ssh/sshd_config" ]; then
            $SUDO cp "/etc/ssh/sshd_config" "${backup_dir}/sshd_config.${timestamp}"
            $SUDO chmod 644 "${backup_dir}/sshd_config.${timestamp}"
            echo -e "${INFO} Backup created at ${backup_dir}/sshd_config.${timestamp}"
        fi
    fi
    
    if [ -f "${HOME}/.ssh/authorized_keys" ]; then
        cp "${HOME}/.ssh/authorized_keys" "${backup_dir}/authorized_keys.${timestamp}"
        echo -e "${INFO} Backup created at ${backup_dir}/authorized_keys.${timestamp}"
    fi
}

validate_port() {
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        echo -e "${ERROR} Invalid port number: ${SSH_PORT}"
        echo -e "${INFO} Port must be a number between 1-65535"
        exit 1
    fi
    echo -e "${INFO} Valid port number: ${SSH_PORT}"
}

get_github_key() {
    if [ "${KEY_ID}" == '' ]; then
        read -e -p "Please enter the GitHub account: " KEY_ID
        [ "${KEY_ID}" == '' ] && echo -e "${ERROR} Invalid input." && exit 1
    fi
    echo -e "${INFO} The GitHub account is: ${KEY_ID}"
    echo -e "${INFO} Getting key from GitHub..."
    
    local response
    response=$(curl -fsSL -w "%{http_code}" -o /tmp/github_key.txt https://github.com/${KEY_ID}.keys)
    
    if [ "$response" == "404" ]; then
        echo -e "${ERROR} GitHub account not found."
        exit 1
    elif [ "$response" != "200" ]; then
        echo -e "${ERROR} Failed to connect to GitHub (HTTP ${response})."
        exit 1
    fi
    
    PUB_KEY=$(cat /tmp/github_key.txt)
    rm -f /tmp/github_key.txt
    
    if [ -z "$PUB_KEY" ]; then
        echo -e "${ERROR} This account has no public SSH keys."
        exit 1
    fi
    
    # Count keys found
    key_count=$(echo "$PUB_KEY" | wc -l)
    echo -e "${INFO} Found ${key_count} SSH key(s)."
    
    # Allow user to select a key if multiple found
    if [ "$key_count" -gt 1 ]; then
        echo -e "${INFO} Multiple keys found. Displaying all keys:"
        local i=1
        echo "$PUB_KEY" | while read -r key; do
            key_type=$(echo "$key" | awk '{print $1}')
            key_comment=$(echo "$key" | awk '{if (NF>2) print $NF}')
            echo "  ${i}: ${key_type} ${key_comment:-<no comment>}"
            i=$((i+1))
        done
        
        read -e -p "Enter key number to use (default: all): " key_num
        if [[ "$key_num" =~ ^[0-9]+$ ]] && [ "$key_num" -ge 1 ] && [ "$key_num" -le "$key_count" ]; then
            PUB_KEY=$(echo "$PUB_KEY" | sed -n "${key_num}p")
            echo -e "${INFO} Selected key ${key_num}."
        else
            echo -e "${INFO} Using all keys."
        fi
    fi
}

get_url_key() {
    if [ "${KEY_URL}" == '' ]; then
        read -e -p "Please enter the URL: " KEY_URL
        [ "${KEY_URL}" == '' ] && echo -e "${ERROR} Invalid input." && exit 1
    fi
    echo -e "${INFO} Getting key from URL: ${KEY_URL}..."
    
    local response
    response=$(curl -fsSL -w "%{http_code}" -o /tmp/url_key.txt ${KEY_URL})
    
    if [ "$response" != "200" ]; then
        echo -e "${ERROR} Failed to download key from URL (HTTP ${response})."
        exit 1
    fi
    
    PUB_KEY=$(cat /tmp/url_key.txt)
    rm -f /tmp/url_key.txt
    
    if [ -z "$PUB_KEY" ]; then
        echo -e "${ERROR} No key found at the provided URL."
        exit 1
    fi
    
    # Verify it's a valid SSH key
    if ! echo "$PUB_KEY" | grep -q "ssh-rsa\|ssh-ed25519\|ssh-dss\|ecdsa-sha2"; then
        echo -e "${WARN} The content doesn't appear to be a valid SSH key."
        read -e -p "Continue anyway? (y/N): " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && exit 1
    fi
}

get_local_key() {
    if [ "${KEY_PATH}" == '' ]; then
        read -e -p "Please enter the path: " KEY_PATH
        [ "${KEY_PATH}" == '' ] && echo -e "${ERROR} Invalid input." && exit 1
    fi
    
    if [ ! -f "${KEY_PATH}" ]; then
        echo -e "${ERROR} File not found: ${KEY_PATH}"
        exit 1
    fi
    
    echo -e "${INFO} Getting key from ${KEY_PATH}..."
    PUB_KEY=$(cat ${KEY_PATH})
    
    if [ -z "$PUB_KEY" ]; then
        echo -e "${ERROR} The file is empty."
        exit 1
    fi
    
    # Verify it's a valid SSH key
    if ! echo "$PUB_KEY" | grep -q "ssh-rsa\|ssh-ed25519\|ssh-dss\|ecdsa-sha2"; then
        echo -e "${WARN} The content doesn't appear to be a valid SSH key."
        read -e -p "Continue anyway? (y/N): " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && exit 1
    fi
}

install_key() {
    [ -z "${PUB_KEY}" ] && echo -e "${ERROR} SSH key does not exist." && exit 1
    
    # Create .ssh directory if it doesn't exist
    if [ ! -d "${HOME}/.ssh" ]; then
        echo -e "${INFO} Creating ${HOME}/.ssh/ directory..."
        mkdir -p ${HOME}/.ssh/
    fi
    
    # Create authorized_keys file if it doesn't exist
    if [ ! -f "${HOME}/.ssh/authorized_keys" ]; then
        echo -e "${INFO} Creating ${HOME}/.ssh/authorized_keys file..."
        touch ${HOME}/.ssh/authorized_keys
        if [ ! -f "${HOME}/.ssh/authorized_keys" ]; then
            echo -e "${ERROR} Failed to create SSH key file."
            exit 1
        fi
    fi
    
    # Backup existing keys if not already done
    if [ "$BACKUP_DONE" != "1" ]; then
        backup_config
        BACKUP_DONE=1
    fi
    
    # Add or overwrite key
    if [ "${OVERWRITE}" == 1 ]; then
        echo -e "${INFO} Overwriting SSH key..."
        echo "${PUB_KEY}" > ${HOME}/.ssh/authorized_keys
    else
        echo -e "${INFO} Adding SSH key..."
        # Check if key already exists
        if grep -q -F "$PUB_KEY" "${HOME}/.ssh/authorized_keys"; then
            echo -e "${WARN} Key already exists in authorized_keys."
            read -e -p "Add anyway? (y/N): " confirm
            [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return
        fi
        echo "${PUB_KEY}" >> ${HOME}/.ssh/authorized_keys
    fi
    
    # Set correct permissions
    chmod 700 ${HOME}/.ssh/
    chmod 600 ${HOME}/.ssh/authorized_keys
    
    # Verify key was installed
    if grep -q -F "$PUB_KEY" "${HOME}/.ssh/authorized_keys"; then
        echo -e "${INFO} SSH Key installed successfully!"
    else
        echo -e "${ERROR} SSH key installation failed!"
        exit 1
    fi
}

change_port() {
    validate_port
    
    echo -e "${INFO} Changing SSH port to ${SSH_PORT}..."
    
    if [ "$OS" = "termux" ]; then
        if [ -z "$(grep "^Port " "$PREFIX/etc/ssh/sshd_config")" ]; then
            echo -e "Port ${SSH_PORT}" >> $PREFIX/etc/ssh/sshd_config
        else
            sed -i "s/^Port .*/Port ${SSH_PORT}/" $PREFIX/etc/ssh/sshd_config
        fi
        
        if grep -q "^Port ${SSH_PORT}" "$PREFIX/etc/ssh/sshd_config"; then
            echo -e "${INFO} SSH port changed successfully!"
            RESTART_SSHD=2
        else
            echo -e "${ERROR} SSH port change failed!"
            exit 1
        fi
    else
        if ! grep -q "^Port " /etc/ssh/sshd_config; then
            $SUDO bash -c "echo 'Port ${SSH_PORT}' >> /etc/ssh/sshd_config"
        else
            $SUDO sed -i "s/^Port .*/Port ${SSH_PORT}/" /etc/ssh/sshd_config
        fi
        
        if grep -q "^Port ${SSH_PORT}" /etc/ssh/sshd_config; then
            echo -e "${INFO} SSH port changed successfully!"
            RESTART_SSHD=1
        else
            echo -e "${ERROR} SSH port change failed!"
            exit 1
        fi
    fi
    
    # Update firewall if needed
    if command -v ufw &>/dev/null; then
        echo -e "${INFO} Updating UFW firewall rules..."
        $SUDO ufw allow ${SSH_PORT}/tcp
        $SUDO ufw reload
    elif command -v firewall-cmd &>/dev/null; then
        echo -e "${INFO} Updating firewalld rules..."
        $SUDO firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
        $SUDO firewall-cmd --reload
    elif command -v iptables &>/dev/null; then
        echo -e "${INFO} Updating iptables rules..."
        $SUDO iptables -A INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT
        if command -v iptables-save &>/dev/null; then
            $SUDO iptables-save > /etc/iptables/rules.v4 || echo -e "${WARN} Could not save iptables rules"
        fi
    fi
}

disable_password() {
    echo -e "${INFO} Disabling password login..."
    
    if [ "$OS" = "termux" ]; then
        sed -i "s/^#*PasswordAuthentication .*/PasswordAuthentication no/" $PREFIX/etc/ssh/sshd_config
        sed -i "s/^#*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" $PREFIX/etc/ssh/sshd_config
        
        if grep -q "^PasswordAuthentication no" "$PREFIX/etc/ssh/sshd_config"; then
            RESTART_SSHD=2
            echo -e "${INFO} Disabled password login in SSH."
        else
            echo -e "${ERROR} Disable password login failed!"
            exit 1
        fi
    else
        $SUDO sed -i "s/^#*PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
        $SUDO sed -i "s/^#*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/" /etc/ssh/sshd_config
        
        # Also update UsePAM settings
        read -e -p "Disable PAM authentication too? This is recommended for security (y/N): " disable_pam
        if [[ "$disable_pam" == "y" || "$disable_pam" == "Y" ]]; then
            $SUDO sed -i "s/^#*UsePAM .*/UsePAM no/" /etc/ssh/sshd_config
        fi
        
        if grep -q "^PasswordAuthentication no" "/etc/ssh/sshd_config"; then
            RESTART_SSHD=1
            echo -e "${INFO} Disabled password login in SSH."
        else
            echo -e "${ERROR} Disable password login failed!"
            exit 1
        fi
    fi
}

enhance_security() {
    echo -e "${INFO} Enhancing SSH security settings..."
    
    local config_file="/etc/ssh/sshd_config"
    [ "$OS" = "termux" ] && config_file="$PREFIX/etc/ssh/sshd_config"
    
    # Security settings to add
    local settings=(
        "PermitRootLogin prohibit-password"
        "X11Forwarding no"
        "MaxAuthTries 3"
        "LoginGraceTime 30"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
    )
    
    local editor="$SUDO sed -i"
    [ "$OS" = "termux" ] && editor="sed -i"
    
    for setting in "${settings[@]}"; do
        local key=$(echo "$setting" | cut -d ' ' -f1)
        $editor "s/^#*${key} .*/${setting}/" "$config_file"
        
        # If the setting doesn't exist, add it
        if ! grep -q "^${key} " "$config_file"; then
            if [ "$OS" = "termux" ]; then
                echo "$setting" >> "$config_file"
            else
                $SUDO bash -c "echo '$setting' >> $config_file"
            fi
        fi
    done
    
    echo -e "${INFO} SSH security settings enhanced."
    RESTART_SSHD=1
    [ "$OS" = "termux" ] && RESTART_SSHD=2
}

RESTART_SSHD=0
BACKUP_DONE=0

# Main execution
if [ $# -eq 0 ]; then
    USAGE
    exit 1
fi

check_os
check_dependencies

while getopts "og:u:f:p:dbhs" OPT; do
    case $OPT in
    o)
        OVERWRITE=1
        ;;
    g)
        KEY_ID=$OPTARG
        get_github_key
        install_key
        ;;
    u)
        KEY_URL=$OPTARG
        get_url_key
        install_key
        ;;
    f)
        KEY_PATH=$OPTARG
        get_local_key
        install_key
        ;;
    p)
        SSH_PORT=$OPTARG
        change_port
        ;;
    d)
        disable_password
        ;;
    b)
        backup_config
        BACKUP_DONE=1
        ;;
    s)
        enhance_security
        ;;
    h)
        USAGE
        exit 0
        ;;
    \?)
        USAGE
        exit 1
        ;;
    :)
        echo -e "${ERROR} Option -$OPTARG requires an argument."
        USAGE
        exit 1
        ;;
    *)
        USAGE
        exit 1
        ;;
    esac
done

if [ "$RESTART_SSHD" = 1 ]; then
    echo -e "${INFO} Restarting sshd..."
    if command -v systemctl &>/dev/null; then
        $SUDO systemctl restart sshd && echo -e "${INFO} Done."
    elif command -v service &>/dev/null; then
        $SUDO service sshd restart && echo -e "${INFO} Done."
    else
        echo -e "${WARN} Please restart SSH service manually."
    fi
elif [ "$RESTART_SSHD" = 2 ]; then
    echo -e "${INFO} Restart sshd or Termux App to take effect."
fi

# Final security recommendations
echo -e "\n${INFO} Security recommendations:"
echo -e "1. Make sure to test your SSH connection with keys before closing this session"
echo -e "2. Consider changing default SSH port (use option -p)"
echo -e "3. Disable password authentication (use option -d)"
echo -e "4. Set up a firewall to restrict access to SSH port"
echo -e "5. Consider implementing fail2ban for brute force protection"