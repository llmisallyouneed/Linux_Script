#!/bin/bash
#=============================================================
# 哪吒监控 Agent 安全配置脚本
# 描述：创建nezha用户和组，更新服务配置使用该用户运行
# 处理多配置文件情况，并增强安全性
#=============================================================

# 颜色定义
RED_FONT_PREFIX="\033[31m"
GREEN_FONT_PREFIX="\033[32m"
YELLOW_FONT_PREFIX="\033[33m"
FONT_COLOR_SUFFIX="\033[0m"
INFO="[${GREEN_FONT_PREFIX}信息${FONT_COLOR_SUFFIX}]"
ERROR="[${RED_FONT_PREFIX}错误${FONT_COLOR_SUFFIX}]"
WARN="[${YELLOW_FONT_PREFIX}警告${FONT_COLOR_SUFFIX}]"

# 定义路径
NZ_BASE_PATH="/opt/nezha"
NZ_AGENT_PATH="${NZ_BASE_PATH}/agent"
NZ_LOG_PATH="/var/log/nezha"

# 检查是否有root权限
if [ $EUID -ne 0 ]; then
    echo -e "${ERROR} 此脚本需要root权限运行，请使用sudo或root用户执行" 
    exit 1
fi

echo -e "${INFO} 开始执行哪吒监控Agent安全配置"

# 创建nezha用户和组(如果不存在)
echo -e "${INFO} 检查并创建nezha用户和组..."
getent group nezha &>/dev/null || groupadd nezha
id -u nezha &>/dev/null || useradd -g nezha -m -d /var/lib/nezha -s /sbin/nologin nezha

# 检查nezha-agent是否已安装
if [ ! -f "${NZ_AGENT_PATH}/nezha-agent" ]; then
    echo -e "${ERROR} 未找到哪吒监控Agent程序，请先安装哪吒监控"
    exit 1
fi

# 查找所有配置文件
echo -e "${INFO} 检查哪吒监控Agent配置文件..."
config_files=$(find "${NZ_AGENT_PATH}" -name "config*.yml")

if [ -z "$config_files" ]; then
    echo -e "${WARN} 未找到配置文件，请确保已正确配置哪吒监控Agent"
    exit 1
fi

# 创建日志目录
if [ ! -d "$NZ_LOG_PATH" ]; then
    echo -e "${INFO} 创建日志目录..."
    mkdir -p "$NZ_LOG_PATH"
    chown nezha:nezha "$NZ_LOG_PATH"
    chmod 750 "$NZ_LOG_PATH"
fi

# 更新文件权限
echo -e "${INFO} 更新Agent目录权限..."
chown -R nezha:nezha "${NZ_AGENT_PATH}"
chmod -R 750 "${NZ_AGENT_PATH}"

# 特殊处理配置文件权限
for config_file in $config_files; do
    echo -e "${INFO} 设置配置文件权限: $config_file"
    chown nezha:nezha "$config_file"
    chmod 640 "$config_file"
done

# 处理服务文件
service_files=$(find /etc/systemd/system -name "nezha-agent*.service")

if [ -z "$service_files" ]; then
    echo -e "${WARN} 未找到服务文件，尝试查找可能的默认服务文件位置..."
    
    # 尝试查找其他可能的位置
    service_files=$(find /usr/lib/systemd/system -name "nezha-agent*.service" 2>/dev/null)
    
    if [ -z "$service_files" ]; then
        echo -e "${ERROR} 未找到任何哪吒监控Agent服务文件"
        
        # 询问是否创建默认服务文件
        read -p "是否创建默认服务文件? (y/n) " create_service
        if [ "$create_service" != "y" ] && [ "$create_service" != "Y" ]; then
            echo -e "${INFO} 已取消创建服务文件"
            exit 0
        fi
        
        # 选择配置文件
        if [ $(echo "$config_files" | wc -l) -gt 1 ]; then
            echo -e "${INFO} 检测到多个配置文件，请选择要使用的配置文件:"
            
            i=1
            for file in $config_files; do
                echo "$i) $file"
                i=$((i+1))
            done
            
            read -p "请输入序号选择配置文件: " config_num
            
            # 验证输入
            if ! [[ "$config_num" =~ ^[0-9]+$ ]]; then
                echo -e "${ERROR} 无效的输入"
                exit 1
            fi
            
            # 获取选定的配置文件
            config_file=$(echo "$config_files" | sed -n "${config_num}p")
            
            if [ -z "$config_file" ]; then
                echo -e "${ERROR} 无效的选择"
                exit 1
            fi
        else
            config_file=$config_files
        fi
        
        # 创建默认服务文件
        default_service="/etc/systemd/system/nezha-agent.service"
        echo -e "${INFO} 创建服务文件: $default_service"
        
        cat > "$default_service" << EOF
[Unit]
Description=哪吒监控 Agent
After=network.target
ConditionFileIsExecutable=${NZ_AGENT_PATH}/nezha-agent

[Service]
Type=simple
User=nezha
Group=nezha
StartLimitInterval=5
StartLimitBurst=10
ExecStart=${NZ_AGENT_PATH}/nezha-agent "-c" "${config_file}"
WorkingDirectory=${NZ_AGENT_PATH}
Restart=always
RestartSec=30
StandardOutput=append:${NZ_LOG_PATH}/nezha-agent.log
StandardError=append:${NZ_LOG_PATH}/nezha-agent.error.log

# 安全相关设置
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF
        
        service_files="$default_service"
    fi
fi

# 更新服务文件
for service_file in $service_files; do
    echo -e "${INFO} 更新服务文件: $service_file"
    
    # 备份原服务文件
    backup_file="${service_file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$service_file" "$backup_file"
    
    # 获取当前服务使用的配置文件
    current_config=$(grep -oP 'ExecStart=.*\-c[" ]*\K[^"]*' "$service_file" || echo "")
    
    if [ -z "$current_config" ]; then
        echo -e "${WARN} 无法在服务文件中找到配置文件路径，将使用默认路径: ${NZ_AGENT_PATH}/config.yml"
        current_config="${NZ_AGENT_PATH}/config.yml"
    fi
    
    # 检查配置文件是否存在
    if [ ! -f "$current_config" ]; then
        echo -e "${WARN} 配置文件不存在: $current_config"
        
        # 如果有多个配置文件，让用户选择
        if [ $(echo "$config_files" | wc -l) -gt 1 ]; then
            echo -e "${INFO} 检测到多个配置文件，请选择要使用的配置文件:"
            
            i=1
            for file in $config_files; do
                echo "$i) $file"
                i=$((i+1))
            done
            
            read -p "请输入序号选择配置文件: " config_num
            
            # 验证输入
            if ! [[ "$config_num" =~ ^[0-9]+$ ]]; then
                echo -e "${ERROR} 无效的输入"
                exit 1
            fi
            
            # 获取选定的配置文件
            selected_config=$(echo "$config_files" | sed -n "${config_num}p")
            
            if [ -z "$selected_config" ]; then
                echo -e "${ERROR} 无效的选择"
                exit 1
            fi
            
            current_config=$selected_config
        else
            current_config=$config_files
        fi
    fi
    
    # 更新服务文件，保留原配置文件路径
    cat > "$service_file" << EOF
[Unit]
Description=哪吒监控 Agent
After=network.target
ConditionFileIsExecutable=${NZ_AGENT_PATH}/nezha-agent

[Service]
Type=simple
User=nezha
Group=nezha
StartLimitInterval=5
StartLimitBurst=10
ExecStart=${NZ_AGENT_PATH}/nezha-agent "-c" "${current_config}"
WorkingDirectory=${NZ_AGENT_PATH}
Restart=always
RestartSec=30
StandardOutput=append:${NZ_LOG_PATH}/nezha-agent.log
StandardError=append:${NZ_LOG_PATH}/nezha-agent.error.log

# 安全相关设置
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF
done

# 重新加载systemd配置
echo -e "${INFO} 重新加载systemd配置..."
systemctl daemon-reload

# 重启所有哪吒监控Agent服务
for service_file in $service_files; do
    service_name=$(basename "$service_file")
    echo -e "${INFO} 重启服务: $service_name"
    systemctl restart "$service_name"
    
    # 检查服务状态
    if systemctl is-active --quiet "$service_name"; then
        echo -e "${INFO} 服务 $service_name 已成功启动"
    else
        echo -e "${ERROR} 服务 $service_name 启动失败"
        echo -e "${INFO} 查看详细日志请运行: journalctl -u $service_name -n 50 --no-pager"
        
        # 提供回滚选项
        read -p "是否要恢复到原始配置? (y/n) " choice
        if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
            echo -e "${INFO} 恢复到原始配置..."
            cp "${service_file}.bak."* "$service_file"
            systemctl daemon-reload
            systemctl restart "$service_name"
            echo -e "${INFO} 已恢复原始配置"
        fi
    fi
done

echo -e "${INFO} 安全配置完成"
echo -e "${INFO} 哪吒监控Agent现在使用nezha用户运行，并启用了额外的安全设置"
echo -e "${INFO} 日志文件位置: ${NZ_LOG_PATH}/nezha-agent.log"