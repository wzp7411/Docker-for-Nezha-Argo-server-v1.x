#!/usr/bin/env bash

# 配置变量和常量

## 网络与代理配置
GH_PROXY='https://ghproxy.lvedong.eu.org/'
GRPC_PROXY_PORT=${GRPC_PROXY_PORT:-'443'}
CADDY_HTTP_PORT=2052
PRO_PORT=${PORT:-'80'}

## 版本号配置
DASH_VER=${DASH_VER:-'v1.12.4'}
if [[ "$DASH_VER" =~ ^(v)?0\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
    GRPC_PORT=${GRPC_PORT:-'5555'}
    WEB_PORT=${WEB_PORT:-'8080'}
    AGENT_VER=${AGENT_VER:-'v0.17.5'}
else
    GRPC_PORT=${GRPC_PORT:-'8008'}
    WEB_PORT=${WEB_PORT:-'8008'}
    AGENT_VER=${AGENT_VER:-'v1.12.2'}
fi
CADDY_VER=${CADDY_VER:-'2.9.1'}
CADDY_VER=$(remove_v_prefix "$CADDY_VER")

## 目录路径配置
WORK_DIR=/dashboard

REPO_BASE="https://raw.githubusercontent.com/dsadsadsss/Docker-for-Nezha-Argo-server-v1.x/main"

## GitHub 仓库地址
# Dashboard 仓库: nezhahq/dashboard
# Agent 仓库: nezhahq/agent
# 其他自定义仓库保持原样

## 其他配置
IS_UPDATE=${IS_UPDATE:-'yes'}
GH_BACKUP_USER=${GH_BACKUP_USER:-$GH_USER}
LOCAL_TOKEN=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)  # 默认生成，如果有 NO_SUIJI 则使用它
[ -n "$NO_SUIJI" ] && LOCAL_TOKEN="$NO_SUIJI"
DAYS=5
IS_DOCKER=1
TEMP_DIR=/tmp/restore_temp
NO_ACTION_FLAG=/tmp/flag
XIEYI='vl'
XIEYI2='vm'
CF_IP=${CF_IP:-'ip.sb'}
SUB_NAME=${SUB_NAME:-'nezha'}

# 辅助函数
#error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; } # 红色
#info() { echo -e "\033[32m\033[01m$*\033[0m"; }   # 绿色
#hint() { echo -e "\033[33m\033[01m$*\033[0m"; }   # 黄色
error() { echo "[ERROR] $*" && exit 1; }
info()  { echo "[INFO ] $*"; }
hint()  { echo "[HINT ] $*"; }

download_file() {
    local url="$1"
    local output="$2"
    local quiet="${3:-false}"
    local original_url="$url"
    local print_msg=true

    if [[ "$quiet" == "true" ]]; then
        print_msg=false
    fi

    # 如果 URL 是 GitHub 的且未包含代理前缀，则自动添加 GH_PROXY
    if [[ "$url" =~ https?://github\.com ]] && [[ "$url" != ${GH_PROXY}* ]]; then
        url="${GH_PROXY}${url#https?://}"
    fi

    if [[ $print_msg == true ]]; then
        info "开始下载: $original_url 到 $output"
    fi

    local max_retries=3
    local success=false
    local tool quiet_flag cmd

    if command -v curl >/dev/null 2>&1; then
        tool="curl"
        quiet_flag="-s"
        local curl_opts="--connect-timeout 15 --max-time 15"
        if [[ $print_msg == true ]]; then
            curl_opts="$curl_opts --progress-bar"
        fi
        local cmd_base="curl -L $quiet_flag $curl_opts"
        if [[ "$output" == "-" ]]; then
            cmd="${cmd_base} \"$url\""
        else
            cmd="${cmd_base} -o \"$output\" \"$url\""
        fi
    elif command -v wget >/dev/null 2>&1; then
        tool="wget"
        quiet_flag="-q"
        local wget_opts="--timeout=15 --tries=1"
        if [[ $print_msg == true ]]; then
            wget_opts="$wget_opts --show-progress"
        fi
        local cmd_base="wget $quiet_flag $wget_opts"
        if [[ "$output" == "-" ]]; then
            cmd="${cmd_base} -O- \"$url\""
        else
            cmd="${cmd_base} -O \"$output\" \"$url\""
        fi
    else
        if [[ $quiet == "true" ]]; then
            return 1
        else
            error "未找到 curl 或 wget，无法下载文件。"
        fi
    fi

    for attempt in {1..3}; do
        if eval "$cmd"; then
            if [[ "$output" != "-" ]] && [[ ! -s "$output" ]]; then
                if [[ $attempt -lt 3 ]]; then
                    if [[ $print_msg == true ]]; then
                        info "下载失败 (尝试 $attempt/3)，5 秒后重试..."
                    fi
                    sleep 5
                    continue
                fi
            else
                success=true
                break
            fi
        else
            if [[ $attempt -lt 3 ]]; then
                if [[ $print_msg == true ]]; then
                    info "下载失败 (尝试 $attempt/3)，5 秒后重试..."
                fi
                sleep 5
                continue
            fi
        fi
    done

    if [[ $success == true ]]; then
        if [[ $print_msg == true ]]; then
            info "下载成功: $original_url 到 $output"
        fi
        return 0
    else
        if [[ $quiet == "true" ]]; then
            return 1
        else
            error "下载失败: $original_url 到 $output，重试 3 次后仍失败。"
        fi
    fi
}

add_v_prefix() {
    local version=$1
    if [[ ! $version =~ ^v ]]; then
        version="v$version"
    fi
    echo "$version"
}

remove_v_prefix() {
    local version=$1
    if [[ $version =~ ^v ]]; then
        version="${version#v}"
    fi
    echo "$version"
}

get_country_code() {
    country_code="UN"
    urls=("http://ipinfo.io/country" "https://ifconfig.co/country" "https://ipapi.co/country")

    for url in "${urls[@]}"; do
        country_code=$(download_file "$url" "-" "true" 2>/dev/null || true)
        if [ -n "$country_code" ] && [ ${#country_code} -eq 2 ]; then
            break
        fi
    done

    echo "$country_code"
}

detect_port_conflicts() {
    info "正在进行端口冲突检查..."

    local conflict_found=false

    # 检查 Caddy 内部的端口冲突
    # Caddy 不能用同一个端口同时作为 HTTP 入口和 gRPC 代理入口
    if [[ "$PRO_PORT" -eq "$GRPC_PROXY_PORT" ]]; then
        error "检测到严重配置冲突：Caddy 的公共端口 (PRO_PORT: $PRO_PORT) 和 gRPC 代理端口 (GRPC_PROXY_PORT: $GRPC_PROXY_PORT) 不能相同。"
        conflict_found=true
    fi

    # 检查 Caddy 和 Dashboard 之间的端口冲突
    # Caddy 的 Web 代理入口不能和 Dashboard 的 Web 监听口冲突
    if [[ "$PRO_PORT" -eq "$WEB_PORT" ]]; then
        error "检测到严重配置冲突：Caddy 的公共端口 (PRO_PORT: $PRO_PORT) 将由 Caddy 监听，但 Dashboard 的 Web 服务也计划监听相同端口 (WEB_PORT: $WEB_PORT)。这会导致其中一个服务启动失败。请确保它们使用不同的端口。"
        conflict_found=true
    fi

    # Caddy 的 gRPC 代理入口不能和 Dashboard 的 gRPC 监听口冲突
    if [[ "$GRPC_PROXY_PORT" -eq "$GRPC_PORT" ]]; then
        error "检测到严重配置冲突：Caddy 的 gRPC 代理端口 (GRPC_PROXY_PORT: $GRPC_PROXY_PORT) 将由 Caddy 监听，但 Dashboard 的 gRPC 服务也计划监听相同端口 (GRPC_PORT: $GRPC_PORT)。这会导致其中一个服务启动失败。请确保它们使用不同的端口。"
        conflict_found=true
    fi

    if [ "$conflict_found" = true ]; then
        error "端口检查失败，发现一个或多个致命的端口冲突。请根据上述错误信息检查并修改您的配置（环境变量或脚本）。"
    else
        info "所有配置的端口均无冲突。"
    fi
}

validate_environment() {
    info "正在检查环境变量..."
    hint "检查关键环境变量是否存在：GH_USER, GH_CLIENTID, GH_CLIENTSECRET, ARGO_AUTH, ARGO_DOMAIN"
    if [[ -z "$GH_USER" || -z "$GH_CLIENTID" || -z "$GH_CLIENTSECRET" || -z "$ARGO_AUTH" || -z "$ARGO_DOMAIN" ]]; then
        error "关键环境变量未设置，请检查 GH_USER, GH_CLIENTID, GH_CLIENTSECRET, ARGO_AUTH, ARGO_DOMAIN。"
    fi
    info "关键环境变量检查通过。"

    hint "检查 ARGO_DOMAIN 格式是否为合法域名..."
    if ! [[ "$ARGO_DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(\.[a-zA-Z]{2,})$ ]]; then
        error "ARGO_DOMAIN 格式无效，必须是一个合法的域名格式。"
    fi
    info "ARGO_DOMAIN 格式校验通过。"

    hint "检查 ARGO_AUTH 格式是否为有效 JSON ({...TunnelSecret...}) 或 Token (ey...)"

    # 首先检查是否是 Token 格式（最准确）
    if [[ "$ARGO_AUTH" =~ ^ey[A-Z0-9a-z=]{120,250}$ ]]; then
        info "ARGO_AUTH 是 Token 格式，已处理。"
    # 然后检查是否是 JSON 格式
    elif [[ "$ARGO_AUTH" =~ TunnelSecret ]] && command -v jq >/dev/null 2>&1; then
        # 使用 jq 检查有效性，这是最安全的方法
        if echo "$ARGO_AUTH" | jq . >/dev/null 2>&1; then
            info "ARGO_AUTH 是有效的 JSON 格式，已处理。"
        else
            error "ARGO_AUTH 包含 'TunnelSecret' 但不是一个有效的 JSON 字符串。请检查其格式。"
        fi
    elif [[ "$ARGO_AUTH" =~ TunnelSecret ]]; then
        # 如果没有 jq，做一个非常基础的检查：必须以 { 开头，以 } 结尾
        if [[ "$ARGO_AUTH" == *{* && "$ARGO_AUTH" == *}* ]]; then
            info "ARGO_AUTH 可能是 JSON 格式（无法使用 jq 验证），已处理。"
        else
            error "ARGO_AUTH 包含 'TunnelSecret' 但看起来不像一个有效的 JSON 字符串。"
        fi
    else
        error "ARGO_AUTH 格式无效，必须是有效的 JSON ({...TunnelSecret...}) 或 Token (ey...) 格式。"
    fi
    info "ARGO_AUTH 格式校验通过。"

    [ -n "$GH_REPO" ] && grep -q '/' <<< "$GH_REPO" && GH_REPO=$(awk -F '/' '{print $NF}' <<< "$GH_REPO")  # 填了项目全路径的处理

    hint "检测 GitHub CDN 连通性..."
    [ -n "$GH_PROXY" ] && download_file "$REPO_BASE/README.md" "-" "true" >/dev/null 2>&1 && unset GH_PROXY
    info "GitHub CDN 连通性检查完成。"

    #检测端口冲突
    detect_port_conflicts

    info "环境校验完成。"
}

setup_os_config() {
    # 设置 DNS
    echo -e "nameserver 127.0.0.11\nnameserver 8.8.4.4\nnameserver 223.5.5.5\nnameserver 2001:4860:4860::8844\nnameserver 2400:3200::1\n" > /etc/resolv.conf

    # 设置 +8 时区 (北京时间)
    ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    dpkg-reconfigure -f noninteractive tzdata
}

detect_architecture() {
    local arch
    case "$(uname -m)" in
        aarch64|arm64 )
          arch="arm64"
          ;;
        x86_64|amd64 )
          arch="amd64"
          ;;
        armv7* )
          arch="arm"
          ;;
        * )
          error "不支持的架构: $(uname -m)"
          ;;
    esac
    echo "$arch"
}

download_dependencies() {
    DASH_VER=$(add_v_prefix "$DASH_VER")
    info "最终确定的面板版本: DASH_VER = $DASH_VER"

    # 下载 Caddy
    download_file "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VER}/caddy_${CADDY_VER}_linux_${ARCH}.tar.gz" "-" "true" | tar xz -C $WORK_DIR caddy

    # 下载 Dashboard
    if [ "$IS_UPDATE" = 'no' ]; then
        download_file "https://github.com/nezhahq/dashboard/releases/download/${DASH_VER}/dashboard-linux-$ARCH.zip" "/tmp/dashboard.zip"
    else
        DASHBOARD_LATEST=$(download_file "https://api.github.com/repos/nezhahq/dashboard/releases/latest" "-" "true" | awk -F '"' '/"tag_name"/{print $4}')
        download_file "https://github.com/nezhahq/dashboard/releases/download/$DASHBOARD_LATEST/dashboard-linux-$ARCH.zip" "/tmp/dashboard.zip"
    fi
    unzip /tmp/dashboard.zip -d /tmp
    if [ -s "/tmp/dist/dashboard-linux-${ARCH}" ]; then
        mv -f /tmp/dist/dashboard-linux-$ARCH $WORK_DIR/app
    else
       mv -f /tmp/dashboard-linux-$ARCH $WORK_DIR/app
    fi

    # 下载 Cloudflared
    download_file "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$ARCH" "$WORK_DIR/cloudflared"

    # 下载 Agent
    if [ "$IS_UPDATE" = 'no' ]; then
        AGENT_VER=$(add_v_prefix "$AGENT_VER")
        info "最终确定的 Agent 版本: AGENT_VER = $AGENT_VER"
        download_file "https://github.com/nezhahq/agent/releases/download/${AGENT_VER}/nezha-agent_linux_$ARCH.zip" "$WORK_DIR/nezha-agent.zip"
    else
        download_file "https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_linux_$ARCH.zip" "$WORK_DIR/nezha-agent.zip"
    fi
    unzip $WORK_DIR/nezha-agent.zip -d $WORK_DIR/
    rm -rf $WORK_DIR/nezha-agent.zip /tmp/dist /tmp/dashboard.zip

    [ -n "$API_TOKEN" ] && [[ "$ARCH" == "amd64" ]] && download_file "https://github.com/dsadsadsss/Docker-for-Nezha-Argo-server-v1.x/releases/download/nezfuz/nezfz-linux-amd64" "$WORK_DIR/nezfz" || [[ "$ARCH" != "amd64" ]] && hint "跳过 nezfz（仅支持 amd64）"

    # 启动xxxry
    # 只有当 UUID 被设置且不为 "0"，并且架构为 amd64 时，才下载 webapp
    if [[ "$ARCH" == "amd64" ]] && [ -n "$UUID" ] && [ "$UUID" != "0" ]; then
        info "检测到有效的 UUID 且为 amd64 架构，正在下载 webapp..."
        download_file "https://github.com/dsadsadsss/d/releases/download/sd/kano-6-amd-w" "$WORK_DIR/webapp"
        if [ $? -eq 0 ]; then
            chmod 755 $WORK_DIR/webapp
            info "Webapp 下载成功并已设置可执行权限。"
        else
            error "Webapp 下载失败，代理服务将无法启动。"
        fi
    else
        # 如果条件不满足，给出明确的提示信息
        if [[ "$ARCH" != "amd64" ]]; then
            hint "跳过 webapp 下载（仅支持 amd64 架构）。"
        else
            hint "跳过 webapp 下载（未设置有效的 UUID）。"
        fi
    fi
}

generate_dashboard_config() {
  if [[ "$DASH_VER" =~ ^(v)?0\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
    cat > ${WORK_DIR}/data/config.yaml << EOF
Debug: false
HTTPPort: $WEB_PORT
Language: zh-CN
GRPCPort: $GRPC_PORT
GRPCHost: $ARGO_DOMAIN
ProxyGRPCPort: $GRPC_PROXY_PORT
TLS: true
Oauth2:
  Type: "github" #Oauth2 登录接入类型，github/gitlab/jihulab/gitee/gitea ## Argo-容器版本只支持 github
  Admin: "$GH_USER" #管理员列表，半角逗号隔开
  ClientID: "$GH_CLIENTID" # 在 ${GH_PROXY}https://github.com/settings/developers 创建，无需审核 Callback 填 http(s)://域名或IP/oauth2/callback
  ClientSecret: "$GH_CLIENTSECRET"
  Endpoint: "" # 如gitea自建需要设置 ## Argo-容器版本只支持 github
site:
  Brand: "Nezha Probe"
  Cookiename: "nezha-dashboard" #浏览器 Cookie 字段名，可不改
  Theme: "default"
EOF
  else
    seed="${ARGO_DOMAIN}${GH_CLIENTSECRET}${GH_CLIENTID}${GH_USER}"
    hash=$(echo -n "$seed" | sha256sum | cut -d' ' -f1)
    AGENT_UUID1="${hash:0:8}-${hash:8:4}-${hash:12:4}-${hash:16:4}-${hash:20:12}"

    token_hash=$(echo -n "TOKEN_${seed}" | sha256sum | cut -d' ' -f1)
    DASH_TOKEN1=$(echo -n "$token_hash" | tr 'abcdef' 'ABCDEF' | head -c 32)
    AGENT_UUID=${AGENT_UUID:-${AGENT_UUID1:-'fraewrwdf-das-2sd2-4324-f232df'}}
    DASH_TOKEN=${DASH_TOKEN:-${DASH_TOKEN1:-'fse-3432-d430-rw3-df32-dfs3-4334gtg'}}
    
    cat > ${WORK_DIR}/data/config.yaml << EOF
agent_secret_key: $DASH_TOKEN
debug: false
listen_port: $GRPC_PORT
language: zh-CN
site_name: "Nezha Probe"
install_host: $ARGO_DOMAIN:$GRPC_PROXY_PORT
location: Asia/Shanghai
tls: true
oauth2:
  GitHub:
    client_id: "$GH_CLIENTID"
    client_secret: "$GH_CLIENTSECRET"
    endpoint:
      auth_url: "https://github.com/login/oauth/authorize"
      token_url: "https://github.com/login/oauth/access_token"
    user_info_url: "https://api.github.com/user"
    user_id_path: "id"
EOF

    cat > ${WORK_DIR}/data/config.yml << EOF
client_secret: $DASH_TOKEN
debug: false
disable_auto_update: false
disable_command_execute: false
disable_force_update: false
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 3
server: 127.0.0.1:$GRPC_PORT
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: false
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: $AGENT_UUID
EOF
  fi

  # 下载包含本地数据的 sqlite.db 文件，生成18位随机字符串用于本地 Token
  if [[ "$DASH_VER" =~ ^(v)?0\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
    if [ ! -f "${WORK_DIR}/data/sqlite.db" ]; then
      download_file "$REPO_BASE/sqlite.db" "${WORK_DIR}/data/sqlite.db"
    fi
    LOCAL_DATE=$(sqlite3 ${WORK_DIR}/data/sqlite.db "SELECT created_at FROM servers WHERE name LIKE '%local%' COLLATE NOCASE LIMIT 1;") 
    [ -z "$LOCAL_DATE" ] && LOCAL_DATE='2023-04-23 13:02:00.770756566+08:00'
    sqlite3 ${WORK_DIR}/data/sqlite.db "update servers set secret='${LOCAL_TOKEN}' where created_at='${LOCAL_DATE}'"
  fi
}

setup_ssh_access() {
  # SSH path 与 GH_CLIENTSECRET 一样
  echo root:"$GH_CLIENTSECRET" | chpasswd root
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g;s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
  service ssh restart
}

generate_argo_config() {
  # 判断 ARGO_AUTH 为 json 还是 token
  # 如为 json 将生成 argo.json 和 argo.yml 文件
  if [[ "$ARGO_AUTH" =~ TunnelSecret ]]; then
    ARGO_RUN="$WORK_DIR/cloudflared tunnel --edge-ip-version auto --config $WORK_DIR/argo.yml run"

    echo "$ARGO_AUTH" > $WORK_DIR/argo.json

    cat > $WORK_DIR/argo.yml << EOF
tunnel: $(cut -d '"' -f12 <<< "$ARGO_AUTH")
credentials-file: $WORK_DIR/argo.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: https://localhost:$GRPC_PROXY_PORT
    path: /proto.NezhaService/*
    originRequest:
      http2Origin: true
      noTLSVerify: true
  - hostname: $ARGO_DOMAIN
    service: ssh://localhost:22
    path: /$GH_CLIENTID/*
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$PRO_PORT
  - service: http_status:404
EOF

  # 如为 token 时
  elif [[ "$ARGO_AUTH" =~ ^ey[A-Z0-9a-z=]{120,250}$ ]]; then
    ARGO_RUN="$WORK_DIR/cloudflared tunnel --edge-ip-version auto --protocol http2 run --token ${ARGO_AUTH}"
  fi
}

generate_ssl_cert() {
  # 生成自签署SSL证书
  openssl genrsa -out $WORK_DIR/nezha.key 2048
  openssl req -new -subj "/CN=$ARGO_DOMAIN" -key $WORK_DIR/nezha.key -out $WORK_DIR/nezha.csr
  openssl x509 -req -days 36500 -in $WORK_DIR/nezha.csr -signkey $WORK_DIR/nezha.key -out $WORK_DIR/nezha.pem
}

generate_utility_scripts() {
  # 内部辅助函数：生成通用实用脚本头部和模板追加
  _generate_utility_script() {
    local filename="$1"
    local template_path="$2"
    local comment="$3"
    cat > $WORK_DIR/$filename << EOF
#!/usr/bin/env bash

$comment
IS_UPDATE=$IS_UPDATE
LOCAL_TOKEN=$LOCAL_TOKEN
GH_PROXY=$GH_PROXY
GH_PAT=$GH_PAT
GH_BACKUP_USER=$GH_BACKUP_USER
GH_EMAIL=$GH_EMAIL
GH_REPO=$GH_REPO
ARCH=$ARCH
WORK_DIR=$WORK_DIR
DAYS=5
IS_DOCKER=1
DASH_VER=$DASH_VER
########
EOF

    download_file "$REPO_BASE/$template_path" "-" "true" | sed '1,/^########/d' >> $WORK_DIR/$filename
  }

  # 生成 backup.sh、backup2.sh 和 update.sh
  _generate_utility_script "backup.sh" "template/backup.sh" "# backup.sh 传参 a 自动还原； 传参 m 手动还原； 传参 f 强制更新面板 app 文件及 cloudflared 文件，并备份数据至成备份库"

  _generate_utility_script "backup2.sh" "template/backup2.sh" "# backup2.sh 传参 a 自动还原； 传参 m 手动还原； 传参 f 强制更新面板 app 文件及 cloudflared 文件，并备份数据至成备份库"

  _generate_utility_script "update.sh" "template/update.sh" "# update.sh 传参 a 自动更新面板 app 文件及 cloudflared 文件，并备份数据至备份库"

  # 生成 restore.sh  
  if [[ -n "$GH_BACKUP_USER" && -n "$GH_EMAIL" && -n "$GH_REPO" && -n "$GH_PAT" ]]; then
    cat > $WORK_DIR/restore.sh << EOF
#!/usr/bin/env bash

# restore.sh 传参 a 自动还原 README.md 记录的文件，当本地与远程记录文件一样时不还原； 传参 f 不管本地记录文件，强制还原成备份库里 README.md 记录的文件； 传参 dashboard-***.tar.gz 还原成备份库里的该文件；不带参数则要求选择备份库里的文件名
GH_PROXY=$GH_PROXY
IS_UPDATE=$IS_UPDATE
LOCAL_TOKEN=$LOCAL_TOKEN
GH_PAT=$GH_PAT
GH_BACKUP_USER=$GH_BACKUP_USER
GH_REPO=$GH_REPO
WORK_DIR=$WORK_DIR
TEMP_DIR=/tmp/restore_temp
NO_ACTION_FLAG=/tmp/flag
IS_DOCKER=1
DASH_VER=$DASH_VER
########
EOF

    download_file "$REPO_BASE/template/restore.sh" "-" "true" | sed '1,/^########/d' >> $WORK_DIR/restore.sh
  fi

  # 生成 restore2.sh
  if [[ -n "$GH_BACKUP_USER" && -n "$GH_EMAIL" && -n "$GH_REPO" && -n "$GH_PAT" ]]; then
    cat > $WORK_DIR/restore2.sh << EOF
#!/usr/bin/env bash

# restore2.sh 传参 a 自动还原 README.md 记录的文件，当本地与远程记录文件一样时不还原； 传参 f 不管本地记录文件，强制还原成备份库里 README.md 记录的文件； 传参 dashboard-***.tar.gz 还原成备份库里的该文件；不带参数则要求选择备份库里的文件名
GH_PROXY=$GH_PROXY
IS_UPDATE=$IS_UPDATE
LOCAL_TOKEN=$LOCAL_TOKEN
GH_PAT=$GH_PAT
GH_BACKUP_USER=$GH_BACKUP_USER
GH_REPO=$GH_REPO
WORK_DIR=$WORK_DIR
TEMP_DIR=/tmp/restore_temp
NO_ACTION_FLAG=/tmp/flag
IS_DOCKER=1
DASH_VER=$DASH_VER
########
EOF

    download_file "$REPO_BASE/template/restore.sh" "-" "true" | sed '1,/^########/d' >> $WORK_DIR/restore2.sh

    # 恢复备份文件
    chmod 777 $WORK_DIR/restore2.sh
    $WORK_DIR/restore2.sh a
  fi

  # 生成 renew.sh
  cat > $WORK_DIR/renew.sh << EOF
#!/usr/bin/env bash
LOCAL_TOKEN=$LOCAL_TOKEN
GH_PROXY=$GH_PROXY
WORK_DIR=/dashboard
TEMP_DIR=/tmp/renew
IS_UPDATE=$IS_UPDATE
DASH_VER=$DASH_VER
########
EOF

  download_file "$REPO_BASE/template/renew.sh" "-" "true" | sed '1,/^########/d' >> $WORK_DIR/renew.sh
}

generate_subscription_info() {
    info "开始生成代理订阅信息..."

    local country_code="UN" # 设置默认国家代码
    if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
        country_code=$(get_country_code)
        [ -z "$country_code" ] && country_code="UN" # 如果函数返回空，则使用默认值
    else
        hint "未找到 curl 或 wget，无法获取国家代码将使用默认值 'UN'。"
    fi
    info "     国家:    $country_code"

    local up_url="${XIEYI}ess://${UUID}@${CF_IP}:443?path=%2F${XIEYI}s%3Fed%3D2048&security=tls&encryption=none&host=${ARGO_DOMAIN}&type=ws&sni=${ARGO_DOMAIN}#${country_code}-${SUB_NAME}"
    local VM_SS="{ \"v\": \"2\", \"ps\": \"${country_code}-${SUB_NAME}\", \"add\": \"${CF_IP}\", \"port\": \"443\", \"id\": \"${UUID}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${ARGO_DOMAIN}\", \"path\": \"/vms?ed=2048\", \"tls\": \"tls\", \"sni\": \"${ARGO_DOMAIN}\", \"alpn\": \"\", \"fp\": \"randomized\", \"allowInsecure\": false}"
    
    local vm_url=""
    if command -v base64 >/dev/null 2>&1; then
        vm_url="${XIEYI2}ess://$(echo -n "$VM_SS" | base64 -w 0)"
    else
        hint "未找到 base64 命令，将跳过 VLESS-VMess 节点生成。"
    fi

    local x_url="${up_url}"
    if [ -n "$vm_url" ]; then
        x_url="${up_url}\n${vm_url}"
    fi

    local encoded_url=""
    if command -v base64 >/dev/null 2>&1; then
        encoded_url=$(echo -e "${x_url}" | base64 -w 0)
    else
        error "致命错误：生成订阅链接需要 base64 命令，但未找到。"
        # 如果 base64 不存在，脚本无法完成核心任务，应该退出
        return 1 # 或者用 exit 1，取决于你是否希望整个脚本在此终止
    fi
    
    echo -e "$encoded_url" > /tmp/list.log
    hint "============  <订阅地址:>  ========  "
    hint "  "
    info "订阅地址1: 项目网址/$UUID"
    hint "  "
    info "订阅地址2: $ARGO_DOMAIN/$UUID"
    hint "  "
    hint "=============================="
    info "订阅信息生成完毕。"
}

generate_config_files() {
    [ ! -d data ] && mkdir data
    info "开始生成所有配置文件和相关脚本..."

    # 按顺序调用各个生成子函数
    generate_dashboard_config    # 1. 核心服务：面板本身配置
    setup_ssh_access             # 2. 核心服务：SSH访问
    generate_argo_config         # 3. 核心服务：隧道配置
    generate_ssl_cert            # 4. 核心服务：内部通信证书

    # 核心服务前置启动命令
    GRPC_PROXY_RUN="$WORK_DIR/caddy run --config $WORK_DIR/Caddyfile --watch"
    
    generate_caddyfile           # 5. 核心服务：反向代理 Caddy (代理上述核心服务)
    generate_utility_scripts     # 6. 对外工具：备份/恢复/更新脚本

    if [ -n "$UUID" ] && [ "$UUID" != "0" ]; then
        info "检测到有效的 UUID ($UUID)，正在启用代理服务功能..."
        generate_subscription_info   # 7. 对外信息：提供给用户的订阅链接
        if [ -f "$WORK_DIR/webapp" ] && [ -x "$WORK_DIR/webapp" ]; then
             WEB_RUN="$WORK_DIR/webapp"
             info "代理服务 (webapp) 启动命令已配置。"
        else
             # 如果因为下载失败导致文件不存在，则取消启动
             hint "警告: $WORK_DIR/webapp 文件不存在或不可执行，代理服务将无法启动。"
             unset WEB_RUN
        fi
    else
        info "未设置有效的 UUID，将跳过代理服务的配置。"
        unset WEB_RUN # 确保 WEB_RUN 变量未被设置
    fi
  

    # 设置 AG_RUN
    if [[ "$DASH_VER" =~ ^(v)?0\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
      if [ "$IS_UPDATE" = 'no' ]; then
        AG_RUN="$WORK_DIR/nezha-agent -s localhost:$GRPC_PORT --disable-auto-update --disable-force-update -p $LOCAL_TOKEN"
      else
        AG_RUN="$WORK_DIR/nezha-agent -s localhost:$GRPC_PORT -p $LOCAL_TOKEN"
      fi
    else
      AG_RUN="$WORK_DIR/nezha-agent -c $WORK_DIR/data/config.yml"
    fi

    info "所有配置文件和脚本已生成完毕。"
}

generate_caddyfile() {
    # --- 内部辅助函数，用于生成 Caddyfile 的各个部分 ---

    # 生成文件头部和 PRO_PORT 块的起始部分
    _generate_caddy_header() {
        cat << EOF
{
  http_port $CADDY_HTTP_PORT
}

:$PRO_PORT {
EOF
    }

    # 生成 PRO_PORT 块中，如果存在 UUID 时的路由
    _generate_uuid_routes() {
        cat << EOF
  handle /${UUID} {
      file_server {
          root /tmp
          browse
      }
      rewrite * /list.log
  }

  reverse_proxy /vls* {
      to localhost:8002
  }

  reverse_proxy /vms* {
      to localhost:8001
  }
EOF
    }

    # 生成 PRO_PORT 块中，如果存在 API_TOKEN 但无 UUID 时的路由
    _generate_upload_route() {
        cat << EOF
  reverse_proxy /upload* {
      to localhost:8009
  }
EOF
    }

    # 生成 PRO_PORT 块的尾部（默认反向代理）
    _generate_caddy_default_proxy() {
        cat << EOF
  reverse_proxy {
      to localhost:$WEB_PORT
  }
}
EOF
    }

    # 生成 GRPC_PROXY_PORT 块
    _generate_caddy_grpc_block() {
        cat << EOF

:$GRPC_PROXY_PORT {
  reverse_proxy {
      to localhost:$GRPC_PORT
      transport http {
          versions h2c 2
      }
  }
  tls $WORK_DIR/nezha.pem $WORK_DIR/nezha.key
}
EOF
    }

    # --- 主逻辑：像搭积木一样组合各个部分 ---

    # 1. 总是写入文件头部和 PRO_PORT 块的开始
    #    使用 > 覆盖写入，创建一个新文件
    _generate_caddy_header > $WORK_DIR/Caddyfile

    # 2. 根据条件，追加写入中间的路由部分
    if [ -n "$API_TOKEN" ] && [ -n "$UUID" ] && [ "$UUID" != "0" ]; then
        # 情况A: API_TOKEN 和 UUID 都存在 -> 追加 VPN 路由
        _generate_uuid_routes >> $WORK_DIR/Caddyfile
    elif [ -n "$API_TOKEN" ] && ([ -z "$UUID" ] || [ "$UUID" == "0" ]); then
        # 情况B: API_TOKEN 存在但 UUID 无效 -> 追加 Upload 路由
        _generate_upload_route >> $WORK_DIR/Caddyfile
    elif [ -z "$API_TOKEN" ] && [ -n "$UUID" ] && [ "$UUID" != "0" ]; then
        # 情况C: API_TOKEN 不存在但 UUID 有效 -> 追加 VPN 路由
        _generate_uuid_routes >> $WORK_DIR/Caddyfile
    fi
    # 如果以上条件都不满足（例如 API_TOKEN 和 UUID 都无效），则什么都不追加，直接到下一步。

    # 3. 总是追加写入 PRO_PORT 块的结尾部分
    _generate_caddy_default_proxy >> $WORK_DIR/Caddyfile

    # 4. 总是追加写入 gRPC 块
    _generate_caddy_grpc_block >> $WORK_DIR/Caddyfile

    info "Caddyfile 已在 $WORK_DIR/Caddyfile 生成完毕。"
}

setup_services_and_cron() {
  # 生成定时任务: 1.每天北京时间 3:30:00 更新备份和还原文件，2.每天北京时间 4:00:00 备份一次，并重启 cron 服务； 3.每分钟自动检测在线备份文件里的内容
  [ -z "$NO_AUTO_RENEW" ] && [ -s $WORK_DIR/renew.sh ] && ! grep -q "$WORK_DIR/renew.sh" /etc/crontab && echo "30 3 * * * root bash $WORK_DIR/renew.sh" >> /etc/crontab
  [ -s $WORK_DIR/backup.sh ] && ! grep -q "$WORK_DIR/backup.sh" /etc/crontab && echo "0 * * * * root bash $WORK_DIR/backup.sh a" >> /etc/crontab
  [ -s $WORK_DIR/update.sh ] && ! grep -q "$WORK_DIR/update.sh" /etc/crontab && echo "0 4 * * * root bash $WORK_DIR/update.sh a" >> /etc/crontab
  [ -z "$NO_RES" ] && [ -s $WORK_DIR/restore.sh ] && ! grep -q "$WORK_DIR/restore.sh" /etc/crontab && echo "* * * * * root bash $WORK_DIR/restore.sh a" >> /etc/crontab
  service cron restart

  # 生成 supervisor 进程守护配置文件
  cat > /etc/supervisor/conf.d/damon.conf << EOF
[supervisord]
nodaemon=true
logfile=/dev/null
pidfile=/run/supervisord.pid

[program:grpcproxy]
command=$GRPC_PROXY_RUN
autostart=true
autorestart=true
stderr_logfile=/dev/null
stdout_logfile=/dev/null

[program:nezha]
command=$WORK_DIR/app
autostart=true
autorestart=true
stderr_logfile=/dev/null
stdout_logfile=/dev/null

[program:agent]
command=$AG_RUN
autostart=true
autorestart=true
stderr_logfile=/dev/null
stdout_logfile=/dev/null

[program:argo]
command=$ARGO_RUN
autostart=true
autorestart=true
stderr_logfile=/dev/null
stdout_logfile=/dev/null
EOF
  if [ -n "$API_TOKEN" ] && [ "$API_TOKEN" != "0" ]; then
    cat >> /etc/supervisor/conf.d/damon.conf << EOF

[program:nezfz]
command=$WORK_DIR/nezfz
autostart=true
autorestart=true
stderr_logfile=/dev/null
stdout_logfile=/dev/null
EOF
  fi
  if [ -n "$UUID" ] && [ "$UUID" != "0" ]; then
    cat >> /etc/supervisor/conf.d/damon.conf << EOF

[program:webapp]
command=$WEB_RUN
autostart=true
autorestart=true
stderr_logfile=/dev/null
stdout_logfile=/dev/null
EOF
  fi
}

# 主函数
main() {
    # 首次运行时执行以下流程，再次运行时存在 /etc/supervisor/conf.d/damon.conf 文件，直接到最后一步
    if [ ! -s /etc/supervisor/conf.d/damon.conf ]; then

        validate_environment
        setup_os_config
        ARCH=$(detect_architecture)
        download_dependencies
        generate_config_files
        setup_services_and_cron

        # 赋执行权给 sh 及所有应用
        chmod +x $WORK_DIR/{cloudflared,app,nezfz,nezha-agent,*.sh}

        # 运行 supervisor 进程守护
        supervisord -c /etc/supervisor/supervisord.conf
    else
        # 直接运行 supervisor
        supervisord -c /etc/supervisor/supervisord.conf
    fi
}


# 启动主函数
main "$@"
