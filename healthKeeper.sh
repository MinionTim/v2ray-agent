#!/bin/bash

# 自定义字体彩色，read 函数
warning() { echo -e "\033[31m\033[01m$*\033[0m"; }  # 红色
error() { echo -e "\033[31m\033[01m$*\033[0m"; }  # 红色
info() { echo -e "\033[32m\033[01m$*\033[0m"; }   # 绿色
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }   # 黄色
reading() { read -rp "$(info "$1")" "$2"; }


function check_ip {
    echo "======================== [$(date +"%Y-%m-%d %H:%M:%S")] ================================="
    domain=$(jq -r .inbounds[0].settings.clients[0].add /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json)
    port=$(jq -r .inbounds[0].port /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json)   
    echo "Auto check with: ${domain}:${port}, count=[$check_retry_count, $http_retry_count]"
    inside_tcp=""
    outside_tcp=""
    # 国内检测
    url="https://www.toolsdaquan.com/toolapi/public/ipchecking/$domain/$port"
    echo "Checking server [inside], url = ${url}"
    headers=(
        -H "sec-ch-ua: \"Chromium\";v=\"112\", \"Google Chrome\";v=\"112\", \"Not:A-Brand\";v=\"99\""
        -H "Accept: application/json, text/javascript, */*; q=0.01"
        -H "Referer: https://www.toolsdaquan.com/ipcheck/"
        -H "X-Requested-With: XMLHttpRequest"
        -H "sec-ch-ua-mobile: ?0"
        -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
        -H "sec-ch-ua-platform: \"macOS\""
        --compressed
    )

    local ret_inside
    response=$(curl -sSL "${url}" "${headers[@]}")
    tcp_status=$(echo "$response" | jq -r '.tcp')
    if [ "$tcp_status" == "success" ]; then
        ret_inside=0
        inside_tcp="国内: TCP可用"
    elif [ "$tcp_status" == "fail" ]; then
        ret_inside=1
        inside_tcp="国内: TCP不可用"
    else
        ret_inside=2
        inside_tcp="程序异常"
        echo ${response}
    fi
    sleep 1

    # 国外检测 -2
    local ret_outside
    echo "Checking server [outside]..."
    # 检查端口连接是否成功
    if nc -z "$domain" "$port" >/dev/null 2>&1; then
        echo "outside连接成功：$domain:$port"
        ret_outside=0
        outside_tcp="国外: TCP可用"
    else
        echo "outside连接失败：$domain:$port"
        ret_outside=1
        outside_tcp="国外: TCP不可用"
    fi

    # 国外检测 -1 , www.toolsdaquan.com 异常，切换成 nc检查
#    local ret_outside
#    url="https://www.toolsdaquan.com/toolapi/public/ipchecking2/$domain/$port"
#    echo "Checking server [outside], url = ${url}"
#    response=$(curl -sSL "${url}" "${headers[@]}")
#    tcp_status=$(echo "$response" | jq -r '.outside_tcp')
#    if [ "$tcp_status" == "success" ]; then
#        ret_outside=0
#        outside_tcp="国外: TCP可用"
#    elif [ "$tcp_status" == "fail" ]; then
#        ret_outside=1
#        outside_tcp="国外: TCP不可用"
#    else
#        ret_outside=2
#        outside_tcp="程序异常"
#        echo ${response}
#    fi

    # 国内不通，国外通
    if [ "$ret_inside" == "1" ] && [ "$ret_outside" == "0" ]; then
        if [ $check_retry_count -eq $max_check_retry_count ]; then
            echo "Reach the max retry count, exit the process."
            send_msg_by_slack " *自检服务异常* ，自动更改配置失败重试达到最大次数，请登录服务查看日志."
            exit
        fi
        
        if [ $http_retry_count -eq $max_http_retry_count ]; then
            check_failed=1
            echo "Port blocked by GFW, begin to change config..."
            send_msg_by_slack ":slightly_frowning_face: *国内连接受阻* ，即将更新节点配置，稍后请查看订阅。当前受阻节点: $domain:$port"
            change_config
            check_retry_count=$[$check_retry_count+1]
            http_retry_count=0
            check_ip
        else
            http_retry_count=$[$http_retry_count+1]
            sleep 3
            echo "Check IP Bloacked. Retrying..."
            check_ip
        fi
        
    elif [ "$ret_inside" == "0" ] && [ "$ret_outside" == "0" ]; then
        echo "Server check heathy. Good ^_^ "
        if [ "${check_failed}" == "1" ]; then
            send_msg_by_slack ":tada:恭喜，节点已检测通过，继续保持～ 节点: $domain:$port"
            check_failed=0
        fi
        local d=$(date +%H:%M)
        if [[ "${d}" > "08:00" && "${d}" < "08:30" ]] || [[ "${d}" > "12:00" && "${d}" < "12:30" ]] || [[ "${d}" > "18:00" && "${d}" < "18:30" ]]; then
            send_msg_by_slack ":tada:当前节点检测通过，继续保持～ 节点: $domain:$port"
        fi
        
    else
        echo "Server down / firewall blocked, please check"
        send_msg_by_slack ":slightly_frowning_face:节点检测异常，原因可能是服务异常。稍后会自动重试，请登录服务器检查。当前受阻节点: $domain:$port"
    fi
}

function change_config() {
    local domain_current=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].myCurrentDomain /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json)
    local domain_wilechid=$(echo "${domain_current}" | cut -d'.' -f 2-)
    local domain_new="au$(date +%y%m%d%H%M%S).${domain_wilechid}"
    # local domain_new=${domain_current}
    local port=$(jq -r .inbounds[0].port /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json)   
    local port_new=$[$port+1]

    # 更新lightsail 和 CloudFlare，如果更新失败，则仅更新port、uuid。
    remote_update_ip_dns ${domain_new} ${domain_current}
    if [ $? -ne 0 ]; then
        domain_new=${domain_current}
        echo "Lightsail或CloudFlare异常，仅更新port\uuid。"
        send_msg_by_slack "Lightsail或CloudFlare异常，仅更新port\uuid。"
    fi

    sed -i "s/${domain_current}/${domain_new}/g" /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
    sed -i "s/port\": ${port},/port\": ${port_new},/g" /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
    
    sed -i "s/${domain_current}/${domain_new}/g" /etc/nginx/conf.d/alone.conf
    sed -i "s/${domain_new}:${port}/${domain_new}:${port_new}/g" /etc/nginx/conf.d/alone.conf

    change_uuid

    restart_progress
    send_msg_by_slack "更新成功：port、uuid、domain. ${domain_current}:${port} => ${domain_new}:${port_new}"

    bash ${v2ray_agent_install_path} autoSubscribe
    update_subscribe
}

function restart_progress() {
    systemctl restart xray
    sleep 2
    if [[ -n $(pgrep -f "xray/xray") ]]; then
        echo "Xray restart success."
    else
        echo "Xray restart fail."
        echo"请手动执行【/etc/v2ray-agent/xray/xray -confdir /etc/v2ray-agent/xray/conf】，查看错误日志"
        send_msg_by_slack "重启 Xray 服务失败，请登录服务器查看日志."
        exit 0
    fi
    
    # update nginx port
    systemctl reload nginx
    sleep 1
    echo "Nginx restart success."
}

function change_uuid() {
    jq .inbounds[0].settings.clients /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
        local uuid=$(echo "${user}" | jq -r .id)
        local email_prefix=$(echo "${user}" | jq -r .email | awk -F "[-]" '{print $1}')
        local email="\"email\": \"${email_prefix}-"

        local uuid_new=$(/etc/v2ray-agent/xray/xray uuid)
        local email_prefix_new=$(echo "${uuid_new}" | awk -F "[-]" '{print $1}')
        local email_new="\"email\": \"${email_prefix_new}-"
        echo "uuid: ${uuid} ==> ${uuid_new}"
        echo "email: ${email} ==> ${email_new}"
        sed -i "s/${uuid}/${uuid_new}/g" /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
        sed -i "s/${uuid}/${uuid_new}/g" /etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
        sed -i "s/${uuid}/${uuid_new}/g" /etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
        sed -i "s/${uuid}/${uuid_new}/g" /etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json

        sed -i "s/${email}/${email_new}/g" /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
        sed -i "s/${email}/${email_new}/g" /etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
        sed -i "s/${email}/${email_new}/g" /etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
        sed -i "s/${email}/${email_new}/g" /etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json

    done
    echo "uuid更新完成"

    # systemctl restart xray
    # sleep 2
    # if [[ -n $(pgrep -f "xray/xray") ]]; then
    #     echo "Xray restart success."
    # else
    #     echo "Xray restart fail."
    #     echo"请手动执行【/etc/v2ray-agent/xray/xray -confdir /etc/v2ray-agent/xray/conf】，查看错误日志"
    #     mv /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json.autobackup.$st /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
    #     echo "Rollback changing operation."
    #     send_msg_by_slack "重启 Xray 服务失败，请登录服务器查看日志."
    #     exit 0
    # fi
    # bash $v2ray_agent_install_path autoSubscribe
    # send_msg_by_slack "uuid更新成功"


}

# 不传参数needcheck，即表示强制更新
function update_subscribe() {
    local port=$(jq -r .inbounds[0].port /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json)
    local user=$(jq -r .inbounds[0].settings.clients[0].email /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json | awk -F "[-]" '{print $1}')
    # 指定需要检查文件状态，同时文件已存在，则不执行后续逻辑。
    if [ "$1" == "needcheck" ] && [ -n "/etc/v2ray-agent/subscribe_local/default/${user}.autogenerate" ]; then
        echo "File exists. update subscribe canceled. file=/etc/v2ray-agent/subscribe_local/default/${user}.autogenerate"
        return
    fi

    local local_auto_file="/etc/v2ray-agent/subscribe_local/default/${user}.autogenerate"
    cat "/etc/v2ray-agent/subscribe_local/default/${user}" | grep -v "TLS_Vision" > "${local_auto_file}"

    # 更新vmess协议的端口号，因为vmess进行了base64编码，所以这里需要先解码再修改，再编码
    while IFS= read -r line; do
        if [[ $line == vmess://* ]]; then
            decoded_content=$(echo "$line" | cut -d'/' -f3 | base64 -d)
            new_content=$(echo "$decoded_content" | sed "s/\"port\":[0-9]\+/\"port\":$port/g")
            updated_content="vmess://$(echo "$new_content" | base64 -w 0)"
            echo "$updated_content"
        else
            # 非vmess://开头的行直接输出
            echo "$line"
        fi
    done < "${local_auto_file}" > .temp_file_swap_vmess && mv .temp_file_swap_vmess "${local_auto_file}"

    sed -Ei "s/:[0-9]*\?/:${port}\?/g" "${local_auto_file}"
    echo "${extra_nodes}" | grep -v "^$" >> "${local_auto_file}"
    # 将以"vmess://"或"vless://"开头的行调整到最后
    grep -Ev '^(vmess|vless)://' "${local_auto_file}" >> output.temp && grep -E '^(vmess|vless)://' "${local_auto_file}" >> output.temp && mv output.temp "${local_auto_file}"
    local base64Result
    base64Result=$(base64 -w 0 "${local_auto_file}")
    echo "${base64Result}" >"/etc/v2ray-agent/subscribe/default/autogenerate"

    # 去除重复行
    sort -u "${local_auto_file}" -o "${local_auto_file}"
    echo "Update subscribe file done. Latest content >>>>"
    cat "${local_auto_file}"
    echo "======= END ======"

    local directory="/etc/v2ray-agent/subscribe/clashMeta"
    latest_file=$(ls -t "$directory" | grep -v "autogenerate" | head -1)
    if [ -z "$latest_file" ]; then
        echo "目录为空或未找到配置文件"
    else
        cp -f "$directory/$latest_file" "$directory/autogenerate" && echo "已成功复制文件 ${directory}/${latest_file}, 并重命名为autogenerate"
    fi

    local directory="/etc/v2ray-agent/subscribe/clashMetaProfiles"
    latest_file=$(ls -t "$directory" | grep -v "autogenerate" | head -1)
    if [ -z "$latest_file" ]; then
        echo "目录为空或未找到配置文件"
    else
        cp -f "$directory/$latest_file" "$directory/autogenerate" && echo "已成功复制文件 ${directory}/${latest_file}, 并重命名为autogenerate"
    
        # 使用 awk 命令替换同时包含 "clashMeta" 和 "url" 的行为 "abdc"
        replacement="url: https://worker.fh6766.com/subscribe-clashmeta/serving-the-net"
        # awk -v repl="${replacement}" '/clashMeta/ && /url/ { $0 = repl } 1' "$directory/autogenerate" > temp.yaml && mv temp.yaml "$directory/autogenerate"

        # 使用 awk 命令替换同时包含 "clashMeta" 和 "url" 的行，并保留行前的空格
        awk -v repl="$replacement" '/clashMeta/ && /url/ { match($0, /^[[:space:]]*/); spaces = substr($0, RSTART, RLENGTH); $0 = spaces repl } 1' "$directory/autogenerate" > temp.yaml && mv temp.yaml "$directory/autogenerate"
    fi
}

# update_dns xx.example.org 10.10.10.80 yy.example.org
# 域名若存在，则更新A解析; 否则创建并解析，同时删除指定域名
function update_dns() {
    local subdomain=$1
    local new_ip=$2
    local last_domain=$3
    local api_url="https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records"

    # 获取子域名当前的 DNS 记录
    sleep 1
    local response=$(curl -s -X GET "${api_url}?type=A&name=${subdomain}" \
        -H "X-Auth-Email: ${EMAIL}" \
        -H "X-Auth-Key: ${API_KEY}" \
        -H "Content-Type: application/json")

    # 解析 JSON 数据并提取当前的 IP 地址和记录 ID
    local current_ip=$(echo "$response" | jq -r '.result[0].content // ""')
    local record_id=$(echo "$response" | jq -r '.result[0].id // ""') #找不到该字段，则返回空，而不是null
    echo ${record_id}

    if [ -z "$record_id" ]; then
        echo "创建子域名"
        # 子域名不存在，创建 A 记录
        sleep 1
        local response=$(curl -s -X POST "${api_url}"  \
            -H "X-Auth-Email: ${EMAIL}" \
            -H "X-Auth-Key: ${API_KEY}" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"${subdomain}\",\"content\":\"${new_ip}\",\"ttl\":1,\"proxied\":false}")
        local status=$(echo "$response" | jq -r '.success // ""')
        if [ "$status" = "true" ]; then
            echo "New subdomain (${subdomain}) created with A record: ${new_ip}"
            send_msg_by_slack "CloudFlare域名解析更新成功。创建新域名，${subdomain} A记录解析到 ${new_ip}"

            # 删除旧域名
            if [ -n "${last_domain}" ]; then
                delete_dns_record ${last_domain}
                 if [ $? -ne 0 ]; then
                    send_msg_by_slack "**操作失败**，CloudFlare域名,删除域名失败。"
                fi
            fi
            return 0
        fi
    else
        # 更新子域名的 IP 地址
        echo "更新子域名"
        sleep 1
        local response=$(curl -s -X PUT "${api_url}/${record_id}"  \
            -H "X-Auth-Email: ${EMAIL}" \
            -H "X-Auth-Key: ${API_KEY}" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"${subdomain}\",\"content\":\"${new_ip}\",\"ttl\":1,\"proxied\":false}")
        local status=$(echo "$response" | jq -r '.success // ""')
        if [ "$status" = "true" ]; then
            echo "Domain: ${subdomain}, A record has been updated from ${current_ip} to ${new_ip}"
            send_msg_by_slack "CloudFlare域名解析更新成功。A记录 ${subdomain} 从 ${current_ip} 更新到 ${new_ip}"
            return 0
        fi
    fi

    echo "Failed to update DNS record. response: ${response}"
    return -1
}

function delete_dns_record() {
    local domain=$1
    local api_url="https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records"
    
    sleep 1
    local response=$(curl -s -X GET "${api_url}?type=A&name=${domain}" \
        -H "X-Auth-Email: ${EMAIL}" \
        -H "X-Auth-Key: ${API_KEY}" \
        -H "Content-Type: application/json")

    # 解析 JSON 数据并提取当前的 IP 地址和记录 ID
    local record_id=$(echo "$response" | jq -r '.result[0].id // ""') #找不到该字段，则返回空，而不是null

    # 检查记录是否存在
    if [ -z "$record_id" ]; then
        echo "DNS record not found for ${domain}"
        return 1
    fi

    # 删除记录
    sleep 1
    delete_response=$(curl -s -X DELETE "${api_url}/${record_id}" \
        -H "X-Auth-Email: ${EMAIL}" \
        -H "X-Auth-Key: ${API_KEY}" \
        -H "Content-Type: application/json")

    # 检查删除是否成功
    delete_status=$(echo "$delete_response" | jq -r '.success')

    if [ "$delete_status" = "true" ]; then
        echo "DNS record deleted for ${domain}"
        return 0
    else
        echo "Failed to delete DNS record for ${domain}"
        send_msg_by_slack "Failed to delete DNS record for ${domain}"
    fi
    return -1
}


# update_staticip 仅更新LightSail实例的静态ip
function update_staticip() {
    local INSTANCE_NAME=${G_INSTANCE_NAME}
    local REGION=${G_REGION}
    local NEW_IP_NAME="AutoGen-$(date +%y%m%d-%H%M%S)"

    # 函数：检查命令执行结果
    check_command_result() {
        if [ $? -ne 0 ]; then
            echo "命令执行失败：$1"
            send_msg_by_slack "更新LightSail静态IP **失败** ，命令执行失败：$1"
            exit 1
        fi
    }

    # 获取绑定指定实例的静态 IP 名称
    echo "正在查询当前实例及IP绑定..."
    local old_ip_info=$(aws lightsail get-static-ips --region $REGION --query 'staticIps[?attachedTo==`'$INSTANCE_NAME'`].[name, ipAddress]' --output json)
    check_command_result "无法查询到绑定了实例${INSTANCE_NAME} 的IP"
    local old_ip=$(echo ${old_ip_info} | jq -r '.[][0]')
    local old_ip_addr=$(echo ${old_ip_info} | jq -r '.[][1]')
    if [ -z "${old_ip_addr}" ]; then
        echo "无法查询到绑定了实例${INSTANCE_NAME} 的IP"
        send_msg_by_slack "更新LightSail静态IP **失败** ，无法查询到绑定了实例${INSTANCE_NAME} 的IP"
        return 1
    fi
    echo "当前实例 < ${INSTANCE_NAME} > 绑定的ip为ip: ${old_ip}, ${old_ip_addr}"

    # 创建新的静态 IP
    echo "正在创建新IP，并绑定实例..."
    sleep 1
    local new_ip=$(aws lightsail allocate-static-ip --static-ip-name ${NEW_IP_NAME} --region $REGION --query 'operations[0].resourceName' --output text)
    check_command_result "无法创建新的静态 IP"
    
    # 绑定新的静态 IP,并默认将旧IP解除绑定
    sleep 1
    aws lightsail attach-static-ip --static-ip-name $new_ip --instance-name $INSTANCE_NAME --region $REGION >> /tmp/aws.log
    check_command_result "无法绑定新的静态 IP"


    # 删除旧的静态 IP
    echo "正在删除旧IP..."
    sleep 1
    aws lightsail release-static-ip --static-ip-name $old_ip --region $REGION >> /tmp/aws2.log
    check_command_result "无法删除旧的静态 IP"
    

    g_new_ip_addr=$(aws lightsail get-static-ips --region $REGION --query 'staticIps[?attachedTo==`'$INSTANCE_NAME'`].ipAddress' --output text)

    if [[ $g_new_ip_addr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "公网 IP 更新成功！实例: ${INSTANCE_NAME}, IP changed from ${old_ip_addr} to ${g_new_ip_addr}"
        send_msg_by_slack "LightSail公网 IP 更新成功！实例: ${INSTANCE_NAME}, IP changed from ${old_ip_addr} to ${g_new_ip_addr}"
        return 0
    else
        send_msg_by_slack "LightSail公网 IP 更新失败！实例: ${INSTANCE_NAME}"
    fi

    return 1
}

# 更新实例的staticip，并将域名解析指向新的ip
function remote_update_ip_dns() {
    # 新域名domain_proxy_new， 旧域名：domain_proxy_last
    local domain_proxy_new=$1
    local domain_proxy_last=$2
    local domain_host=host.$(echo "${domain_proxy_new}" | cut -d'.' -f 2-)
    local domain_test=test2.$(echo "${domain_proxy_new}" | cut -d'.' -f 2-)
    update_dns $domain_test "54.95.15.1"
    if [ $? -ne 0 ]; then
        echo "CloudFlare 测试域名执行失败，可能是CloudFlare异常"
        send_msg_by_slack "**操作失败**，CloudFlare 测试域名执行失败，可能是CloudFlare异常"
        return 1
    fi

    update_staticip
    if [ $? -ne 0 ]; then
        echo "remote_update_ip_dns命令执行失败： update_staticip"
        send_msg_by_slack "**操作失败**，LightSail更新公网IP失败。"
        return 1
    fi
    # 更新host域名
    update_dns $domain_host $g_new_ip_addr
    if [ $? -ne 0 ]; then
        echo "remote_update_ip_dns命令执行失败： update_dns"
        send_msg_by_slack "**操作失败**，CloudFlare域名解析修改失败。"
        return 1
    fi

    # 更新proxy域名
    update_dns $domain_proxy_new $g_new_ip_addr $domain_proxy_last
    if [ $? -ne 0 ]; then
        echo "remote_update_ip_dns命令执行失败： update_dns"
        send_msg_by_slack "**操作失败**，CloudFlare域名解析修改失败。"
        return 1
    fi

    send_msg_by_slack "更换IP成功"
    return 0
}

# send_msg_by_slack "测试消\n123息", "guahao"
function send_msg_by_slack() {
    message="$@"
    url="https://slack.com/api/chat.postMessage"
    channel="C0551JF7Q76"  # Replace with your Slack channel ID
    token="xoxb-229343062502-3527341865107-aGJnKeG0m0Ftf5dfHvZYLcxH"  # Replace with your Slack Bot token

    payload="{\"channel\":\"${channel}\",\"text\":\"${message}\"}"
    headers=(
        -H "Authorization: Bearer ${token}"
        -H "Content-Type: application/json; charset=utf-8"
    )
    response=$(curl -sSL -X POST "${url}" -d "${payload}" "${headers[@]}")
    if echo "${response}" | jq -e '.ok' > /dev/null; then
        echo "[Slack] Message sent successfully!"
    else
        echo "[Slack] Failed to send message:"
        echo "${response}" | jq
    fi
}

function ensure_server_configs(){
    # configuration for CloudFlare.
    local config="${HOME}/.vps-healthy"

    if [[ ! -f "${config}" ]]; then
        error "Config file Not Found in path: ${config}"
        exit 1
    fi
    API_KEY=$(jq -r .CloudFlare.API_KEY ${config})
    EMAIL=$(jq -r .CloudFlare.EMAIL ${config})
    ZONE_ID=$(jq -r .CloudFlare.ZONE_ID ${config})

    # configuration for LightSail
    G_INSTANCE_NAME=$(jq -r .LightSail.G_INSTANCE_NAME ${config})
    G_REGION=$(jq -r .LightSail.G_REGION ${config})

    if [[ "${API_KEY}" = "null" ]] || [[ "${EMAIL}" = "null" ]] || [[ "${ZONE_ID}" = "null" ]] || [[ "${G_INSTANCE_NAME}" = "null" ]] || [[ "${G_REGION}" = "null" ]]; then
        echo "Error: CloudFlare or LightSail or Domain configuration not set in ${config}"
        exit
    fi
    echo "Find Configs of CloudFlare and LightSail."
}

function test_configs() {
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
        -H "X-Auth-Email: $EMAIL" \
        -H "X-Auth-Key: $API_KEY" \
        -H "Content-Type: application/json")

    success=$(echo "$response" | jq -r '.success')
    if [ "$success" == "true" ]; then
        echo "CloudFlare API Request Success."
    else
        errors=$(echo "$response" | jq -r '.errors')
        echo "CloudFlare API 请求失败: $errors"
    fi

    local instance_info=$(aws lightsail get-instance --instance-name $G_INSTANCE_NAME --region $G_REGION)
    if [ -z "$instance_info" ]; then
        echo "LightSail Cli Error."
    else
        echo "LightSail Cli Request Success."
    fi
}

function install(){
    local config="${HOME}/.vps-healthy"
    if [[ ! -f "${config}" ]]; then
       cat <<EOF >${config}
{
    "CloudFlare": {
        "API_KEY": "",
        "EMAIL":"",
        "ZONE_ID":""
    },

    "LightSail": {
        "G_INSTANCE_NAME": "",
        "G_REGION": ""
    }
}
EOF
    fi

    cron_command="*/15 * * * * /bin/bash /etc/v2ray-agent/healthKeeper.sh >> /etc/v2ray-agent/logs/log_health_keeper.log 2>&1"
    existing_cron_jobs=$(crontab -l 2>/dev/null)
    if ! echo "$existing_cron_jobs" | grep -qF "$cron_command"; then
        (crontab -l 2>/dev/null; echo "$cron_command") | crontab -
    fi
}

function uninstall() {
    # 移除 包含“/etc/v2ray-agent/healthKeeper.sh”的定时任务
    crontab -l | grep -v "/etc/v2ray-agent/healthKeeper.sh" | crontab -
    # 卸载时保留 .vps-healthy 配置文件
    info "vahealth所需的配置文件不会被删除，若需删除请手动执行 [rm -fr ~/.vps-healthy]"
}

function _test_run() {
    echo "test run..."
    ensure_server_configs
}

# usage:
# bash healthKeeper.sh [subscribe]
function main() {
    if [[ "$1" == "-h" ]]; then
        echo "usage:"
        echo "bash healthKeeper.sh [ subscribe | _dns | _staticip | ip-dns | test-run ]"
    elif [ "$1" = "subscribe" ]; then
        echo "Only execute update subscribe action."
        update_subscribe
    elif [ "$1" = "_dns" ]; then
        ensure_server_configs
        update_dns "a1.example.com" "10.10.10.40"
    elif [ "$1" = "_staticip" ]; then
        ensure_server_configs
        update_staticip
    elif [ "$1" = "ip-dns" ]; then
        ensure_server_configs
        remote_update_ip_dns
    elif [ "$1" = "change-uuid" ]; then
        change_uuid
    elif [ "$1" = "change-config" ]; then
        ensure_server_configs
        change_config
    elif [ "$1" = "test-configs" ]; then
        ensure_server_configs
        test_configs
    elif [ "$1" = "_test-run" ]; then
        _test_run
    elif [ "$1" = "install" ]; then
        install
    elif [ "$1" = "uninstall" ]; then
        uninstall
    else
        ensure_server_configs
        echo "Auto check with: ${domain}:${port}"
        update_subscribe needcheck
        check_ip
    fi
}

#http失败时，会重试
http_retry_count=0
max_http_retry_count=2

# 连续多次失败
check_retry_count=0
max_check_retry_count=2
check_failed=0
extra_nodes=""
v2ray_agent_install_path="/etc/v2ray-agent/install.sh"
domain=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].myCurrentDomain /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json)
port=$(jq -r .inbounds[0].port /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json)

main "$@"
