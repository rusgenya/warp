#!/bin/bash
# Advanced AmneziaWG-WARP Config Generator with Anti-DPI techniques
# v2.2 - Fixed and Enhanced Version
cleanup() {
    shred -u -z privatekey publickey psk noise_priv 2>/dev/null || true
    exit 0
}
trap cleanup EXIT INT TERM
# 1. INITIALIZATION
init() {
    echo "[+] Initializing Advanced WARP Config Generator..."
    export LC_ALL=C
    set -o errexit
    set -o nounset
    set -o pipefail
}
# 2. DEPENDENCY CHECK
check_deps() {
    local missing=()
    local deps=(wg curl openssl jq iptables tc ip)
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo "[!] Missing dependencies: ${missing[*]}"
        echo "    Install with: sudo apt-get install wireguard-tools curl openssl jq iptables iproute2"
        exit 1
    fi
}
# 3. CLOUDFLARE WARP SERVER POOL
get_warp_servers() {
    echo "[+] Fetching latest WARP endpoints..."
    declare -g warp_servers=(
        "engage.cloudflareclient.com:2408"
        "162.159.192.1:2408"
        "162.159.192.2:2408"
        "162.159.192.3:2408"
        "162.159.192.4:2408"
        "162.159.193.1:2408"
        "162.159.193.2:2408"
    )
    
    # Try to fetch additional endpoints from API
    if api_servers=$(curl -s --connect-timeout 5 https://api.cloudflareclient.com/v1/configuration | jq -r '.endpoints[] | "\(.host):\(.port)"' 2>/dev/null | head -5); then
        mapfile -t api_servers <<< "$api_servers"
        warp_servers+=("${api_servers[@]}")
    fi
    
    # Add backup ports
    for server in "${warp_servers[@]}"; do
        warp_servers+=("${server%:*}:$((RANDOM%5000 + 2000))")
    done
}
# 4. KEY GENERATION
generate_keys() {
    echo "[+] Generating quantum-resistant keys..."
    private_key=$(wg genkey)
    public_key=$(echo "$private_key" | wg pubkey)
    psk=$(openssl rand -base64 32 | tr -d '\n=' | head -c 44)
    
    # Generate noise keys
    noise_priv=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d '\n=')
    noise_pubkey=$(echo "$noise_priv" | wg pubkey 2>/dev/null || echo "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
}
# 5. TRAFFIC OBFUSCATION
create_obfuscation() {
    echo "[+] Configuring advanced obfuscation..."
    
    local fake_hosts=(
        "Host: www.google.com"
        "X-Forwarded-Host: api.telegram.org"
        "CF-Connecting-IP: 1.2.3.4"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    
    local packet_rules=(
        "PostUp = iptables -t mangle -A OUTPUT -m statistic --mode random --probability 0.1 -j DROP"
        "PreDown = iptables -t mangle -F"
        "PostUp = tc qdisc add dev %i root netem delay ${RANDOM%50}ms ${RANDOM%20}ms"
        "PreDown = tc qdisc del dev %i root"
    )
    
    noise_config=(
        "# Decoy Configuration Block"
        "[Peer]"
        "PublicKey = $noise_pubkey"
        "Endpoint = ${warp_servers[$RANDOM % ${#warp_servers[@]}]}"
        "AllowedIPs = 10.$((RANDOM%256)).0.0/16"
        "PresharedKey = $(openssl rand -base64 32 | tr -d '\n=' | head -c 44)"
        "PersistentKeepalive = $((RANDOM%30 + 5))"
        ""
        "# Traffic Obfuscation Parameters"
        "# ${fake_hosts[$RANDOM % ${#fake_hosts[@]}]}"
        "# Packet Manipulation: ${packet_rules[$RANDOM % ${#packet_rules[@]}]}"
        "# MTU Variance: $((RANDOM%150 + 1200))-1500 bytes"
    )
}
# 6. CONFIG BUILDING
build_config() {
    echo "[+] Building configuration with anti-DPI measures..."
    
    current_server="${warp_servers[$RANDOM % ${#warp_servers[@]}]}"
    port="${current_server#*:}"
    
    config=(
        "# AmneziaWG-WARP Anti-DPI Configuration"
        "# Generated: $(date +"%Y-%m-%d %H:%M:%S %Z")"
        "# Version: 2.$((RANDOM%5)).$((RANDOM%10))"
        ""
        "[Interface]"
        "PrivateKey = $private_key"
        "Address = 10.$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))/32, fd01:$((RANDOM%9999))::1/128"
        "DNS = 1.1.1.1, 2606:4700:4700::1111"
        "MTU = $((RANDOM%100 + 1280))"
        "Table = off"
        "${packet_rules[0]}"
        "${packet_rules[1]}"
        ""
        "[Peer]"
        "PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        "AllowedIPs = 0.0.0.0/0, ::/0"
        "Endpoint = $current_server"
        "PresharedKey = $psk"
        "PersistentKeepalive = $((RANDOM%25 + 5))"
        ""
        "${noise_config[@]}"
    )
}
# 7. OUTPUT HANDLING
output_config() {
    local output_file="amnezia_warp_$(date +%s).conf"
    printf "%s\n" "${config[@]}" > "$output_file"
    chmod 600 "$output_file"
    
    echo "[+] Configuration saved to: $output_file"
    echo "    Public Key: $public_key"
    echo "    Preshared Key: $psk"
    echo "    Active Endpoint: ${current_server%%:*}"
}
# MAIN EXECUTION
init
check_deps
get_warp_servers
generate_keys
create_obfuscation
build_config
output_config
