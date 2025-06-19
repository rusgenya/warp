#!/bin/bash
# AmneziaWG-WARP Config Generator (Fixed Version)
# Last Updated: 2024-03-15

cleanup() {
    [ -f "privatekey" ] && shred -u -z privatekey
    [ -f "publickey" ] && shred -u -z publickey
    [ -f "psk" ] && shred -u -z psk
    exit 0
}

error_exit() {
    echo "[ERROR] $1" >&2
    cleanup
    exit 1
}

check_dependencies() {
    local deps=("wg" "curl" "openssl")
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error_exit "Missing required tool: $cmd"
        fi
    done
}

generate_keys() {
    if ! wg genkey > privatekey; then
        error_exit "Failed to generate private key"
    fi
    
    if ! wg pubkey < privatekey > publickey; then
        error_exit "Failed to generate public key"
    fi
    
    if ! openssl rand -base64 32 | tr -d '\n=' | head -c 44 > psk; then
        error_exit "Failed to generate PSK"
    fi
    
    private_key=$(cat privatekey)
    public_key=$(cat publickey)
    psk=$(cat psk)
}

get_warp_endpoints() {
    endpoints=(
        "engage.cloudflareclient.com:2408"
        "162.159.192.1:2408"
        "162.159.192.2:2408"
        "162.159.192.3:2408"
        "162.159.192.4:2408"
        "162.159.193.1:2408"
        "162.159.193.2:2408"
    )
    
    # Add random ports
    for server in "${endpoints[@]}"; do
        endpoints+=("${server%:*}:$((RANDOM%5000 + 2000))")
    done
}

create_config() {
    local selected_endpoint="${endpoints[$RANDOM % ${#endpoints[@]}]}"
    local config_file="warp_config_$(date +%s).conf"
    
    cat > "$config_file" <<EOF
# AmneziaWG-WARP Configuration
# Generated: $(date +"%Y-%m-%d %H:%M:%S")

[Interface]
PrivateKey = $private_key
Address = 10.$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))/32
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = $((RANDOM%100 + 1280))

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $selected_endpoint
PresharedKey = $psk
PersistentKeepalive = $((RANDOM%25 + 5))
EOF

    chmod 600 "$config_file"
    echo "$config_file"
}

main() {
    trap cleanup EXIT INT TERM
    
    echo "[+] Starting WARP configuration generator"
    check_dependencies
    generate_keys
    get_warp_endpoints
    
    local config_file
    config_file=$(create_config)
    
    echo "[+] Successfully generated configuration file: $config_file"
    echo "    Public Key: $public_key"
    echo "    Preshared Key: $psk"
}

main "$@"
