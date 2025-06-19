#!/bin/bash
# Fixed AmneziaWG-WARP Config Generator

cleanup() {
    shred -u -z privatekey publickey psk noise_priv 2>/dev/null || true
    exit 0
}
trap cleanup EXIT INT TERM

init() {
    echo "[+] Initializing WARP Config Generator..."
    export LC_ALL=C
    set -o errexit -o nounset -o pipefail
}

check_deps() {
    local missing=()
    local deps=(wg curl openssl)
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo "[!] Missing: ${missing[*]}"
        echo "    Install: sudo apt install wireguard-tools curl openssl"
        exit 1
    fi
}

get_warp_servers() {
    echo "[+] Getting WARP endpoints..."
    warp_servers=(
        "engage.cloudflareclient.com:2408"
        "162.159.192.1:2408"
        "162.159.192.2:2408"
        "162.159.192.3:2408"
        "162.159.192.4:2408"
    )
    
    # Add random ports
    for server in "${warp_servers[@]}"; do
        warp_servers+=("${server%:*}:$((RANDOM%5000 + 2000))")
    done
}

generate_keys() {
    echo "[+] Generating keys..."
    private_key=$(wg genkey)
    public_key=$(echo "$private_key" | wg pubkey)
    psk=$(openssl rand -base64 32 | tr -d '\n=' | head -c 44)
}

create_config() {
    local server="${warp_servers[$RANDOM % ${#warp_servers[@]}]}"
    
    cat > "warp_$(date +%s).conf" <<EOF
# AmneziaWG-WARP Config
# Generated: $(date +"%Y-%m-%d %H:%M:%S")

[Interface]
PrivateKey = $private_key
Address = 10.$((RANDOM%256)).$((RANDOM%256)).2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = $server
PresharedKey = $psk
PersistentKeepalive = 25
EOF
}

# Main execution
init
check_deps
get_warp_servers
generate_keys
create_config

echo "[+] Config file generated: $(ls warp_*.conf)"
