#!/bin/bash

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

echo "Scanning running services and open firewall ports..."
echo

# Step 1: Get listening services and ports (TCP/UDP)
echo "[+] Collecting listening services..."
LISTENING=$(ss -tulnp | awk 'NR>1 {print $1, $5, $7}' | sort -u)

# Step 2: Get open ports from the firewall (firewalld or iptables)
echo "[+] Checking firewall for open ports..."

# Function to extract open ports from firewalld
get_firewalld_ports() {
    firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | sed 's/\/.*//' | sort -u
}

# Function to extract open ports from iptables
get_iptables_ports() {
    iptables -L INPUT -n | grep "ACCEPT" | grep -Eo '[0-9]{1,5}' | sort -u
}

if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
    echo "[+] Firewalld detected and running."
    OPEN_PORTS=$(get_firewalld_ports)
elif command -v iptables &>/dev/null; then
    echo "[+] Firewalld not detected. Falling back to iptables."
    OPEN_PORTS=$(get_iptables_ports)
else
    echo "[-] No supported firewall (firewalld or iptables) found."
    exit 1
fi

# Step 3: Match listening ports with open firewall ports
echo
echo "[+] Matching listening services with open firewall ports:"
echo

while read -r proto addr pidinfo; do
    # Extract the port
    PORT=$(echo "$addr" | awk -F':' '{print $NF}')
    PROC=$(echo "$pidinfo" | sed 's/pid=\([0-9]*\),.*$/\1/' | xargs -I{} ps -p {} -o comm= 2>/dev/null)

    # If port is in open ports, print it
    if echo "$OPEN_PORTS" | grep -qw "$PORT"; then
        printf "Port: %-6s | Protocol: %-4s | Service: %s\n" "$PORT" "$proto" "${PROC:-Unknown}"
    fi
done <<< "$LISTENING"
