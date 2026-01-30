#!/bin/bash

SAFE_IP_FILE="/etc/safe_ips.txt"
SURICATA_DROP_RULES="/etc/suricata/rules/drop-ips.rules"
SURICATA_RULE_TEMPLATE="drop ip %s any -> any any (msg:\"Unauthorized IP login attempt\"; sid:%s; rev:1;)"
LOG_FILE="/var/log/unauthorized_logins.log"

# Ensure the rule file exists
touch "$SURICATA_DROP_RULES"

# Fetch active IPs from `who`
ACTIVE_IPS=$(who | awk '{print $5}' | tr -d '()')

for ip in $ACTIVE_IPS; do
    if ! grep -q "$ip" "$SAFE_IP_FILE"; then
        echo "Unauthorized login detected from $ip"

        # Generate unique SID using epoch timestamp
        SID=$(date +%s%N | cut -c1-10)

        # Create rule
        RULE=$(printf "$SURICATA_RULE_TEMPLATE" "$ip" "$SID")

        # Add rule if not already present
        if ! grep -q "$ip" "$SURICATA_DROP_RULES"; then
            echo "$RULE" >> "$SURICATA_DROP_RULES"
            echo "[+] Rule added to Suricata to drop $ip"
        fi

        # Reload Suricata rules (adjust command as needed)
        suricatasc -c reload-rules

        # Kill sessions from the IP (optional and aggressive)
        pkill -KILL -f "$ip"

        # Log the incident
        echo "$(date): Blocked unauthorized IP $ip, SID $SID" >> "$LOG_FILE"
    fi
done
