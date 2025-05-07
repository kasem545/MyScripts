#!/bin/bash

# krbgen.sh - Generate a basic krb5.conf file

# Usage: ./krbgen.sh <REALM> <DOMAIN> <KDC_IP> [OUTPUT_PATH]
# Example: ./krbgen.sh EXAMPLE.HTB example.htb 10.10.10.10 /tmp/krb5.conf
#          export KRB5_CONFIG=/tmp/krb5.conf

if [ "$1" == "--example" ]; then
    echo "Example:"
    echo "./krbgen.sh EXAMPLE.HTB example.htb 10.10.10.10 /tmp/krb5.conf"
    echo "export KRB5_CONFIG=/tmp/krb5.conf"
    exit 0
fi

# Validate input
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <REALM> <DOMAIN> <KDC_IP> [OUTPUT_PATH]"
    echo "Try '$0 --example' for an example."
    exit 1
fi

REALM=$(echo "$1" | tr '[:lower:]' '[:upper:]')
DOMAIN=$2
KDC_IP=$3
OUTPUT_PATH=${4:-/etc/krb5.conf}

if ! [[ $KDC_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "[-] Invalid IP address format: $KDC_IP"
    exit 3
fi

if [ -f "$OUTPUT_PATH" ]; then
    cp "$OUTPUT_PATH" "${OUTPUT_PATH}.bak"
    echo "[*] Backup of existing config saved as ${OUTPUT_PATH}.bak"
fi

cat <<EOF > "$OUTPUT_PATH"
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    rdns = false

[realms]
    $REALM = {
        kdc = $KDC_IP
        admin_server = $KDC_IP
    }

[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
EOF

if [ $? -eq 0 ]; then
    chmod 644 "$OUTPUT_PATH"
    echo "[+] krb5.conf successfully written to $OUTPUT_PATH"
else
    echo "[-] Failed to write krb5.conf"
    exit 2
fi
