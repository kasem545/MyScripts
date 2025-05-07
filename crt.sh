#!/bin/bash

usage() {
    echo "Usage: $0 -d DOMAIN [-o OUTPUT_FILE] [-f FORMAT]"
    echo "  -d DOMAIN        The domain to query (e.g., example.com)"
    echo "  -o OUTPUT_FILE   Save output to a file (optional)"
    echo "  -f FORMAT        Output format: text (default) or json"
    echo "  -h               Display this help message"
}

OUTPUT_FILE=""
FORMAT="text"

while getopts "d:o:f:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        f) FORMAT="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    echo "Error: Domain is required"
    usage
    exit 1
fi

echo "[*] Fetching subdomains for: $DOMAIN"
RESULT=$(curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | jq -r '.[].name_value' | sort -u)

if [ -z "$RESULT" ]; then
    echo "[!] No results found for $DOMAIN"
    exit 1
fi

if [ "$FORMAT" == "json" ]; then
    JSON_RESULT=$(echo "$RESULT" | jq -R -s -c 'split("\n")[:-1]')
    OUTPUT="$JSON_RESULT"
else
    OUTPUT="$RESULT"
fi

if [ "$FORMAT" == "json" ]; then
    echo "$OUTPUT" | jq
else
    echo "$OUTPUT"
fi

if [ -n "$OUTPUT_FILE" ]; then
    if [ "$FORMAT" == "json" ]; then
        if [ -s "$OUTPUT_FILE" ]; then
            sed -i '$ s/,$//' "$OUTPUT_FILE"
            sed -i '$ s/]$//' "$OUTPUT_FILE"
            echo "," >> "$OUTPUT_FILE"
        else
            echo "[" > "$OUTPUT_FILE"
        fi
        echo "$OUTPUT" | jq -c '.' >> "$OUTPUT_FILE"
        echo "]" >> "$OUTPUT_FILE"
    else
        echo "$OUTPUT" >> "$OUTPUT_FILE"
    fi
    echo "[*] Results appended to: $OUTPUT_FILE"
fi
