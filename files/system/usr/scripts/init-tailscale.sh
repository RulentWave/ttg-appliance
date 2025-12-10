#!/usr/sbin/sh
set -euo pipefail
SECRETS_FILE="/etc/secrets"

if [ -f "$SECRETS_FILE" ]; then
    source "$SECRETS_FILE"
else
    echo "Error: Secrets file not found at $SECRETS_FILE"
    exit 1
fi

/usr/sbin/tailscale up --auth-key="$TAILSCALE_KEY"
