#!/usr/bin/env bash
# scripts/setup_secrets.sh
# OWASP Section 6: Secrets stored with filesystem permissions, never in plain .env
#
# Usage:
#   chmod +x scripts/setup_secrets.sh
#   ./scripts/setup_secrets.sh

set -euo pipefail

SECRETS_FILE=".env.secrets"

if [ -f "$SECRETS_FILE" ]; then
    echo "  $SECRETS_FILE already exists. Remove it first if you want to reset."
    exit 0
fi

echo "Setting up secrets file..."
read -rsp "Enter your OpenAI API key: " OPENAI_KEY
echo

# Write key to secrets file
printf "%s" "$OPENAI_KEY" > "$SECRETS_FILE"

# OWASP Section 6: Restrict permissions — owner read/write only
chmod 600 "$SECRETS_FILE"

echo "  Created $SECRETS_FILE with permissions 600"
echo "  Do not commit this file to version control."
echo ""
echo "  To use without Docker, load it with:"
echo "    export OPENAI_API_KEY=\$(cat $SECRETS_FILE)"
echo ""
echo "  To use with Docker Compose:"
echo "    docker-compose up"
