#!/usr/bin/env bash

# Stop on error, stop on unset variables, stop if a pipe fails
set -euo pipefail

SECRETS_FILE="/etc/secrets"

if [ -f "$SECRETS_FILE" ]; then
    source "$SECRETS_FILE"
else
    echo "Error: Secrets file not found at $SECRETS_FILE"
    exit 1
fi

# Ensure required vars are set
if [[ -z "${TENANT_ID:-}" ]] || [[ -z "${CLIENT_ID:-}" ]] || [[ -z "${CLIENT_SECRET:-}" ]] || [[ -z "${SMBPASSWORD:-}" ]]; then
    echo "Error: One or more required environment variables are missing."
    exit 1
fi

BASE_DIR="/srv/share"
mkdir -p "$BASE_DIR"

echo "Retrieving access token..."
# Step 1: Get an app-only access token
TOKEN_RESPONSE=$(curl -s -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "grant_type=client_credentials")

TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to retrieve access token. Response:"
  echo "$TOKEN_RESPONSE"
  exit 1
fi

# URL-encoded filter: userType eq 'Member' and accountEnabled eq true
ENCODED_FILTER="%24filter=userType%20eq%20'Member'%20and%20accountEnabled%20eq%20true"
NEXT_URL="https://graph.microsoft.com/v1.0/users?$ENCODED_FILTER"
AUTH_HEADER="Authorization: Bearer $TOKEN"

echo "Processing users..."

# Step 2: Retrieve filtered users
while [ -n "$NEXT_URL" ]; do
  RESPONSE=$(curl -s -H "$AUTH_HEADER" "$NEXT_URL")
  
  # Check for API errors
  if echo "$RESPONSE" | jq -e '.error' > /dev/null; then
    echo "Error retrieving users from Graph API:"
    echo "$RESPONSE" | jq '.error'
    exit 1
  fi

  # Process the current page of users
  # We use a file descriptor redirection (<<<) or standard read loop to avoid subshell issues
  # but here we iterate over the JSON array directly
  
  # Decode user list into a bash array of base64 strings to handle spaces safely during iteration
  # (Requires jq installed)
  for USER_JSON in $(echo "$RESPONSE" | jq -r '.value[] | @base64'); do
    
    _decoded_user=$(echo "$USER_JSON" | base64 --decode)
    DISPLAY_NAME=$(echo "$_decoded_user" | jq -r '.displayName')
    UPN=$(echo "$_decoded_user" | jq -r '.userPrincipalName')

    # Sanitize: Replace spaces/special chars with underscores to prevent collisions
    # This turns "John Doe" into "John_Doe" instead of "JohnDoe"
    SAFE_FOLDER_NAME=$(echo "$DISPLAY_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g')

    # Fallback if empty
    if [ -z "$SAFE_FOLDER_NAME" ] || [ "$SAFE_FOLDER_NAME" = "_" ]; then
      SAFE_FOLDER_NAME=$(echo "$UPN" | sed 's/[^a-zA-Z0-9._-]/_/g')
    fi

    USER_DIR="$BASE_DIR/$SAFE_FOLDER_NAME"

    if [ ! -d "$USER_DIR" ]; then
      mkdir -p "$USER_DIR"
      echo "Created: $USER_DIR"
    else
      # Optional: Don't spam logs on every run
      : # No-op
    fi
  done

  NEXT_URL=$(echo "$RESPONSE" | jq -r '."@odata.nextLink" // empty')
done

echo "All member + enabled user folders processed."

echo "Setting up permissions..."
# Use || true to prevent script exit if SELinux is disabled/missing
chcon -R -t samba_share_t "$BASE_DIR" || echo "Warning: chcon failed (SELinux disabled?)"
chown -R scans:scans "$BASE_DIR"

echo "Configuring Samba user 'scans'..."

# Check if user exists in pdbedit to determine if we add (-a) or update
if pdbedit -L scans > /dev/null 2>&1; then
    echo "User 'scans' exists. Updating hash."
    # Use smbpasswd or pdbedit without -a to update? 
    # pdbedit doesn't have a clean 'update' flag for hashes without -a in some versions.
    # It is often easier to delete and re-add to ensure the hash is set exactly as requested.
    pdbedit -x -u scans
fi

echo "Adding user 'scans' with provided hash..."
pdbedit -a -u scans --set-nt-hash="$SMBPASSWORD"

echo "Done."
