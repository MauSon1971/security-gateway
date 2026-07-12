#!/usr/bin/env bash
# Security Gateway · HMAC key rotation with 24h grace window.
#
# Old key is preserved as `hmac.key.old` during the grace window so consumers
# with cached seals can still verify. After 24h the old key must be removed.
#
# Usage:
#   sudo bash /var/www/security-gateway/scripts/rotate_hmac_key.sh
#
# Steps:
#   1. Backup current key → hmac.key.old_<ts>
#   2. Generate new key (32 bytes hex, openssl)
#   3. Write new key → hmac.key (chmod 600, owner securitus)
#   4. Restart security-gateway to pick up the new key
#   5. Log to /var/log/security-gateway/hmac_rotation.log
#
# Consumers use `sg_client.verify_seal()` which will try current key first,
# then any `.old_*` keys within 24h if `SG_HMAC_KEY_DIR` is exported.

set -euo pipefail

KEY_DIR="${SG_HMAC_KEY_DIR:-/etc/security-gateway}"
KEY_FILE="${KEY_DIR}/hmac.key"
LOG_FILE="/var/log/security-gateway/hmac_rotation.log"
TS=$(date -u +"%Y%m%dT%H%M%SZ")

mkdir -p "$(dirname "$LOG_FILE")"

log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG_FILE"; }

if [ ! -f "$KEY_FILE" ]; then
  log "ERROR: current key not found at $KEY_FILE — bootstrap first"
  exit 1
fi

# Step 1: backup
BAK="${KEY_FILE}.old_${TS}"
cp "$KEY_FILE" "$BAK"
chmod 600 "$BAK"
chown securitus:securitus "$BAK"
log "backup created: $BAK"

# Step 2: generate
NEW_HEX=$(openssl rand -hex 32)
if [ ${#NEW_HEX} -ne 64 ]; then
  log "ERROR: openssl generated key of unexpected length ${#NEW_HEX}"
  exit 1
fi

# Step 3: write atomically
TMP=$(mktemp)
printf '%s' "$NEW_HEX" > "$TMP"
chmod 600 "$TMP"
chown securitus:securitus "$TMP"
mv -f "$TMP" "$KEY_FILE"
log "new key installed at $KEY_FILE"

# Step 4: restart gateway
systemctl restart security-gateway
sleep 5
if systemctl is-active --quiet security-gateway; then
  log "gateway restarted OK"
else
  log "ERROR: gateway failed to restart — rolling back"
  mv -f "$BAK" "$KEY_FILE"
  systemctl restart security-gateway
  exit 1
fi

# Step 5: prune old backups older than 30 days (grace window is 24h,
# but we keep a month for forensics)
find "$KEY_DIR" -maxdepth 1 -name "hmac.key.old_*" -mtime +30 -print -delete 2>&1 | tee -a "$LOG_FILE"

log "rotation complete"
echo
echo "Rotation done. Grace window: 24h (consumers with cached seals should still verify)."
echo "After 24h, seals signed with the old key will be rejected."
echo "Old key preserved at: $BAK"
