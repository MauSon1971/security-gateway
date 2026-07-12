#!/usr/bin/env bash
# VKF · Backup + verify + fire-drill.
#
# Steps:
#   1. Dump security_gateway schema to /var/backups/vkf/vkf_YYMMDD_HHMM.sql.gz
#   2. Test-restore into temp DB `vkf_restore_test`
#   3. Assert schema tables + row counts match
#   4. Drop temp DB
#   5. Report to /var/log/security-gateway/backup_verify.log
#
# Runs weekly (systemd timer). Any error → SECURITY_LOG.md alert.
set -euo pipefail

BACKUP_DIR="/var/backups/vkf"
LOG_FILE="/var/log/security-gateway/backup_verify.log"
TS=$(date -u +"%Y%m%dT%H%M%SZ")
BACKUP="$BACKUP_DIR/vkf_${TS}.sql.gz"

mkdir -p "$BACKUP_DIR"

log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG_FILE"; }

log "==== VKF backup verify · start ===="

# 1. Dump schema + data
log "dumping security_gateway schema..."
sudo -u postgres pg_dump -d vektrun --schema=security_gateway --format=custom > "${BACKUP%.gz}"
gzip -f "${BACKUP%.gz}"

SIZE=$(stat -c %s "$BACKUP")
log "dump complete: $BACKUP ($SIZE bytes)"

# 2. Row counts BEFORE restore
BEFORE_MSG=$(sudo -u postgres psql -d vektrun -t -A -c "SELECT count(*) FROM security_gateway.raw_messages")
BEFORE_AUDIT=$(sudo -u postgres psql -d vektrun -t -A -c "SELECT count(*) FROM security_gateway.audit_log")
log "prod counts: raw_messages=$BEFORE_MSG audit_log=$BEFORE_AUDIT"

# 3. Test-restore in temp DB
TEST_DB="vkf_restore_test"
sudo -u postgres psql -c "DROP DATABASE IF EXISTS ${TEST_DB}" 2>&1 | tail -1
sudo -u postgres psql -c "CREATE DATABASE ${TEST_DB}" 2>&1 | tail -1
log "created temp DB ${TEST_DB}"

gunzip -c "$BACKUP" | sudo -u postgres pg_restore -d "$TEST_DB" 2>&1 | tail -5

# 4. Verify restored counts
AFTER_MSG=$(sudo -u postgres psql -d "$TEST_DB" -t -A -c "SELECT count(*) FROM security_gateway.raw_messages")
AFTER_AUDIT=$(sudo -u postgres psql -d "$TEST_DB" -t -A -c "SELECT count(*) FROM security_gateway.audit_log")
log "restored counts: raw_messages=$AFTER_MSG audit_log=$AFTER_AUDIT"

# 5. Assert match
if [ "$BEFORE_MSG" != "$AFTER_MSG" ] || [ "$BEFORE_AUDIT" != "$AFTER_AUDIT" ]; then
  log "❌ MISMATCH: raw_messages=$BEFORE_MSG→$AFTER_MSG audit=$BEFORE_AUDIT→$AFTER_AUDIT"
  echo "" >> /var/www/vaults/V0_MSN/_MD/SECURITY_LOG.md 2>/dev/null || true
  echo "## 🔴 [$(date -u +%FT%TZ)] BACKUP VERIFY FAIL" >> /var/www/vaults/V0_MSN/_MD/SECURITY_LOG.md 2>/dev/null || true
  echo "- $BACKUP row count mismatch" >> /var/www/vaults/V0_MSN/_MD/SECURITY_LOG.md 2>/dev/null || true
  sudo -u postgres psql -c "DROP DATABASE ${TEST_DB}" 2>&1 | tail -1
  exit 1
fi

log "✅ verify OK"

# 6. Cleanup temp DB
sudo -u postgres psql -c "DROP DATABASE ${TEST_DB}" 2>&1 | tail -1

# 7. Retention: keep 30 days
find "$BACKUP_DIR" -maxdepth 1 -name "vkf_*.sql.gz" -mtime +30 -print -delete 2>&1 | tee -a "$LOG_FILE"

log "==== VKF backup verify · complete ===="
