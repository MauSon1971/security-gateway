#!/usr/bin/env bash
# Vektrun Security Gateway · Plug-and-play installer
#
# Usage:  sudo bash install.sh
#
# Auto-configures:
#   - System user `securitus` (system, no shell)
#   - Python venv + deps
#   - HMAC key (auto-generated 32 bytes)
#   - Postgres schema `security_gateway` (uses local socket, peer auth)
#   - AGE keypair for at-rest encryption (optional module)
#   - systemd unit + timer for gateway + admission worker + report + parser + TTL + canary
#
# Zero manual configuration required.

set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/var/www/security-gateway}"
DATA_DIR="/var/lib/security-gateway"
LOG_DIR="/var/log/security-gateway"
ETC_DIR="/etc/security-gateway"
USER_NAME="securitus"
DB_NAME="${SG_DB_NAME:-vektrun}"
DB_USER="${SG_DB_USER:-vektrun_user}"

log() { echo "[install $(date -u +%FT%TZ)] $*"; }

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "MISSING: $1 — installing..."
    apt-get install -y "$2"
  fi
}

log "==== 1. Prerequisites ===="
apt-get update -qq
require python3 python3
require python3-venv python3-venv
require pg_config postgresql-server-dev-all
require clamdscan clamav-daemon
require openssl openssl
require age age
if [ ! -f /usr/local/bin/sops ]; then
  log "Installing sops..."
  wget -q -O /usr/local/bin/sops https://github.com/getsops/sops/releases/latest/download/sops-v3.10.2.linux.amd64
  chmod +x /usr/local/bin/sops
fi

log "==== 2. System user ===="
if ! id "$USER_NAME" &>/dev/null; then
  useradd -r -s /usr/sbin/nologin "$USER_NAME"
  log "created user: $USER_NAME"
else
  log "user exists: $USER_NAME"
fi

log "==== 3. Directories ===="
mkdir -p "$INSTALL_ROOT" "$DATA_DIR/models" "$DATA_DIR/hf_home" "$LOG_DIR" "$ETC_DIR"
chown -R "$USER_NAME:$USER_NAME" "$DATA_DIR" "$LOG_DIR"
chmod 700 "$ETC_DIR"

log "==== 4. HMAC key ===="
if [ ! -f "$ETC_DIR/hmac.key" ]; then
  openssl rand -hex 32 > "$ETC_DIR/hmac.key"
  chmod 600 "$ETC_DIR/hmac.key"
  chown "$USER_NAME:$USER_NAME" "$ETC_DIR/hmac.key"
  log "generated HMAC key"
else
  log "HMAC key exists — reusing"
fi

log "==== 5. .env (defaults, no user input needed) ===="
if [ ! -f "$ETC_DIR/.env" ]; then
  cat > "$ETC_DIR/.env" <<ENV_EOF
# Auto-generated defaults. Edit only if you need a different model / DSN.
SG_PROMPT_GUARD_MODEL=protectai/deberta-v3-base-prompt-injection-v2
HF_HOME=$DATA_DIR/hf_home
SG_DB_DSN=host=/var/run/postgresql dbname=$DB_NAME user=$DB_USER
SG_GATEWAY_URL=http://127.0.0.1:8850
SG_LLAMAGUARD_MODEL=llama-guard3:1b
OLLAMA_URL=http://127.0.0.1:11434
ENV_EOF
  chmod 600 "$ETC_DIR/.env"
  chown "$USER_NAME:$USER_NAME" "$ETC_DIR/.env"
  log ".env created with defaults"
fi

log "==== 6. Python venv + deps ===="
if [ ! -d "$INSTALL_ROOT/venv" ]; then
  python3 -m venv "$INSTALL_ROOT/venv"
fi
"$INSTALL_ROOT/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_ROOT/venv/bin/pip" install --quiet \
    fastapi uvicorn transformers pydantic \
    "torch --index-url https://download.pytorch.org/whl/cpu" \
    requests psycopg2-binary slowapi pytest httpx \
    2>&1 | tail -3
chown -R "$USER_NAME:$USER_NAME" "$INSTALL_ROOT/venv"

log "==== 7. Postgres schema (idempotent) ===="
if [ -f "$INSTALL_ROOT/db/001_init.sql" ]; then
  sudo -u postgres psql -d "$DB_NAME" -f "$INSTALL_ROOT/db/001_init.sql" 2>&1 | grep -v NOTICE | tail -5
  # Peer auth mapping for the securitus user → vektrun_user
  PG_VER=$(ls /etc/postgresql/ | head -1)
  if ! grep -q "^sg_map" "/etc/postgresql/$PG_VER/main/pg_ident.conf" 2>/dev/null; then
    echo "sg_map    $USER_NAME    $DB_USER" >> "/etc/postgresql/$PG_VER/main/pg_ident.conf"
  fi
  if ! grep -q "map=sg_map" "/etc/postgresql/$PG_VER/main/pg_hba.conf"; then
    sed -i "/^local   all             all                                     peer/i\\local   $DB_NAME         $DB_USER                            peer map=sg_map" "/etc/postgresql/$PG_VER/main/pg_hba.conf"
  fi
  systemctl reload postgresql
  log "postgres schema + peer auth configured"
fi

log "==== 8. systemd units ===="
if [ -d "$INSTALL_ROOT/systemd" ]; then
  cp "$INSTALL_ROOT/systemd"/*.service "$INSTALL_ROOT/systemd"/*.timer /etc/systemd/system/ 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable --now security-gateway.service 2>&1 | tail -2
  for t in admission_worker admission_report admission_ttl admission_parser sg_wally_adapter canary_test; do
    systemctl enable --now "${t}.timer" 2>/dev/null || log "timer ${t}: not present (skip)"
  done
fi

log "==== 9. ClamAV daemon ===="
systemctl enable --now clamav-daemon clamav-freshclam 2>&1 | tail -1

log "==== 10. Ollama (optional, for LlamaGuard) ===="
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh 2>&1 | tail -1
  systemctl enable --now ollama
  sleep 3
  # Pull default guard model in background (~1.6GB)
  nohup ollama pull llama-guard3:1b >/dev/null 2>&1 &
  log "ollama installed, pulling llama-guard3:1b in background"
fi

log "==== 11. AGE keypair for at-rest encryption (optional) ===="
if [ -f "$INSTALL_ROOT/scripts/confidential_bootstrap.sh" ]; then
  bash "$INSTALL_ROOT/scripts/confidential_bootstrap.sh" 2>&1 | tail -3
fi

log "==== 12. Verify ===="
sleep 5
if curl -s -m 5 http://127.0.0.1:8850/health | grep -q "\"status\""; then
  log "✅ Gateway responding at http://127.0.0.1:8850"
  curl -s http://127.0.0.1:8850/health
else
  log "⚠️  Gateway not responding yet. Check: journalctl -u security-gateway"
fi

echo
echo "════════════════════════════════════════════════════════════════"
echo "  Vektrun Security Gateway installed."
echo "  Endpoint: http://127.0.0.1:8850  (internal only)"
echo "  Health:   curl -s http://127.0.0.1:8850/health | jq"
echo "  Logs:     journalctl -u security-gateway -f"
echo "════════════════════════════════════════════════════════════════"
