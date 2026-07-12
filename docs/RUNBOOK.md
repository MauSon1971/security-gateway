# VKF Guard · Operational Runbook

Runbook for on-call operators of the Vektrun Forge Security Gateway.
Written for a human 3 AM oncall responder — not for the original engineer.

## Contact points

- **SuperAdmin**: Mauri (Telegram, out of band)
- **Auto-notify channel**: `_report_Mau/` (batch) + `SECURITY_LOG.md` (append-only)
- **Repo**: `MauSon1971/security-gateway` (GitHub)

## Fast checklist

- Gateway alive: `curl -s http://127.0.0.1:8850/health | jq .status`
- Timers active: `systemctl list-timers | grep -E 'admission_|bypass|canary|dlq'`
- Prometheus target: `curl -s 'http://127.0.0.1:9090/api/v1/query?query=up{job=%22vkf-gateway%22}' | jq '.data.result[].value[1]'`
- Grafana: http://127.0.0.1:3050 (VKF folder)
- Jaeger: http://127.0.0.1:16686 (service `vkf-guard`)
- Postgres: `sudo -u postgres psql -d vektrun -c "SELECT COUNT(*) FROM security_gateway.raw_messages"`

---

## Incident: Gateway down

**Symptom**: 5xx or timeout on `/health`.

1. Check systemd: `sudo systemctl status security-gateway`
2. Last 100 log lines: `sudo journalctl -u security-gateway -n 100 --no-pager`
3. Common causes:
   - **Postgres unreachable** → check `sudo systemctl status postgresql`
   - **ClamAV socket missing** → `sudo systemctl status clamav-daemon`
   - **HuggingFace model missing** → check `~securitus/.cache/huggingface/` size
4. Restart: `sudo systemctl restart security-gateway`
5. If persists: rollback last commit — `cd /var/www/security-gateway && git log --oneline -5 && git revert <sha>`

---

## Incident: HMAC seal breach suspected

**Symptom**: SECURITY_LOG.md shows `hmac_verify_failed` bursts.

1. Rotate immediately:
   ```bash
   bash ~/.claude/scripts/rotate.sh SG_HMAC_KEY /etc/security-gateway/.env
   sudo systemctl restart security-gateway
   ```
2. Old sealed messages within 24h TTL will fail verification (expected).
3. Re-scan latest COMMS_Hub uningested rows: `POST /admission/reprocess?id=<id>&decision=admit`
4. Audit `security_gateway.audit_log` for the affected window.

---

## Incident: DB restore from backup

Backups are pg_dumps taken weekly Sunday 04:00 Madrid, gzipped to `/var/backups/vkf/`.

```bash
# 1. Stop gateway (avoid writes during restore)
sudo systemctl stop security-gateway

# 2. Restore into a fresh DB
sudo -u postgres createdb vektrun_restore
gunzip -c /var/backups/vkf/vektrun-YYYY-MM-DD.sql.gz | sudo -u postgres psql -d vektrun_restore

# 3. Verify row counts match audit trail
sudo -u postgres psql -d vektrun_restore -c "SELECT COUNT(*) FROM security_gateway.raw_messages"

# 4. Rename to promote (destructive — triple-confirm with Mauri)
# → follow TRIPLE CONFIRMACIÓN P0 protocol

# 5. Restart gateway
sudo systemctl start security-gateway
```

Fire drill runs weekly via `backup_verify.timer` — restore into temp DB, assert count, drop. Any failure → SECURITY_LOG.md.

---

## Incident: ClamAV down

**Symptom**: `/gateway/scan-attachment` returns 503 or `malware_scan_pass=null`.

1. `sudo systemctl restart clamav-daemon`
2. If freshclam is stuck: `sudo systemctl restart clamav-freshclam`
3. Verify: `echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | clamdscan -`
4. If DB corruption: `sudo rm /var/lib/clamav/main.cvd && sudo systemctl restart clamav-freshclam`

---

## Incident: LlamaGuard 3-1B unreachable (Capa 3.5)

**Symptom**: Ollama container down or slow. Fallback: Capa 3 (protectai) still runs.

1. `docker ps | grep ollama` — must be Running
2. `curl -sf http://127.0.0.1:11434/api/tags` — model listed
3. `docker restart ollama` if stuck
4. Pull model if missing: `docker exec ollama ollama pull llama-guard3:1b`
5. Log: `sudo journalctl -u docker | grep ollama | tail -30`

Gateway continues to serve with Capa 0/3/4 while Capa 3.5 is down — recorded in `SECURITY_LOG.md`.

---

## Incident: DLQ retry exploded

**Symptom**: `agent_dlq` growing without draining.

1. Count: `sudo -u postgres psql -d vektrun -c "SELECT agent, COUNT(*) FROM vkf_ledger.agent_dlq WHERE resolved_at IS NULL GROUP BY 1"`
2. Check worker timer: `systemctl status vkf-dlq-retry.timer`
3. Recent failures: `sudo journalctl -u vkf-dlq-retry.service -n 50 --no-pager`
4. If a specific agent is dead-letter looping, freeze it manually:
   ```sql
   UPDATE vkf_ledger.agent_dlq SET retry_count = max_retries WHERE agent = 'X' AND resolved_at IS NULL;
   ```
   Then investigate that agent's health.

---

## Incident: Credential rotation emergency

If any key in `/etc/security-gateway/.env` is suspected leaked:

1. `bash ~/.claude/scripts/rotate.sh <VAR_NAME> /etc/security-gateway/.env`
2. `sudo systemctl restart security-gateway`
3. API smoke test: `curl -X POST http://127.0.0.1:8850/gateway/scan-text -H 'Content-Type: application/json' -d '{"text":"ping","source_id":"post-rotate"}'`
4. Log the rotation in `SECURITY_LOG.md` (auto by rotate.sh).

Prohibited: editing `.env` with nano/vim/sed. Prohibited: any secret on command line.

---

## Incident: CI pipeline failing (GitHub Actions security workflow)

- Trivy fs → check `security-events` tab in GitHub
- pip-audit → new CVE in transitive dep; run `pip-audit -r requirements.txt` locally
- Bandit → new code triggered a Python security lint rule
- SBOM (CycloneDX) → dependency graph change

Do NOT bypass with `--no-verify` or skip CI. Fix the root cause.

---

## Incident: Bypass detection alert fired

**Symptom**: `bypass_alert.timer` reported >5 attempts/hour from one source in `SECURITY_LOG.md`.

1. `SELECT source_id, COUNT(*) FROM security_gateway.blocked_attempts WHERE ts > NOW() - INTERVAL '1 hour' GROUP BY 1 ORDER BY 2 DESC;`
2. If clearly malicious sender → add to admission blocklist or block at Traefik.
3. If false-positive volume from a legit sender → tune Capa 0 heuristic thresholds.

---

## Common commands

```bash
# All active timers for VKF
systemctl list-timers | grep -E 'admission_|bypass|canary|dlq|backup_verify'

# Live tail gateway
sudo journalctl -u security-gateway -f

# Check tenant count
sudo -u postgres psql -d vektrun -c "SELECT COUNT(*) FROM security_gateway.tenants"

# Prometheus reload
curl -sf -X POST http://127.0.0.1:9090/-/reload

# Grafana admin password location
ls -l /var/www/vkf-observability/grafana/.env

# Keycloak admin login
# URL: http://127.0.0.1:8180/admin
# Credentials in /var/www/vkf-keycloak/.env
```

---

## SLA references

- Availability target: 99.5% (max ~3.6h downtime/month)
- Latency SLA: p95 ≤ 50 ms scan-text, p99 ≤ 100 ms
- Recovery Time Objective (RTO): 1 hour
- Recovery Point Objective (RPO): 24 hours (daily pg_dump)
