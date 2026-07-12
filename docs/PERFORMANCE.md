# VKF · Performance Baseline

Locust load test result — v0.3.0, VPS single node (Ryzen local dev).

## Reproduce

```bash
cd /var/www/security-gateway
sudo -u securitus venv/bin/locust -f perf/locustfile.py \
    --host http://127.0.0.1:8850 \
    --users 10 --spawn-rate 3 --run-time 30s --headless --only-summary
```

## Baseline (10 concurrent users, 30s)

Total requests: **920** (≈30 req/s aggregate — capped by rate limiter).

### Latency percentiles (successful requests, ms)

| Endpoint | p50 | p95 | p99 | max |
|---|---|---|---|---|
| POST /gateway/scan-text (benign) | 6 | 11 | 17 | 37 |
| POST /gateway/scan-text (injection) | 6 | 10 | 13 | 15 |
| GET /health | 3 | 7 | 7 | 12 |

Injection path (Capa 0 heuristic prescan) is as fast as benign because it short-circuits before the ML classifier.

### Rate limiting

88% of requests get **429 Too Many Requests** at this concurrency level. This is intentional — slowapi is configured at `10 req/s per IP`. When performing capacity planning:

- Disable rate limit temporarily (`SG_RATE_LIMIT_DISABLED=1`) to measure raw throughput.
- Or bump `SG_RATE_LIMIT_TEXT_PER_SEC` to your target and re-baseline.

## Interpreting

- **Latency SLA proposal**: p95 ≤ 50 ms for /scan-text, p99 ≤ 100 ms. Current headroom is 5×.
- **Throughput SLA proposal**: 500 req/s sustained per gateway node under Ryzen 9 9950X-class CPU.
- Real bottleneck under high concurrency is the DeBERTa-v3 classifier (~150ms on CPU for non-prescan hits). LlamaGuard 3-1B fallback is CPU-friendly (~200ms). LlamaGuard 3-8B on GPU (post-MS-A2) drops to <40ms.

## Roadmap

- Post-MS-A2: repeat baseline under GPU inference. Expect 3-5× throughput.
- Multi-node: measure with 2× gateway pods behind Traefik.
- Chaos: kill classifier mid-run, verify fallback to Capa 0 heuristic + 5xx-free response.
