# Ch3ck3r — API Security Scanner Command Reference

## Quick Start

```bash
# Backend
cd backend
cp .env.example .env          # Edit .env with your settings
pip install -r requirements.txt  # or: poetry install
alembic upgrade head            # Run database migrations
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev                     # http://localhost:3000

# Background worker (separate terminal)
cd backend
celery -A app.tasks worker -l info
```

---

## 📡 API Commands (curl / httpx)

### Authentication

```bash
# Register a new user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"StrongPass1!","full_name":"Admin User"}'

# Login (save token)
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"StrongPass1!"}' | \
  python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

echo "Token: $TOKEN"
```

### Projects

```bash
# Create a project
curl -X POST http://localhost:8000/api/v1/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My API","description":"Production API security test","repository_url":"https://github.com/user/repo"}'

# List projects
curl http://localhost:8000/api/v1/projects \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Scans

```bash
# Create a single scanner scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"project_id":"<PROJECT_UUID>","scan_type":"openapi","target":"https://example.com/api/openapi.json"}'

# Run a full multi-scanner scan (all 4 scanners)
curl -X POST http://localhost:8000/api/v1/scans/full-scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com/api","project_id":"<PROJECT_UUID>"}'

# List scans
curl http://localhost:8000/api/v1/scans?limit=10 \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Get scan detail
curl http://localhost:8000/api/v1/scans/<SCAN_UUID> \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Execute a pending scan
curl -X POST http://localhost:8000/api/v1/scans/<SCAN_UUID>/execute \
  -H "Authorization: Bearer $TOKEN"

# List available scanners
curl http://localhost:8000/api/v1/scans/scanners \
  -H "Authorization: Bearer $TOKEN"
```

### Findings

```bash
# Get findings for a scan
curl "http://localhost:8000/api/v1/findings?scan_id=<SCAN_UUID>" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Filter by severity
curl "http://localhost:8000/api/v1/findings?scan_id=<SCAN_UUID>&severity=critical" \
  -H "Authorization: Bearer $TOKEN"
```

### Reports

```bash
# Generate a report
curl -X POST http://localhost:8000/api/v1/reports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scan_id":"<SCAN_UUID>","format":"json"}'

# List reports
curl http://localhost:8000/api/v1/reports \
  -H "Authorization: Bearer $TOKEN"
```

### Scan Chains (Phase 6)

```bash
# List available scan chains
curl http://localhost:8000/api/v1/scans/chains \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Run a full assessment chain
curl -X POST "http://localhost:8000/api/v1/scans/chains/full_assessment/run?target=https://example.com/api&project_id=<PROJECT_UUID>" \
  -H "Authorization: Bearer $TOKEN"

# Quick check (OpenAPI + Nuclei CVE)
curl -X POST "http://localhost:8000/api/v1/scans/chains/quick_check/run?target=https://example.com/api&project_id=<PROJECT_UUID>" \
  -H "Authorization: Bearer $TOKEN"

# Deep dive (ZAP active + Semgrep SAST)
curl -X POST "http://localhost:8000/api/v1/scans/chains/deep_dive/run?target=https://example.com&project_id=<PROJECT_UUID>" \
  -H "Authorization: Bearer $TOKEN"
```

### Scan Diffing (Phase 6)

```bash
# Compare two scans
curl "http://localhost:8000/api/v1/scans/diff/<SCAN_ID_A>/<SCAN_ID_B>" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Compare latest two scans of same type in a project
curl "http://localhost:8000/api/v1/scans/diff/latest/<PROJECT_UUID>/openapi" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## 🔌 WebSocket Live Scan Progress

```bash
# Connect to live scan progress (requires wscat)
# npm install -g wscat
wscat -c "ws://localhost:8000/ws/scans/<SCAN_UUID>?token=$TOKEN"

# You'll receive JSON events like:
# {"type":"connected","message":"Connected to scan stream"}
# {"type":"scan_started","scan_id":"...","status":"running"}
# {"type":"finding","finding":{"title":"...","severity":"critical",...}}
# {"type":"scan_completed","scan_id":"...","status":"completed","risk_score":7.5}
# {"type":"scan_failed","scan_id":"...","status":"failed","message":"..."}
```

---

## 📊 GraphQL API

```bash
# Query scan statistics
curl -X POST http://localhost:8000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ scanStats { totalScans criticalFindings highFindings averageRiskScore } }"}'

# List projects with scans
curl -X POST http://localhost:8000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ projects { id name description scans { id scanType status riskScore totalFindings } } }"}'

# Get findings with pagination
curl -X POST http://localhost:8000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ findings(limit: 10, offset: 0, severity: \"critical\") { id title severity category endpoint remediation } }"}'

# Create a scan via mutation
curl -X POST http://localhost:8000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { createScan(projectId: \"<UUID>\", scanType: \"openapi\", target: \"https://example.com/api\") { id scanType status riskScore } }"}'
```

---

## 🔔 Webhook Subscription Management

```bash
# Subscribe to scan events
curl -X POST http://localhost:8000/api/v1/webhooks/subscribe \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event_type":"scan.completed","url":"https://hooks.example.com/ch3ck3r","secret":"your-hmac-secret"}'

# Valid event types: scan.started, scan.completed, scan.failed, finding.critical, finding.high, *

# Unsubscribe
curl -X POST http://localhost:8000/api/v1/webhooks/unsubscribe \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event_type":"scan.completed","url":"https://hooks.example.com/ch3ck3r"}'

# List all subscribers
curl http://localhost:8000/api/v1/webhooks/subscribers \
  -H "Authorization: Bearer $TOKEN"
```

---

## ⚙️ External Tool Verification

```bash
# Verify installed external tools
zap-cli --version
nuclei -version
semgrep --version

# Test Nuclei with API tags
nuclei -u https://example.com -tags api,cve -severity critical,high -json -o results.json

# Test ZAP baseline scan
zap-cli quick-scan -s xss,sqli https://example.com/api

# Test Semgrep with OWASP rules
semgrep --config p/owasp-top-ten --config p/security-audit .
```

---

## 📈 Running Performance Benchmarks

```bash
# Start the backend first
cd backend && uvicorn app.main:app --reload --port 8000 &

# Run benchmarks against a running server
python benchmarks/benchmark.py http://localhost:8000

# Output example:
# ╔══════════════════════════════════════════════════════════════╗
# ║  Ch3ck3r Performance Benchmark Results                      ║
# ╚══════════════════════════════════════════════════════════════╝
# Health Check:        p50=2ms   p95=5ms   p99=12ms   ops=500/500
# Auth Register:       p50=45ms  p95=120ms p99=250ms  ops=20/20
# Scanners List:       p50=1ms   p95=3ms   p99=8ms    ops=500/500

# With pytest (pytest-benchmark integration)
pytest benchmarks/ -v --benchmark-only

# Generate benchmark HTML report
pytest benchmarks/ --benchmark-only --benchmark-json=bench-results.json
python -c "
import json, sys
with open('bench-results.json') as f:
    data = json.load(f)
for name, bench in data['benchmarks'].items():
    print(f\"{name}: mean={bench['stats']['mean']*1000:.1f}ms  median={bench['stats']['median']*1000:.1f}ms\")
"
```

---

## 🧪 Running Tests

```bash
# All tests
cd backend
pytest tests/ -v

# Integration tests (need running PG + Redis)
pytest tests/integration/test_api.py -v

# Health-specific tests
pytest tests/test_health.py -v

# Benchmark tests
pytest benchmarks/ -v

# With coverage
pytest --cov=app --cov-report=term --cov-report=html tests/
```

---

## 📦 Docker

```bash
# Build and start all services
docker compose up --build

# Run only backend
docker compose up backend redis postgres

# Run specific scanner only
docker compose up nuclei

# Scale workers
docker compose up -d --scale celery-worker=3
```

---

## 🐳 Kubernetes Deployment

```bash
# Deploy to Kubernetes
kubectl create namespace ch3ck3r
kubectl apply -k kubernetes/base -n ch3ck3r

# With dev overlay
kubectl apply -k kubernetes/overlays/dev -n ch3ck3r

# With prod overlay (scaled up)
kubectl apply -k kubernetes/overlays/prod -n ch3ck3r

# Check status
kubectl get pods -n ch3ck3r
kubectl get deployments -n ch3ck3r
kubectl logs -f deployment/backend -n ch3ck3r

# Port forward for local access
kubectl port-forward svc/backend 8000:8000 -n ch3ck3r
kubectl port-forward svc/frontend 3000:3000 -n ch3ck3r
```

---

## 🔐 Alert Configuration (Slack / Discord / Email)

```bash
# Set in .env:
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy
SMTP_HOST=smtp.gmail.com
SMTP_USERNAME=you@gmail.com
SMTP_PASSWORD=app-password
ALERT_EMAIL_TO=security@example.com

# Alert rules are managed via the dashboard:
# http://localhost:3000/alerts
```

---

## 🩺 Health Check

```bash
# Liveness
curl http://localhost:8000/api/v1/health/live

# Readiness (checks DB + Redis)
curl http://localhost:8000/api/v1/health/ready
```

---

## Quick Scan Targets for Testing

```bash
# Deliberately vulnerable APIs (test only!)
# OWASP Juice Shop
https://juice-shop.herokuapp.com

# crAPI (Completely Ridiculous API)
http://crapi.local:8888

# VAmPI (Vulnerable API)
http://localhost:5000

# Generic test
https://httpbin.org
https://jsonplaceholder.typicode.com
```

---

## 🔍 Querying with jq (pretty print & filter)

```bash
# Extract all critical findings
curl -s "http://localhost:8000/api/v1/findings?scan_id=<UUID>" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '.findings[] | select(.severity == "critical") | {title, endpoint, remediation}'

# Get scan risk scores
curl -s http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" | \
  jq '.scans[] | {target, risk_score, total_findings, status}'

# Watch a live scan (polling)
watch -n 2 "curl -s http://localhost:8000/api/v1/scans/<UUID> \
  -H 'Authorization: Bearer $TOKEN' | \
  jq '{status, risk_score, total_findings}'"
```
