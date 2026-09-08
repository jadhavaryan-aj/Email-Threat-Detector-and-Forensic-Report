# SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

Smart India Hackathon 2026 submission for problem statement **SIH26106**
(AICTE, Cyber Security Cell theme — Blockchain & Cybersecurity).

> Analyzes an email, explains the evidence, traces observable infrastructure,
> correlates indicators across cases, and produces a forensic investigation report —
> an investigator-oriented platform, not a binary phishing checker.

See [docs/ps_component_mapping.md](docs/ps_component_mapping.md) for every requirement
mapped to its implementing file, and [docs/build_roadmap.md](docs/build_roadmap.md) for
what's built vs. planned, phased.

There's also a **Chrome extension** ([`extension/`](extension/)) that scans your
Gmail inbox and labels risky emails by threat level using this same pipeline — see
[extension/README.md](extension/README.md) for setup (needs a one-time Google OAuth
client of your own; can't be pre-configured).

## Architecture

```
Raw .eml → parsing → header/auth analysis (SPF/DKIM/DMARC, live DNS + real crypto)
        → URL extraction/analysis → domain/IP/threat intelligence (real DNS/WHOIS/
          ip-api, honest "unavailable" without a threat-intel API key)
        → AI content analysis (Claude, heuristic fallback) → signal-based explainable
          risk scoring → hash-chained evidence log entry
        → case creation → cross-case correlation (shared infrastructure) +
          rule-based attribution scenario assessment
        → investigation dashboard → forensic PDF report
```

Every stage is a separate, independently-testable module — see
`backend/app/services/` and `backend/app/intelligence/`. Nothing is mocked: every
SPF/DMARC verdict comes from a live DNS lookup, every DKIM verdict from real
cryptographic signature verification, every IP/domain intelligence field from a real
lookup (or an honest "unavailable" if the lookup fails or no API key is configured).

**Backend**: Python 3.11 + FastAPI + SQLModel + SQLite (Postgres-ready — see Deploying)
**Frontend**: React + Vite + TypeScript + Tailwind CSS v4 (dark SOC-style UI)
**AI**: Claude (Anthropic) for content/intent analysis, with a local heuristic fallback
when no API key is configured

## Installation & setup

**Backend** (port 8000):

```bash
cd backend
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env
.venv\Scripts\python -m uvicorn app.main:app --port 8000 --reload
```

**Frontend** (port 5173, proxies `/api` to the backend):

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

## Environment variables (`backend/.env`)

All optional — the full pipeline runs with zero keys configured:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLite path (default `sqlite:///./data/sih.db`) |
| `RAW_EMAIL_DIR` | Where uploaded `.eml` originals are stored, keyed by SHA-256 |
| `CORS_ORIGINS` | Allowed frontend origin(s) |
| `ABUSEIPDB_API_KEY` | Optional — enables real IP threat-intel verdicts |
| `VIRUSTOTAL_API_KEY` | Optional — enables real domain threat-intel verdicts |
| `ANTHROPIC_API_KEY` | Optional — enables real AI content analysis (Claude) in place of the local keyword heuristic for identity disguise, social engineering, and similar deception patterns |
| `BACKEND_API_KEY` | Optional — gates every `/api/*` route behind this shared secret (`X-API-Key` header). Unset means the API is fully open; the frontend prompts for it once and remembers it in `localStorage` if the backend rejects a request with 401 |

## Testing

```bash
cd backend
.venv\Scripts\python -m pytest tests\ -v
```

64 tests: `.eml`/header/signal-generation unit tests, hash-chain and attribution-
scenario unit tests, API-key auth gate tests, plus end-to-end API integration tests
against the real demo fixtures (these need network access — real DNS/WHOIS/ip-api
lookups, by design).

## Sample email testing

[`sample_emails/`](sample_emails/) has 3 fixtures grounded in DNS records that were
genuinely live when built (see [sample_emails/README.md](sample_emails/README.md)):

| Fixture | Expected result |
|---|---|
| `clean_legit_001.eml` | LOW risk / Legitimate — real Gmail SPF pass, real DMARC pass |
| `spf_fail_spoofed_001.eml` | HIGH risk / Credential Theft — spoofed SBI bank alert, real hard SPF fail against SBI's actual `-all` policy |
| `dmarc_fail_lookalike_bec_001.eml` | CRITICAL risk / Malware Delivery — lookalike PayPal domain, BEC payment-fraud language, suspicious attachment |

Upload them via the dashboard's Upload page, or:

```bash
curl -X POST http://127.0.0.1:8000/api/cases/upload -F "file=@sample_emails/clean_legit_001.eml"
```

## API reference

| Endpoint | Purpose |
|---|---|
| `POST /api/cases/upload` | Upload a `.eml` file, runs the full pipeline synchronously |
| `GET /api/cases` | List all cases (summary) |
| `GET /api/cases/{id}` | Full case detail — headers, signals, intelligence, URLs |
| `GET /api/cases/{id}/timeline` | Investigation timeline events |
| `POST /api/cases/{id}/notes` | Add an analyst note |
| `PATCH /api/cases/{id}/status` | Update case status |
| `GET /api/cases/{id}/indicators` | Shared-infrastructure correlation for this case |
| `GET /api/cases/{id}/graph` | Node/edge graph JSON for the correlation view |
| `GET /api/cases/{id}/attribution` | Rule-based attribution scenario assessment (confidence + reasoning) |
| `GET /api/cases/{id}/evidence-log` | Hash-chained evidence log, live-verified on every call |
| `GET /api/cases/{id}/report` | Forensic PDF report |
| `GET /api/dashboard/stats` | Aggregate dashboard statistics |

All `/api/*` routes above require the `X-API-Key` header if `BACKEND_API_KEY` is set
(see Environment variables); `/health` never requires it.

Interactive docs (Swagger) at http://localhost:8000/docs once the backend is running.

## Judge demo flow (~3 minutes)

1. Open the **Dashboard** — aggregate stats across analyzed cases.
2. Upload `dmarc_fail_lookalike_bec_001.eml` from the Upload page.
3. Land on the case detail page — see the **risk score + executive summary**.
4. Scroll to **Risk Breakdown** — every point on the score has a name, category,
   severity, explanation, and evidence.
5. **Authentication** tiles — real SPF/DKIM/DMARC results.
6. **Email Identity** — From/Reply-To/Return-Path with mismatches called out.
7. **Received Chain** — the header trace, hop by hop.
8. **Infrastructure Intelligence** — real IP geolocation/ASN and domain WHOIS, with
   the "observed infrastructure, not attacker location" disclaimer front and center.
9. **URL Analysis** — lexical risk flags on any links.
10. **Threat Correlation** graph + shared-infrastructure callouts, next to the
    **Attribution Assessment** (spoofed domain / compromised account / anonymized
    infrastructure / direct actor, with stated confidence and reasoning).
11. **Evidence Log** — the hash-chained chain of custody, live-verified on every page
    load (green = verified). For real drama: edit one entry's payload directly in the
    database and reload — verification catches it and turns red.
12. Change the case **status**, add an **analyst note**.
13. Click **Export Report** for the full forensic PDF.

## Deploying

**Docker Compose** (backend + frontend, wired together):

```bash
docker compose up --build
```

Frontend on http://localhost, reverse-proxying `/api` to the backend container
(`frontend/nginx.conf`). Backend data persists in a named volume (`backend_data`).
For a from-scratch cloud deployment, `backend/Dockerfile` and `frontend/Dockerfile`
also build independently if you're placing each on a different service.

Before exposing either container beyond localhost, change:

| Variable | Change to |
|---|---|
| `CORS_ORIGINS` | The real frontend origin(s) — never `*` |
| `DATABASE_URL` | A Postgres connection string for anything beyond a demo — SQLModel/SQLAlchemy make this a pure connection-string swap, no code changes (`postgresql://user:pass@host:5432/dbname`); `psycopg2-binary` is already in `requirements.txt` |
| `BACKEND_API_KEY` | A real random secret, so the API isn't fully open to the internet |

## Limitations & future work

Not built this pass, tracked in [docs/build_roadmap.md](docs/build_roadmap.md):
real-time WebSocket alerts, and full multi-user auth/RBAC (the current
`BACKEND_API_KEY` is a single shared secret, not per-user accounts). A real paid
threat-intel key (AbuseIPDB/VirusTotal) can be dropped into `backend/.env` at any
time — the code path is already real, just gated on the key being present.

## Project layout

```
backend/
  app/
    services/       ingestion pipeline, detection engine, scoring, correlation, dashboard, PDF report, evidence log
    intelligence/    pluggable Domain/IP/ThreatIntelligence providers (real local defaults)
    nlp/             pluggable content-analysis interface — Claude (LLM) + local heuristic fallback
    utils/           eml/header/URL parsing, domain-similarity matching, SHA-256 hash-chain primitives
    models/          SQLModel tables (case, signal, intelligence, correlation, forensics)
    api/             FastAPI routers
    templates/       Jinja2 forensic report template
    auth.py          optional shared-secret gate on /api/*
  tests/             pytest suite (unit + API integration) — 64 tests
  Dockerfile         backend container image
frontend/
  src/
    pages/           Dashboard, Upload, Case list, Case detail
    components/      Signal cards, identity panel, intelligence cards, correlation graph, attribution panel,
                      evidence log panel, timeline, notes, error boundary
  Dockerfile         multi-stage build → nginx, reverse-proxies /api to the backend container
  nginx.conf         SPA fallback routing + /api proxy config
extension/           Chrome extension — Gmail inbox scanner with threat-level labeling
sample_emails/       3 real, DNS-verified demo fixtures + the script that generated them
docs/                PS-to-code mapping and the phased roadmap
docker-compose.yml   runs backend + frontend together (`docker compose up --build`)
```
