# Build roadmap

Phased using the structure requested for this build pass. Each phase below is marked
✅ done / 🟡 partial / ⬜ not started, with what's left. See
[ps_component_mapping.md](ps_component_mapping.md) for the exact file backing each
piece.

## Phase 1 — MVP ✅ done

Real `.eml` ingestion, full header extraction (From/To/Cc/Reply-To/Return-Path/Date/
Message-ID/Authentication-Results/MIME structure), real live-DNS SPF/DMARC evaluation,
real DKIM cryptographic verification, Received-chain parsing + routing-anomaly
detection, signal-based explainable scoring (structured name/category/severity/score/
explanation/evidence — not a bare number), the PS's 5-way risk-band classification
plus a separate investigator-facing threat-category taxonomy.

## Phase 2 — Intelligence ✅ done

- Domain intelligence: real DNS (MX/NS) + WHOIS (registrar, creation date, age) +
  Spamhaus DBL domain-reputation check. `backend/app/intelligence/local_domain_provider.py`.
- IP intelligence: real geolocation/ASN/org via `ip-api.com` (free, no key) + Spamhaus
  ZEN IP-reputation check. `backend/app/intelligence/local_ip_provider.py`. Every
  result carries a persisted disclaimer — observed infrastructure, never attacker
  attribution.
- Threat intelligence: real AbuseIPDB/VirusTotal calls *if* the user configures an API
  key in `.env`; otherwise an honest `available=False`, never fabricated.
  `backend/app/intelligence/env_threat_intel_provider.py`.
- URL analysis: lexical risk scoring (IP-based host, punycode, shorteners, excessive
  subdomains, display-text/destination mismatch, lookalike link domains).
  `backend/app/services/url_analysis_service.py`.

All external calls are timeout-protected and degrade to `unavailable` rather than
blocking ingestion — verified by design, not just assumed.

## Phase 3 — NLP/ML ✅ done

A modular `ContentAnalyzer` interface (`backend/app/nlp/base.py`) with two
implementations behind it: `LLMContentAnalyzer` (`llm_analyzer.py`), real AI content
analysis via the Claude API — detects hidden intent, social engineering, and identity
deception that pure keyword matching misses — and `HeuristicContentAnalyzer` as the
local keyword-based fallback when no `ANTHROPIC_API_KEY` is configured. Selected
automatically in `detection_engine.py` based on whether the key is set, so the app
still works fully offline per the demo-mode requirement. AI-sourced signals score
dynamically from the model's own confidence rather than a fixed weight, and merge into
the same explainable Signal model as every deterministic check — never a bare "AI
score."

## Phase 4 — Correlation ✅ done (simplified, not a graph DB)

`IndicatorObservation` records every IP/domain observed per case;
`correlation_service.py` finds shared infrastructure via a `GROUP BY` query and builds
an on-the-fly node/edge graph for the frontend's SVG mini-graph
(`CorrelationGraph.tsx`). Verified end-to-end with a regression test
(`test_correlation_detects_shared_ip_across_cases`) using two synthetic cases sharing
one IP.

Also done: confidence-scored attribution scenarios. `assess_attribution_scenario()` in
`correlation_service.py` classifies a case into one of four DFIR scenarios
(`spoofed_domain` / `compromised_account` / `anonymized_infrastructure` / `direct_actor`,
or `insufficient_data` below a risk threshold) purely from signals/intelligence already
computed — rule-based, not a new ML model, with stated reasoning and a confidence.
Exposed via `GET /api/cases/{id}/attribution`, shown next to the correlation graph.

## Phase 5 — Forensics ✅ done

- Case management: `CaseStatus` enum (new/investigating/escalated/resolved/
  false_positive), analyst notes (`CaseNote`), both exposed via API and the case-detail
  UI's status dropdown + notes panel.
- Investigation timeline: `TimelineEvent` rows emitted at every pipeline stage
  (ingested → headers analyzed → URLs extracted → intelligence retrieved → risk
  scored) plus note/status-change events.
- Forensic PDF report: `report_service.py` + `templates/forensic_report.html` via
  `xhtml2pdf` — covers case info, hash, classification, full risk breakdown, sender
  info, auth results, header trace, URL/domain/IP intelligence, threat intel,
  correlated indicators, timeline, notes, and the mandatory attribution disclaimer.

Also done: a hash-chained, tamper-evident evidence log. `EvidenceLogEntry` rows
(`prev_entry_hash` + `entry_hash`, SHA-256 over the previous hash and this entry's
payload) are appended at ingestion/scoring time; `GET /api/cases/{id}/evidence-log`
recomputes and verifies the whole chain live on every call — never a cached flag —
and the case-detail page's Evidence Log panel shows a green/red verified indicator.
A genuinely demoable "recompute the chain, catch a tampered row" moment for judges:
directly editing one stored entry's payload breaks its own hash and every entry
chained after it (see `test_evidence_log_detects_tampering`).

## Phase 6 — Hardening ✅ done for this pass

- 10MB upload cap with a bounded chunked read (never fully buffers an oversized file
  before checking) — verified to reject a 15MB file with HTTP 413.
- Malformed/non-email content degrades gracefully (analyzed as an empty-fields email,
  never a 500) — verified with garbage bytes under a `.eml` extension.
- **Found and fixed a real vulnerability**: the PDF report's Jinja2 environment had no
  `autoescape`, so a crafted email Subject/From/URL could get `xhtml2pdf` to attempt
  loading local files as images (LFI) during report generation. Fixed with
  `autoescape=True`; confirmed exploitable pre-fix and neutralized post-fix via direct
  testing, with a permanent regression test guarding it.
- Verified `python-whois` never shells out in this codebase's usage (the subprocess
  path requires `command=True`, which is never passed).
- CORS restricted to the configured frontend origin, not `*`.

Remaining: rate limiting, request-size limits on JSON endpoints (notes/status), and a
dependency vulnerability scan (`pip-audit`/`npm audit`) haven't been run.

## Phase 7 — Testing ✅ done for this pass

64 pytest tests, all passing: `.eml` parsing (including malformed-input handling),
Received-chain parsing + routing anomalies, domain-similarity/lookalike matching
(including a regression test for a false-positive found during browser testing),
signal generation/scoring/classification logic, hash-chain integrity (including
tamper detection against the real database), attribution-scenario rule branches,
the API-key auth gate, and end-to-end API integration tests against the 3 real
DNS-verified fixtures plus upload validation, dashboard stats, PDF generation, and
cross-case correlation. Run with:

```bash
cd backend
.venv\Scripts\python -m pytest tests\ -v
```

Integration tests need live network access (real DNS/WHOIS/ip-api lookups) by design —
consistent with the project's "no mocked results" philosophy.

Remaining: frontend component tests (none written — verification for the UI was done
via real browser testing instead, per the standing practice for this project).

## Phase 8 — SIH Demo ✅ done

Dark SOC-themed dashboard and case-detail "star page" — executive summary, signal
cards grouped by severity, identity mismatch callouts, auth tiles, interactive
received-chain table, infrastructure-intelligence cards with disclaimers, URL analysis
table, correlation graph, timeline, notes, one-click PDF export. See the root
[README.md](../README.md) for the exact demo flow and commands.

## Phase 9 — Chrome extension ✅ done

`extension/` — Manifest V3, `chrome.identity` OAuth against the user's own Gmail
(`gmail.modify` scope), scans the inbox via the Gmail REST API, uploads each message
to this same backend pipeline, and applies native color-coded Gmail labels by
classification. High-risk mail (fraud score ≥ 90) surfaces its traced origin
geolocation on the dashboard, which deep-links back into the real Gmail message. See
[extension/README.md](../extension/README.md).

## Phase 10 — Professional polish pass ✅ done

- **Visual polish**: IBM Plex Sans/Mono typography (matching the pitch deck), loading
  skeletons, designed empty states, a real favicon, spacing/hierarchy pass on the case
  detail page.
- **Extension branding**: gradient-shield icon set, a "recent scans" list in the
  popup, Chrome-Web-Store-ready manifest copy.
- **Forensic evidence log**: see Phase 5 above.
- **Attribution scenarios**: see Phase 4 above.
- **Production readiness**: an optional `BACKEND_API_KEY` shared-secret gate on every
  `/api/*` route (open by default, matching every other optional setting in this
  app); Postgres documented as a drop-in `DATABASE_URL` swap (`psycopg2-binary`
  already in `requirements.txt`); a React error boundary with a real fallback UI;
  `backend/Dockerfile` + `frontend/Dockerfile` + a root `docker-compose.yml` that runs
  both together behind nginx. See the root README's "Deploying" section.
