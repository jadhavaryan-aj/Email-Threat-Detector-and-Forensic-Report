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

## Phase 3 — NLP/ML 🟡 partial

Done: a modular `ContentAnalyzer` interface (`backend/app/nlp/base.py`) with a local
heuristic default (`heuristic_analyzer.py`) producing intents + confidence + evidence
phrases (urgency, payment diversion, fake invoice, credential harvesting, executive
impersonation) — explicitly not presented as a calibrated ML model.

Not done (by design, not oversight — see the original plan's reasoning): a live
LLM-backed provider implementing the same interface. Wiring one in is a bounded,
well-scoped follow-up: implement `ContentAnalyzer.analyze()` calling out to an LLM API,
register it in place of `HeuristicContentAnalyzer` in `detection_engine.py`. Keep it
optional/env-gated so the app still works fully offline per the demo-mode requirement.

## Phase 4 — Correlation ✅ done (simplified, not a graph DB)

`IndicatorObservation` records every IP/domain observed per case;
`correlation_service.py` finds shared infrastructure via a `GROUP BY` query and builds
an on-the-fly node/edge graph for the frontend's SVG mini-graph
(`CorrelationGraph.tsx`). Verified end-to-end with a regression test
(`test_correlation_detects_shared_ip_across_cases`) using two synthetic cases sharing
one IP.

Not done: confidence-scored attribution scenarios (compromised-account vs
spoofed-domain vs anonymized-infrastructure vs direct-actor). Would layer on top of
the existing correlation data — a `attribution_service.py` that scores which scenario
best fits based on signal combinations, without needing new data collection.

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

Not done: hash-chained tamper-evident evidence log (`EvidenceLogEntry`) — would be a
genuinely demoable "recompute the chain, catch a tampered row" moment for judges.

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

35 pytest tests, all passing: `.eml` parsing (including malformed-input handling),
Received-chain parsing + routing anomalies, domain-similarity/lookalike matching
(including a regression test for a false-positive found during browser testing),
signal generation/scoring/classification logic, and end-to-end API integration tests
against the 3 real DNS-verified fixtures plus upload validation, dashboard stats,
PDF generation, cross-case correlation, and the security fix above. Run with:

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
