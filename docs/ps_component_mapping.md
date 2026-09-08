# SIH26106 — problem statement component mapping

Maps every required component — both the official problem statement and the fuller
DFIR-platform spec the build was upgraded against — to what implements it, so it's
always clear what's demo-ready today versus on the roadmap. See
[build_roadmap.md](build_roadmap.md) for what's not built yet, phased.

## 1. Fraudulent Email Detection Engine

| Requirement | Status | File |
|---|---|---|
| NLP on subject/body, urgency/social-engineering cues | ✅ | [`backend/app/nlp/heuristic_analyzer.py`](../backend/app/nlp/heuristic_analyzer.py) — modular `ContentAnalyzer` interface ([`base.py`](../backend/app/nlp/base.py)), local heuristic by default, pluggable for a real ML/LLM model later |
| Phishing indicators: spoofed sender, deceptive/lookalike domains | ✅ | [`backend/app/utils/domain_similarity.py`](../backend/app/utils/domain_similarity.py) — whole-domain typosquat + brand-embedded-in-longer-domain detection (rapidfuzz), plus display-name impersonation |
| Suspicious attachments / obfuscated links | ✅ | attachments: `detection_engine.py`; links: [`url_analysis_service.py`](../backend/app/services/url_analysis_service.py) (IP-based host, punycode, shorteners, excessive subdomains, display-text mismatch, lookalike link domains) |
| Structured, explainable signals (name/category/severity/score/explanation/evidence) | ✅ | [`backend/app/models/signal.py`](../backend/app/models/signal.py), definitions in [`scoring_config.py`](../backend/app/services/scoring_config.py) — this **replaced** an earlier flat score-breakdown dict specifically so every point on the risk score traces to a named, explained, evidenced signal |
| Multi-category threat classification (Legitimate/Spam/Phishing/Spear Phishing/BEC/Spoofing/Credential Theft/Malware Delivery/Suspicious) + secondary indicators | ✅ | `detection_engine.py::classify_threat_category` — kept distinct from the PS's own 5-way risk-band label (`ClassificationLabel`), since they answer different questions |

## 2. Email Header and Protocol Analysis Module

| Requirement | Status | File |
|---|---|---|
| Full header extraction (From/To/Cc/Reply-To/Return-Path/Subject/Date/Message-ID/MIME/Authentication-Results) | ✅ | [`backend/app/utils/eml_parser.py`](../backend/app/utils/eml_parser.py) |
| DKIM signature verification | ✅ real cryptographic verification via `dkimpy` | [`header_protocol_service.py`](../backend/app/services/header_protocol_service.py) |
| SPF evaluation | ✅ custom live-DNS RFC 7208 evaluator (pyspf rejected as unmaintained) | [`backend/app/utils/spf_dmarc.py`](../backend/app/utils/spf_dmarc.py) |
| DMARC status + alignment | ✅ live DNS + real alignment logic (bug found & fixed: alignment must check the domain SPF was checked *for*, not wherever a `redirect=`/`include:` chain matched) | `spf_dmarc.py`, `header_protocol_service.py` |
| Cross-check against upstream Authentication-Results | ✅ | `header_protocol_service.py::_cross_check_authentication_results` — supplementary evidence only; our own live checks stay authoritative since this header is trivially forgeable |
| Routing anomalies, forged sender fields, relay manipulation | ✅ | [`received_chain_parser.py`](../backend/app/utils/received_chain_parser.py) — return-path/reply-to mismatch, display-name impersonation, out-of-order timestamps, missing hop info |
| Explicit observed/inferred/confidence distinction for header trace | ✅ | received-chain hops are shown as raw structured data (hop/IP/host/timestamp) with no attacker-IP claim baked in; origin selection picks the earliest *public* IP and is labeled as such, not as "the attacker" |

## 3. Origin Traceability and Location Analysis

| Requirement | Status | File |
|---|---|---|
| Extract originating IP from Received chain | ✅ | `received_chain_parser.py::select_originating_ip` |
| IP geolocation (country/region/city/ISP/ASN) | ✅ real, via `ip-api.com` (free, no key) | [`backend/app/intelligence/local_ip_provider.py`](../backend/app/intelligence/local_ip_provider.py) |
| VPN/proxy/TOR + reputation | ✅ `ip-api` proxy flag + real Spamhaus ZEN DNSBL check | `local_ip_provider.py` |
| WHOIS / DNS / MX domain intelligence | ✅ real, via `python-whois` + `dnspython` (verified: never shells out — `command=True` is opt-in and never passed) | [`backend/app/intelligence/local_domain_provider.py`](../backend/app/intelligence/local_domain_provider.py) |
| Domain reputation | ✅ real Spamhaus DBL check | `local_domain_provider.py` |
| Explicit "observed infrastructure, not attacker location" framing | ✅ | `IpIntelResult.disclaimer` is persisted with every row (not just added at render time) and shown on every IP card + in the PDF report |

## 4. Identity Correlation and Attribution Support

| Requirement | Status | File |
|---|---|---|
| Cross-case shared-infrastructure detection | ✅ real, via `IndicatorObservation` (one row per IP/domain per case) + a `GROUP BY ... HAVING COUNT(DISTINCT case_id) > 1` query — deliberately not a generic graph database, which would be over-engineering at this scale | [`backend/app/services/correlation_service.py`](../backend/app/services/correlation_service.py) |
| Graph-based relationship view | ✅ nodes/edges built on the fly, rendered as a plain-SVG mini-graph (no new charting dependency) | `GET /api/cases/{id}/graph`, [`frontend/src/components/CorrelationGraph.tsx`](../frontend/src/components/CorrelationGraph.tsx) |
| Confidence-scored attribution scenarios (compromised account / spoofed domain / anonymized infra / direct actor) | ⬜ roadmap | not built — see build_roadmap.md |
| "Potential correlation" wording, never "same attacker" | ✅ | baked into `correlation_service.py`'s own note text and the frontend's shared-infrastructure callout |

## 5. Alerting, Dashboard, and Forensic Reporting

| Requirement | Status | File |
|---|---|---|
| Analyst dashboard (totals, risk distribution, threat categories, recent cases) | ✅ | [`backend/app/services/dashboard_service.py`](../backend/app/services/dashboard_service.py), [`frontend/src/pages/DashboardPage.tsx`](../frontend/src/pages/DashboardPage.tsx) |
| Case detail "investigation" view | ✅ | [`frontend/src/pages/CaseDetailPage.tsx`](../frontend/src/pages/CaseDetailPage.tsx) — executive summary, signal cards, identity panel, auth tiles, header trace, infrastructure intelligence, URL analysis, correlation graph, timeline, notes |
| Real-time alerts (WebSocket) | ⬜ roadmap | not built |
| Structured forensic PDF report | ✅ | [`backend/app/services/report_service.py`](../backend/app/services/report_service.py) + [`templates/forensic_report.html`](../backend/app/templates/forensic_report.html) via `xhtml2pdf` (chosen over WeasyPrint specifically to avoid its native GTK/Pango/cairo dependency chain on Windows) |
| Case management (status, analyst notes) | ✅ | `CaseStatus` enum on `Case`, [`models/forensics.py`](../backend/app/models/forensics.py) (`CaseNote`), `PATCH /api/cases/{id}/status`, `POST /api/cases/{id}/notes` |
| Investigation timeline | ✅ | `TimelineEvent` rows emitted at every pipeline stage in `ingestion_service.py`, plus note/status-change events |

## Privacy, Legal, and Compliance Safeguards

| Requirement | Status |
|---|---|
| Attribution disclaimer in every report | ✅ — the report's closing section states geolocation "does not establish the physical location or identity of the attacker" verbatim |
| Chain-of-custody / tamper-evident evidence log | ⬜ roadmap (hash-chained `EvidenceLogEntry`) |
| Configurable PII retention/masking | ⬜ roadmap |
| Untrusted-input handling | ✅ 10MB upload cap with a bounded chunked read (never buffers an oversized file fully before checking), extension validation, malformed-email parsing degrades gracefully instead of crashing (verified: garbage bytes with a `.eml` extension are accepted and analyzed as an empty-fields email, never a 500) |

## Security review findings (this build pass)

A real Local-File-Inclusion / HTML-injection vulnerability was found and fixed:
`report_service.py`'s Jinja2 `Environment` had no `autoescape`, so a crafted email
Subject/From/URL containing `<img src="file:///...">` would be passed through to
`xhtml2pdf`'s HTML parser, which does fetch image sources. Confirmed exploitable (a
real local image path was processed pre-fix) and confirmed fixed post-fix (renders as
inert literal text) — see `tests/test_api_integration.py::test_report_escapes_malicious_subject_html`
for the regression test. Also verified: `python-whois` only shells out if
`command=True` is passed explicitly (default `False`, pure-Python socket client) —
this codebase never passes it, so there's no injection risk despite the library
having a subprocess code path.
