# ScamSathi BD

**Don't Trust. Verify First.**

An AI-powered investigation platform that checks suspicious URLs and messages using external security-intelligence APIs, evaluates the evidence deterministically, and explains the findings in **Bangla or English**.

Category: Cybersecurity / Artificial Intelligence / Agentic AI

---

## 1. Project Overview

ScamSathi BD lets a user paste a website URL, an SMS/chat message, an email, or an online offer. A Gemini function-calling agent plans the investigation, Python executes the permitted tools (Google Safe Browsing, VirusTotal, URLhaus, offline domain and message analysis), a deterministic risk engine scores the evidence, and the model explains the result in plain language.

## 2. Problem Statement

People in Bangladesh receive fake bKash/Nagad/bank messages, fake job circulars, fake shopping offers, prize/lottery scams and phishing links through SMS, Messenger, WhatsApp and email every day. Most users cannot independently investigate a link or message before trusting it.

## 3. Our Solution

Submit the content → the agent investigates → you get a risk score, the evidence from each source (including checks that failed or were unavailable), suspicious indicators, a plain-language explanation, recommended actions and the real investigation timeline. Everything is saved to a local history you can delete.

## 4. Key Features

- URL, SMS/message, email and mixed-input investigation with automatic classification
- Gemini **function-calling agent** that selects tools conditionally, within a hard budget of 6 tool calls
- Three external security sources: Google Safe Browsing, VirusTotal, URLhaus (optional)
- Offline analysis: bilingual scam-language indicators and domain-feature indicators (brand lookalikes, abused TLDs, punycode, IP hosts, shorteners)
- **Deterministic risk engine** — the LLM never sets the score
- Separate **confidence** indicator describing investigation completeness
- Bangla / English UI and explanations, with template fallback when Gemini is unavailable
- Real progress events from the backend (no fake animations)
- SQLite history with minimised content, per-record and bulk deletion
- Statistics dashboard, Markdown/JSON report download
- Security hardening: never fetches submitted URLs (SSRF-safe), rejects `javascript:`/`file:`/private-network URLs, validates every tool argument, treats submitted text as untrusted (prompt-injection resistant)

## 5. System Architecture

```text
                         USER
                           |
                           v
                  STREAMLIT FRONTEND            frontend/
               URL / SMS / EMAIL INPUT
                           |
                           v
                   PYTHON BACKEND               backend/orchestrator.py
             Validation and classification      utils/validators.py, backend/classifier.py
                           |
                           v
                    GEMINI AI AGENT             backend/agent.py (+ RuleBasedPlanner fallback)
              Planning and tool selection       backend/tools.py (validated executors)
                           |
             +-------------+-------------+-----------------+----------------+
             |             |             |                 |                |
             v             v             v                 v                v
        VirusTotal    Safe Browsing    URLhaus      Domain indicators  Message analysis
     integrations/   integrations/   integrations/   backend/domain_    backend/message_
      virustotal.py  safe_browsing.py  urlhaus.py     indicators.py      analysis.py
             +-------------+-------------+-----------------+----------------+
                           |
                           v
                  EVIDENCE NORMALIZER           backend/evidence.py
                           |
                           v
                    RISK ENGINE                 backend/risk_engine.py (deterministic)
                           |
                           v
                  GEMINI REPORT WRITER          backend/report_generator.py (structured output)
                           |
                           v
                  RESULTS + SQLITE              database/
```

## 6. Agentic Workflow

1. Input is validated (length, scheme, private-network rejection) and classified (URL / Message / Email / Mixed); URLs are extracted and normalised.
2. The agent receives the content wrapped as **untrusted data** plus the declared tool schemas.
3. The model requests a tool; Python validates the name and arguments (URL arguments must be one of the extracted URLs) and executes it.
4. The normalised result is returned to the model, which decides whether another check adds value.
5. Hard limits: max 6 tool calls, no duplicate calls, no undeclared tools, no arbitrary code, no browsing of the target.
6. `calculate_risk` and `generate_report` are run by the orchestrator, not chosen by the model.
7. Every step is recorded as an agent log (success / failed / skipped / rejected) and streamed to the UI as real events.

If `GEMINI_API_KEY` is missing or Gemini fails mid-run, a deterministic rule-based planner drives the same tool loop and the UI clearly says so.

### Tools

| Tool | Responsibility |
| --- | --- |
| `analyze_message` | Detect suspicious language and claims (Bangla + English) |
| `extract_urls` | Extract validated URLs from text |
| `get_domain_indicators` | Offline domain-feature examination |
| `check_safe_browsing` | Google Safe Browsing lookup |
| `check_virustotal` | VirusTotal URL reputation |
| `check_urlhaus` | URLhaus malware-distribution lookup (when configured) |
| `calculate_risk` | Deterministic risk engine (orchestrator-controlled) |
| `generate_report` | Structured bilingual report (orchestrator-controlled) |

### Risk scoring model

| Evidence group | Max contribution |
| --- | --- |
| Google Safe Browsing threat match | 40 |
| VirusTotal malicious evidence | 25 |
| URLhaus malware match | 20 |
| Suspicious domain indicators | 10 |
| Suspicious message indicators | 5 |

Score bands: 0–19 Low · 20–39 Guarded · 40–69 Suspicious · 70–100 High.

Documented floors: strong message indicators (indicator weight × 9, cap 80) and brand-lookalike domain features (weight × 4, cap 45) can raise the score, because an OTP request or a fake-bKash domain is dangerous regardless of list reputation. Only API evidence can push a score above those caps. Conversely, a URL that Safe Browsing, VirusTotal or URLhaus explicitly lists as phishing/malware is a confirmed threat and is floored at 70 (High) even if nothing else corroborates it. Multiple URLs checked by the same source contribute the maximum, not the sum. An unavailable API contributes no evidence for or against safety and lowers **confidence**, which is reported separately from risk.

## 7. API Integrations

| Provider | Endpoint | Notes |
| --- | --- | --- |
| Google Safe Browsing Lookup API v4 | `POST /v4/threatMatches:find` | Non-commercial terms; a "no match" is not proof of safety |
| VirusTotal API v3 | `GET /urls/{id}` → `POST /urls` → `GET /analyses/{id}` | Bounded polling; public quota is limited |
| URLhaus (abuse.ch) | `POST /v1/url/` | Requires an Auth-Key; malware-distribution data only |
| Gemini API | function calling + structured JSON output | Automatic function calling disabled; the app executes tools |

All calls use explicit timeouts, a single bounded retry on transient errors, and distinguish *not found*, *unavailable*, *failed*, *not configured* and *skipped*.

## 8. Technology Stack

Streamlit · Python 3.10+ · Google Gemini (`google-genai`) · Requests · Pandas · Pydantic · SQLAlchemy + SQLite · Plotly · tldextract · Pytest

## 9. Installation Instructions

```bash
git clone https://github.com/<your-account>/ScamSathi-BD.git
cd ScamSathi-BD
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then fill in your keys
```

## 10. Environment Variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | recommended | Agent planning, AI message classification, report writing |
| `GEMINI_MODEL` | no | Defaults to `gemini-3.5-flash-lite` (≈0.5 s/turn; `gemini-3.6-flash` is stronger but ≈8 s/turn) |
| `GEMINI_FALLBACK_MODELS` | no | Comma-separated models tried only when the primary returns 404/429/5xx (model names are retired often) |
| `GEMINI_THINKING_LEVEL` | no | `low` (default, fast), `high`, or `default` to let the model decide; ignored by models that reject it |
| `GOOGLE_SAFE_BROWSING_KEY` | recommended | Safe Browsing lookups |
| `VIRUSTOTAL_API_KEY` | recommended | VirusTotal lookups |
| `URLHAUS_AUTH_KEY` | optional | URLhaus lookups |
| `DATABASE_URL` | no | Defaults to `sqlite:///scamsathi.db` |
| `RETAIN_SUBMITTED_CONTENT` | no | Store a minimised copy of submissions in history (default `true`) |

Missing keys never crash the app: the corresponding checks are reported as **Not configured** and the investigation continues with the configured tools.

## 11. How to Run

```bash
streamlit run app.py
```

Open http://localhost:8501. Pick a language in the sidebar, paste content, accept the privacy notice and click **Investigate Now**.

## 12. Screenshots

See `docs/screenshots/` (add screenshots of the actual running application before submission).

## 13. Testing

```bash
pytest -q
```

The suite (53 tests) covers input validation and SSRF rejection, URL extraction, classification, bilingual message indicators, domain indicators, deterministic scoring and confidence, each API integration against sanitised fixtures (match / no match / rate limit / timeout / polling), the agent loop (tool selection, argument validation, foreign-URL rejection, duplicate and budget enforcement, fallback planner), prompt-injection handling, report fallback and SQLite persistence. No test contacts a live service.

Suggested live demo scenarios:

- **A — Clear threat:** `http://testsafebrowsing.appspot.com/s/phishing.html` (Google's official test URL).
- **B — Conflicting evidence:** a URL flagged by some VirusTotal engines but absent from Safe Browsing.
- **C — Message without URL:** the Bangla prize/OTP message from the Home page examples — no URL tools are called.

## 14. Limitations

- "No match" from any provider only means "not on that list yet"; new scam domains are often unknown for days.
- Message indicators are heuristics, not proof of fraud; legitimate messages can contain urgency or payment requests.
- Results depend on third-party availability and free-tier quotas; VirusTotal analyses of never-seen URLs may still be queued when the bounded poll ends.
- Score thresholds and weights are initial design choices and need calibration against labelled data.
- The app never visits submitted URLs, so it cannot inspect page content.

## 15. Future Improvements

PDF reports · screenshot-based scam analysis · community reporting · browser extension · WHOIS/domain-age signals · calibrated scoring from labelled Bangladeshi scam datasets.

## 16. Team Members

_Add your team here._

---

Automated risk assessment, not a definitive legal finding. Data submitted for investigation may be sent to Google Safe Browsing, VirusTotal, URLhaus and the Gemini API; do not submit confidential content.
