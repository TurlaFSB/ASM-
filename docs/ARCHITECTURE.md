# Architecture and threat model

## Components

| Component | Responsibility |
|---|---|
| React frontend (nginx, unprivileged) | Single-page app; talks to the API with a cookie session and a CSRF header |
| FastAPI backend | REST API, authentication, authorization, audit log, report generation |
| Celery worker | Runs one scan at a time; owns the scanner tools and their child processes |
| Celery beat | Starts scheduled scans, the stuck-scan reaper, exposure sweeps and the daily retention job |
| PostgreSQL | Targets, scans, assets, findings, changes, seals, users, audit log |
| Redis | Celery broker and results, per-target scan lock, cancellation flags, revoked-token list, rate-limit counters |

## Scan lifecycle

1. The API creates a `pending` scan (one active scan per target is enforced by a database constraint) and queues `run_scan`.
2. The worker takes a per-target Redis lock, starts a *guard* thread (cancellation, runtime limit, lock renewal) and moves the scan to `running`.
3. Stages run in order: subdomains, DNS, WHOIS/ASN, ports, HTTP probing, then the web-analysis group in parallel (technologies, directory discovery, Nuclei, TLS, screenshots, CVE matching). IP and internal targets skip public discovery.
4. Results are saved (assets with change detection, findings, discovered paths), a snapshot is diffed against the previous comparable scan, alerts and the webhook digest are produced, and the scan is sealed.
5. Risk scoring runs, the scan is marked `completed`, and the PDF report is pre-built in the background.

Failure handling: a cancelled scan persists nothing; a timed-out scan is failed with a reason; a lost worker is detected by the reaper and its scan failed; a duplicate delivery of a completed scan is ignored. Diffing, alerting and sealing never turn a finished scan into a failed one.

## Data integrity

Every completed scan gets a signed seal chained to the target's previous seal (Ed25519, key derived from `SECRET_KEY`). Editing or deleting history breaks the chain and is reported by `/integrity`. Retention never deletes scans, findings, change events, seals or the audit log; it only removes on-disk artifacts and delivery logs.

## Threat model

ASM is a security tool with network reach and stored findings, so both its inputs and its own exposure matter.

| Asset | Threat | Mitigation |
|---|---|---|
| Target scope | Scanning something the operator does not own | Targets must be marked authorized; private/internal ranges are blocked unless explicitly allowed; out-of-scope redirect URLs are dropped before web stages |
| User sessions | Token theft, CSRF, brute force | httpOnly SameSite cookie, double-submit CSRF token, server-side revocation, login throttling per IP and username, password policy, global rate limit |
| Script credentials | A leaked or forgotten long-lived token | `asm_` tokens are stored only as a SHA-256 hash, default to read-only with an expiry, cannot create further tokens, die when the owner is deactivated or changes password, and every use updates a last-used time |
| First-run takeover | Someone claims a fresh install | Setup requires a code printed only in the server log; throttled; closes after the first admin |
| Webhooks | SSRF, secret leakage | Destination checked against internal ranges, no redirects, signed payloads, only the host (never the full URL) is logged |
| Scan data | Untrusted strings from targets reaching the UI or reports | Output escaping in the UI and report templates; strict Content Security Policy without inline scripts |
| Exposure findings | Leaking secrets found in public code | Values are masked before storage; only metadata is kept |
| Scan history | Tampering by someone with database access | Signed, chained seals |
| Containers | Escape or privilege escalation | Production overlay: non-root, read-only filesystem, all capabilities dropped (worker keeps only `NET_RAW`), unprivileged web server |
| Supply chain | Vulnerable or malicious dependencies | Dependabot, `pip-audit`, `npm audit`, CodeQL, Trivy image scans, secret scanning; accepted risks documented in SECURITY.md |

Out of scope: protecting against an attacker who already controls the host or the database credentials beyond what the seals detect, and denial of service from a trusted admin pointing scans at fragile targets (rate limits and profiles reduce, but do not remove, that risk).
