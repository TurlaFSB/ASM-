<div align="center">

# ASM

### Self-Hosted Attack Surface Management

Continuous external reconnaissance, vulnerability scanning, TLS auditing and **historical change detection** in a single self-hosted platform.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Stack](https://img.shields.io/badge/stack-FastAPI%20%7C%20PostgreSQL%20%7C%20Celery%20%7C%20React-9b5de5)
![Deploy](https://img.shields.io/badge/deploy-Docker%20Compose-2496ed)
![License](https://img.shields.io/badge/license-MIT-informational)
![Status](https://img.shields.io/badge/status-active%20development-brightgreen)

</div>

---

## Overview

ASM takes an authorized domain or host and runs a full recon-to-report pipeline: subdomain enumeration, DNS and WHOIS/ASN enrichment, port scanning, HTTP probing, technology fingerprinting, directory discovery, template-based vulnerability scanning, CVE matching against detected service versions, TLS auditing and screenshots.

Every scan is stored as a point-in-time **snapshot** and compared with the previous comparable scan. The result is a structured, severity-rated list of what changed on your attack surface: a port opened, a service appeared, a sensitive path became reachable, a new CVE applies. Risk is scored against **CISA's Known Exploited Vulnerabilities (KEV) catalog**, so a Critical rating means active exploitation in the wild, not just a high CVSS score.

### Who it is for

| Audience | Value |
|---|---|
| **VAPT / pentest teams** | A repeatable recon baseline before manual testing, diffable across every engagement. |
| **Red teams** | Full target profiles in one place: ownership, live tech stack, exposed service inventory. |
| **Security engineers** | Continuous monitoring of an owned perimeter with change alerts and webhooks. |
| **Consultants / small teams** | Client-ready PDF reports and scan history without a SaaS subscription. |
| **Students / researchers** | A real multi-service system (queue, database, scanners, report engine) to study and extend. |

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Scan profiles](#scan-profiles)
- [Change detection](#change-detection)
- [Security posture](#security-posture)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [API](#api)
- [Scanning private and lab targets](#scanning-private-and-lab-targets)
- [Development](#development)
- [Backup and restore](#backup-and-restore)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Known limitations](#known-limitations)
- [Scope and responsible use](#scope-and-responsible-use)
- [License](#license)

---

## Architecture

```text
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│    React    │─────▶│   FastAPI    │─────▶│ PostgreSQL  │
│  Frontend   │◀─────│   Backend    │◀─────│             │
└─────────────┘      └──────┬───────┘      └─────────────┘
                            │
                            ▼
                     ┌──────────────┐      ┌─────────────┐
                     │ Celery Queue │─────▶│    Redis    │
                     │    + Beat    │      │             │
                     └──────┬───────┘      └─────────────┘
                            │
                            ▼
   ┌────────────────────────────────────────────────────────────┐
   │                      Scan pipeline                         │
   │                                                            │
   │  Subfinder, Amass → DNS → WHOIS/ASN → Nmap → httpx         │
   │     → WhatWeb · Directory discovery · Nuclei (parallel)    │
   │     → CVE match · sslyze · EyeWitness                      │
   │     → Snapshot + diff → Risk scoring                       │
   └────────────────────────────────────────────────────────────┘
```

Each scan runs as one Celery task and reports progress per stage to the UI. Database schema is managed by **Alembic**; a one-shot `migrate` service applies migrations before the API and workers start.

| Service | Role |
|---|---|
| `postgres` | Primary datastore |
| `redis` | Celery broker and result backend |
| `migrate` | One-shot `alembic upgrade head` |
| `backend` | FastAPI application (JWT auth, REST API) |
| `celery_worker` | Executes scans |
| `celery_beat` | Triggers scheduled scans |
| `frontend` | React single-page app served by nginx |

---

## Features

### Reconnaissance
- Subdomain enumeration (Subfinder, Amass); the apex target is always included, so private and lab hosts work
- WHOIS and ASN lookup: registrar, dates, name servers, network ownership
- DNS resolution, Nmap service/version detection, httpx probing with redirect following
- WhatWeb technology fingerprinting merged with httpx detection and de-duplicated
- Directory and content discovery with feroxbuster and a curated wordlist, rate-limited per target
- EyeWitness screenshots of every live web service

### Vulnerability and TLS analysis
- Nuclei template scanning for web services, plus network-level templates against discovered ports
- **CVE matching** of detected service versions against the NVD (CPE-based, vulnerable-component only). These findings are labelled *inferred* and grouped per component, separate from *confirmed* template matches
- sslyze TLS audit: deprecated protocols, weak ciphers, expired certificates, SHA-1 chains, Heartbleed
- KEV and exploitability enrichment on every matched CVE

### Change detection
- Versioned snapshots of assets, ports, services, technologies, HTTP metadata, discovered paths and findings
- Structured, severity-rated change events with a coverage-aware trust model (see [Change detection](#change-detection))
- Alerts and webhooks driven by confirmed change events: a per-target minimum severity, pending removals never notify, in-app alerts capped per scan, and one bounded digest webhook per scan (CVE roll-ups folded into one line per component)
- Webhooks are SSRF-checked, never follow redirects, retry with backoff, are signed with HMAC-SHA256 (`X-ASM-Signature` over `<timestamp>.<body>`), support generic JSON, Slack and Discord formats, and every delivery is recorded

### Risk and reporting
- Per-asset risk scoring: CVSS baseline, boosted for high-risk ports and admin surfaces, force-escalated to Critical when a matched CVE is in KEV
- Client-ready **PDF reports**, pre-built in the background after each scan and cached, so downloads are instant: executive summary with top actions, asset inventory, infrastructure, confirmed findings, inferred findings grouped per service, change detection, and remediation with SLA tiers
- CSV export for assets and vulnerabilities

### Operations
- Three scan profiles (Quick, Standard, Deep), with a per-target default for scheduled scans
- Recurring scans via Celery Beat (cron expressions or presets)
- JWT authentication on every route; admin created via script, no default credentials
- Audit log of target, scan and authentication actions, with source IP
- Docker Compose deployment with healthchecked dependencies

---

## Scan profiles

| Profile | Ports | Directory discovery | Nuclei (web) | Typical duration |
|---|---|---|---|---|
| **Quick** | Top 100 | none | high, critical | ~2 min |
| **Standard** (default) | Top 1000 plus common web/admin ports | curated core list | medium and above | ~6-10 min |
| **Deep** | All 65535 | core list plus extensions and `common.txt` | medium and above, long budget | ~20-30 min |

Durations are measured on a small lab host and vary with target size. Standard adds about 30 common web, admin and database ports that are outside nmap's top 1000. Services on other ports are not seen by Quick or Standard; use Deep for full-range coverage. Service version detection gets deeper with each profile, which improves CVE matching.

---

## Change detection

Each completed scan is stored as a snapshot. A new scan is compared only with the previous snapshot **of the same profile**, and only for the sections both scans actually covered.

| Rule | Behaviour |
|---|---|
| **Coverage gating** | A section is compared only if the stage ran cleanly in both scans. A timed-out or skipped stage never produces false "closed" or "removed" events. |
| **Additions vs removals** | Additions need a full baseline. Removals need both scans to be full. A partial directory scan is additive-only. |
| **Removal debounce** | The first missing item is held as *pending*. If it is missing again on the next comparable scan it is *confirmed*; if it returns, it is dismissed silently. |
| **Version comparison** | Versions are compared only when both scans report one. |
| **Confidence** | Events are marked *confirmed* or *inferred* (for example version-matched CVEs). |

Event categories: `asset`, `port`, `technology`, `http`, `path`, `finding`. Severity is assigned per rule, for example a newly opened risky port or a newly reachable sensitive path is **high**.

Recompute the events of the newest scan of a profile (for example after upgrading the engine):

```bash
docker compose exec backend python -m backend.scripts.rediff <scan_id>
```

### AI-assisted triage (optional)

With a local model enabled, each confirmed change also gets a one-line summary and a recommended next step. By default (`ASM_LLM_SEVERITY_MODE=advise`) the rules decide severity and the model only explains; when it rates a change differently the Changes page says so. Setting `adjust` lets the model move severity by one step (never lowering a high or critical change, or one tied to a known-exploited CVE). Turn that on only for a model that passes the evaluation below. Both the rule severity and the AI's own answer are always kept. Nothing leaves your machine with the `ollama` provider.

- Model output must match a strict schema; anything else, text containing links or commands, or an answer two or more severity steps away from what the rules allow (the sign of a model that was talked into something) is discarded together with its text, and the rules stand.
- Scanned content reaches the model only as short, whitelisted, sanitized fields, and the prompt treats it as untrusted data.
- Per scan it is bounded (`ASM_LLM_MAX_EVENTS`, `ASM_LLM_BUDGET_SECONDS`) and stops early when the model is down, so a scan never waits on it.
- The Changes page marks AI notes as advisory. Alerts and webhooks use the final severity.

Check the setup with `docker compose exec backend python -m backend.scripts.ai_smoke`. To measure a model before trusting it, run the labelled evaluation (48 cases covering exposed databases, secrets, KEV findings, noise, removals and prompt injection):

```bash
docker compose exec backend python -m backend.scripts.ai_eval
```

It writes a JSON report and exits non-zero unless every quality gate passes: at least 95% valid answers, no visible prompt-injection effect, no serious change lowered by the model, at least 85% of final severities within one step of the labelled answer, and severities no worse than the rules alone. The case inputs use the severities the diff engine really assigns, and a test keeps them in sync.

---

## Security posture

ASM performs active scanning, so its own security matters.

- **Authorization gate enforced at the API.** A target cannot be created without `authorized: true`, and a scan cannot start against an unauthorized or deactivated target. This is re-checked at trigger time.
- **No hardcoded credentials.** The admin account is created interactively; passwords are hashed with bcrypt.
- **JWT on every route**, with account status re-checked on each request.
- **Input validation.** Hostname format and length are enforced, and the per-target rate limit is bounded (1-100 req/s).
- **Private address protection.** Scanning private and reserved ranges is refused unless explicitly enabled (`ASM_ALLOW_PRIVATE_TARGETS`). Discovered hostnames that resolve to loopback, link-local, private or carrier-grade NAT space are skipped too.
- **Scope stays on the target.** URLs that HTTP probing reaches by following a redirect to another organisation are dropped before any scanner runs against them.
- **Webhook safety.** Destinations must be HTTPS and resolve to public addresses, redirects are never followed, messages are signed (HMAC-SHA256), credentials are never returned by the API, and target-controlled text is defanged in Slack and Discord messages.
- **Export safety.** CSV exports neutralise spreadsheet formulas.
- **Audit trail** for sensitive actions, including source IP.
- **Secrets stay out of git.** `.env` and `.env.docker` are ignored, and `SECRET_KEY` has no default: the app refuses to start without one.
- **Report rendering is sandboxed.** Templates are autoescaped and the PDF renderer blocks outbound fetches.

---

## Quick start

### Requirements

| | |
|---|---|
| Docker | Engine 24+ and Compose v2 |
| RAM | 4 GB+ available to Docker |
| Disk | 15-20 GB+ free. Scan artifacts accumulate, and a full disk makes Redis fail writes and scans crash |
| Ports | `3000`, `8000`, `5432`, `6379` free on the host |

### 1. Clone

```bash
git clone https://github.com/TurlaFSB/ASM-.git
cd ASM-
```

### 2. Configure secrets

```bash
cp .env.docker.example .env.docker
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)" > .env
```

Edit `.env.docker`:

```env
DATABASE_URL=postgresql+psycopg://asm_user:<same password as .env>@postgres:5432/asm_db
SECRET_KEY=<output of: openssl rand -hex 32>
```

### 3. Start the stack

```bash
docker compose up -d --build
docker compose ps
```

`postgres` and `redis` should report `healthy`. The `migrate` service exits after applying migrations, so it is not listed as `Up`. To run it manually: `docker compose run --rm migrate`.

### 4. Create the admin account

```bash
docker exec -it asm_backend python3 -m backend.scripts.create_admin
```

### 5. Sign in

Open `http://<host>:3000` (use `localhost` when Docker runs on your machine).

---

## Configuration

Set these in `.env.docker`. Only the first two are required.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | none | SQLAlchemy connection string |
| `SECRET_KEY` | none | JWT signing key (required) |
| `ASM_ALLOW_PRIVATE_TARGETS` | `false` | Permit scanning private/reserved addresses (lab use) |
| `NVD_API_KEY` | unset | NVD API key for higher CVE lookup rate limits |
| `CVE_MIN_CVSS` | `7.0` | Minimum CVSS for version-matched CVE findings |
| `ASM_RATE_MULTIPLIER` | `1` | Scales per-target request rates for all tools |
| `ASM_PARALLEL_STAGES` | `true` | Run independent web stages in parallel |
| `DIRBUSTER_MAX_SECONDS` | `900` | Upper bound for directory discovery per scan |
| `NUCLEI_TIMEOUT` | `1800` | Upper bound for a nuclei run, in seconds |
| `NUCLEI_CONCURRENCY` | `15` | Nuclei template concurrency |
| `ASM_LLM_PROVIDER` | `none` | AI triage: `none`, `ollama` or `mock`. See `ASM_LLM_*` in `.env.docker.example` |
| `ASM_REPORT_CACHE_DIR` | `/app/scan_output/reports` | Where rendered PDF reports are cached |

---

## Usage

| Step | Action |
|---|---|
| **Targets** | *Add Target* with domain, authorizer and rate limit. The authorization box is mandatory and enforced server-side. |
| **Scans** | Pick a profile and click *Scan*. Watch per-stage progress; cancel at any time. |
| **Assets** | Open ports, technologies, HTTP metadata, discovered paths and risk score. |
| **Infrastructure** | Per-target WHOIS/ASN data, tech stack and TLS findings. |
| **Vulnerabilities** | Template findings and TLS issues with severity, CVE and CVSS. |
| **Alerts** | New, changed and disappeared asset alerts; mark read individually or in bulk. |
| **Schedules** | Recurring scans by cron expression or preset interval. |
| **Reports** | Download the PDF or CSV export from any completed scan. |

---

## API

Interactive documentation is served by FastAPI at `http://<host>:8000/docs`. All routes except login require a bearer token.

| Area | Endpoints |
|---|---|
| Auth | `/auth/*` |
| Targets and scans | `/targets/*`, `/scans/*` (including `/scans/profiles`) |
| Assets and vulnerabilities | `/assets/*`, `/vulnerabilities/*` |
| Alerts and schedules | `/alerts/*`, `/schedules/*` |
| Changes | `GET /changes/`, `GET /changes/scans/{scan_id}` |
| Audit | `/audit/*` |

`GET /changes/` supports filters: `target_id`, `scan_id`, `severity` (comma-separated), `category`, `confidence`, `status` and pagination.

---

## Scanning private and lab targets

Public enumeration sources cannot see private hostnames. The pipeline always scans the apex target, but the scanner container must be able to resolve it. For IP targets, set `ASM_ALLOW_PRIVATE_TARGETS=true`. For names that only resolve through your host, add an entry to the `backend` and `celery_worker` services:

```yaml
    extra_hosts:
      - "your-lab-host.local:192.168.x.x"
```

`extra_hosts` is applied at container creation, so recreate the containers:

```bash
docker compose up -d --force-recreate backend celery_worker
```

---

## Development

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r backend/requirements-dev.txt
pytest
```

The test suite runs against in-memory SQLite and mocked scanners; no Docker, Redis or network access is required.

| Change | How to apply |
|---|---|
| Backend code (`backend/`) | The API reloads automatically. Run `docker compose restart celery_worker` for worker changes, and never mid-scan. |
| Frontend code | `docker compose build frontend && docker compose up -d frontend` |
| Database models | Add an Alembic revision in `backend/migrations/versions/`; the `migrate` service applies it on start. |

---

## Backup and restore

`docker compose down -v` permanently deletes all data. Back up first:

```bash
docker exec asm_postgres pg_dump -U asm_user -F c -d asm_db -f /tmp/backup.dump
docker cp asm_postgres:/tmp/backup.dump ./backups/asm_db_$(date +%Y%m%d).dump
```

Restore:

```bash
docker cp ./backups/asm_db_YYYYMMDD.dump asm_postgres:/tmp/restore.dump
docker exec asm_postgres pg_restore -U asm_user -d asm_db --clean --if-exists -v /tmp/restore.dump
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Port 5432 / 6379 already in use | Native Postgres or Redis on the host | Stop and disable the host services |
| `asm_postgres` restart-looping with a mount error | Postgres 18 expects `/var/lib/postgresql` | Keep the volume path used in `docker-compose.yml` |
| CORS error in the browser | Frontend origin not allowed by the backend | Add the host to `allow_origins` in `backend/main.py` |
| 401 with correct credentials | `users` table is empty (usually after `down -v`) | Re-run `create_admin` |
| Scan stuck on `pending` | A non-Docker Celery worker consumed the task | Stop any host-level `celery` process |
| `redis.exceptions.ResponseError: MISCONF` | Disk full, Redis cannot persist | Free space (`docker image prune -a`, `docker builder prune`) and restart |
| Scanner tool "not found" | Binary missing from the image | `docker exec asm_celery_worker which <tool>`; fix the Dockerfile |
| Worker ignores code changes | No auto-reload on the worker | `docker compose restart celery_worker` |
| Frontend changes not visible | Static bundle served by nginx | Rebuild the `frontend` image and hard-refresh |
| Services on unusual ports are missing | Quick/Standard scan only the top 100/1000 ports | Run a Deep scan |

---

## Roadmap

| Area | Status |
|---|---|
| Historical diff engine, change events API | Done |
| CVE roll-up: one line per component and host with "N of M" (report, vulnerabilities API and page, changes API) | Done |
| Changes page in the UI | Done |
| Alerts and webhooks driven by change events (backend, settings API, delivery log) | Done |
| Alerts page and per-target notification settings in the UI | Done |
| Per-port path tracking (paths keyed by host and port) | Done |
| AI-assisted triage: severity, summary and recommended action per change, with guardrails and a labelled evaluation set | Wired in; model evaluation in progress |
| Leak and breach collectors (HIBP, GitHub code search, paste sites) | Planned |
| Dark-web mention monitoring via licensed intelligence APIs | Planned |
| Screenshot perceptual-hash diffing | Planned |
| Report delivery: scheduled PDF, Slack/email notifications for high and critical changes | Planned |
| Container hardening (non-root, pinned dependencies, healthchecks, production compose without bind mounts) | Planned |
| Role-based access (viewer vs admin) on mutating routes | Planned |
| Login throttling per IP and per username, constant-time unknown-user path | Planned |
| Scan watchdog: overall runtime limit (`SCAN_MAX_SECONDS`, default 6h) and a beat-driven reaper for scans stuck in running or pending | Done |
| One active scan per target, enforced by a partial unique index (migration 0008) | Done |
| Pagination on list endpoints; uniqueness constraints on assets | Planned |
| Schedule safety rails: 5-field cron only, minimum interval (`SCHEDULE_MIN_INTERVAL_SECONDS`, default 1h), active-target check, audit entries | Done |

---

## Known limitations

- **Single operator model.** There is no self-service registration or multi-user management; the admin account is script-created.
- **CVE matching is version-based.** At most 15 CVEs are kept per service (highest risk first); the report says when a list was capped. It depends on the version a service reports. Services without a banner version produce no matches, and matches are marked *inferred* until verified.
- **Profile blind spots.** Quick and Standard do not see services outside their port lists (top 100, and top 1000 plus a curated extras list).
- **Network service checks can be starved.** Some services (an old OpenSSH, for instance) answer the banner but stall on the deeper protocol handshakes the nuclei network templates perform. The scanner detects this (per-template timeouts), retries the affected templates gently, and if they still fail marks the host `low coverage`: removals there are held as pending and never reported as fixed. Root-causing a stalling service is left to the operator.
- **Time-boxed stages.** Nuclei and directory discovery stop at their time budget; collected results are kept and the stage is reported as `partial`.
- **TLS findings are not de-duplicated across scans**; recurring issues add rows on every scan.
- **Earlier alerts.** Alerts created before change-event alerting came from asset state and could report scan noise; they are kept, shown in a collapsed group on the Alerts page, and no new ones are written.
- **Webhook delivery resolves DNS twice** (once to validate, once to send), so a hostile DNS server could in theory switch addresses in between. Pinning the resolved address is on the hardening list.

---

## Scope and responsible use

ASM is built for authorized security assessments only. Scan assets you own or have explicit written permission to test. The authorization gate is a technical safeguard, not a substitute for legal authorization.

## License

MIT

---

Medium Writeup for more detailed understanding :https://medium.com/@PranavVerma/asm-a-self-hosted-attack-surface-management-platform-and-a-postmortem-on-the-bug-that-took-four-452444338968

<img width="1919" height="844" alt="image" src="https://github.com/user-attachments/assets/00e9a39f-ea7c-407f-9c53-bbac324f65b6" />
<img width="1919" height="868" alt="image" src="https://github.com/user-attachments/assets/1bccaf6a-05a7-4225-b38b-28fd8d17cc8e" />
<img width="1916" height="868" alt="image" src="https://github.com/user-attachments/assets/35fb8c84-c2b8-4d0f-8e8c-f3a1e562d80e" />
<img width="1913" height="862" alt="image" src="https://github.com/user-attachments/assets/aab178d2-eee9-4441-9b82-f876c45ae3a0" />
<img width="1911" height="871" alt="image" src="https://github.com/user-attachments/assets/421fd757-9b82-4ad3-a9bc-2c03633a1ca7" />

Here is the Sample Industry Grade Report that you can get for every scan :
[asm_report_scan_91.pdf](https://github.com/user-attachments/files/30161571/asm_report_scan_91.pdf)


