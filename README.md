<div align="center">

# ASM
### Self-Hosted Attack Surface Management

Continuous external recon, vulnerability scanning, TLS auditing, and change detection — for teams who need to know what's exposed, what changed, and what's actually exploitable.

![Stack](https://img.shields.io/badge/stack-FastAPI%20%7C%20PostgreSQL%20%7C%20Celery%20%7C%20React-9b5de5)
![License](https://img.shields.io/badge/license-MIT-informational)
![Status](https://img.shields.io/badge/status-active%20development-brightgreen)

</div>

---

Point ASM at a domain. It enumerates subdomains, resolves DNS, pulls WHOIS/ASN ownership data, scans ports, probes HTTP services, fingerprints the technology stack, runs vulnerability templates, audits TLS/SSL configuration, and captures screenshots. Every run is diffed against the last one, so you're never re-reading a static report  you're watching your attack surface change over time.

Most ASM tooling is either an expensive SaaS subscription or a pile of scripts held together with cron. ASM is neither: it's one self-hosted platform that runs the full recon-to-report pipeline, keeps point-in-time history of every scan, and scores risk against **CISA's Known Exploited Vulnerabilities (KEV) catalog** — so a Critical finding means something is being actively exploited in the wild, not just that it scored high on paper.

## Who it's for

| | |
|---|---|
| **VAPT / pentest teams** | A repeatable recon baseline before manual testing begins — subdomains, ports, tech stack, and TLS state captured and diffable across every engagement. |
| **Red teams** | Full target profiles in one place — WHOIS/ASN ownership, live tech stack, exposed service inventory — instead of stitching together five tool outputs by hand. |
| **Students & self-learners** | A real, working ASM pipeline to study and extend — a multi-service system with a scan queue, a database, and a report generator, not a toy script. |
| **Freelance consultants / small teams** | Client-ready PDF reports without a SaaS subscription, plus scan history and change alerts for ongoing retainer-style monitoring. |

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Security posture](#security-posture)
- [Installation](#installation)
- [Usage guide](#usage-guide)
- [Scanning private / lab-only targets](#scanning-private--lab-only-targets)
- [Backup & restore](#backup--restore)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Known limitations](#known-limitations)
- [Scope & responsible use](#scope--responsible-use)

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
        ┌───────────────────────────────────────────┐
        │           Scanner Pipeline (Sequential)     │
        │                                              │
        │  Subfinder → Amass → DNS → WHOIS/ASN        │
        │  → Nmap → httpx → WhatWeb → Nuclei          │
        │  → sslyze → EyeWitness                       │
        └───────────────────────────────────────────┘
```

Every scan runs as a single Celery task, updating scan state at each stage so the frontend can show live progress. Results are diffed against the previous scan's asset state on save — that diff is what drives alerts and webhook delivery.

---

## Features

### Reconnaissance
- Subdomain enumeration via **Subfinder + Amass**, with the apex domain always included as a candidate even when both tools return nothing — covers private, lab-only targets that public sources can't see
- **WHOIS & ASN lookup** — registrar, creation/expiration dates, name servers, and network ownership (ASN, CIDR block, organization) for every target
- DNS resolution, **Nmap** port scanning, **httpx** HTTP probing with redirect following
- **WhatWeb** technology fingerprinting — identifies CMSes, frameworks, web servers, and JS libraries across every live asset, merged with httpx's own tech detection and deduplicated
- **EyeWitness** screenshot capture on every scan

### Vulnerability & TLS analysis
- **Nuclei** template-based vulnerability scanning
- **sslyze**-powered TLS/SSL auditing on every scan — deprecated protocol support (SSLv2/3, TLS 1.0/1.1), weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, MD5), expired certificates, SHA-1 chain signatures, and Heartbleed exposure, per host
- TLS findings feed into the same severity pipeline as Nuclei results — one findings table, one report, no separate workflow

### Change detection & alerting
- Content-hash based diffing (ports, technologies, HTTP status/title) — flags assets as **new**, **changed**, or **disappeared** on every scan
- Point-in-time scan/asset snapshotting, so historical reports stay accurate even as an asset's current state changes
- Webhook alert delivery per target, with delivery status tracked and failure isolation — a webhook outage never breaks the scan pipeline
- Alert list filterable by target and alert type, paginated

### Infrastructure visibility
- A combined **Infrastructure** view per target — WHOIS/ASN ownership, fingerprinted tech stack, and TLS findings in one expandable card in the UI, and as a dedicated section in every generated PDF

### Risk & reporting
- Per-asset risk scoring: CVSS-driven baseline, boosted for high-risk open ports (databases, RDP, WinRM, Telnet, FTP) and admin-surface keywords, force-escalated to Critical if any matched CVE is in **CISA's KEV catalog**
- Client-ready **PDF reports** — executive summary, asset inventory, infrastructure section, vulnerability findings with CVE links, change detection, and severity-tiered remediation SLAs (24-48h Critical, 7 days High, and so on)
- CSV export for assets and vulnerabilities

### Operations
- Scheduled recurring scans via **Celery Beat** — cron expressions or hourly/daily/weekly presets, full create/update/toggle/delete
- **JWT auth** on every route, admin bootstrapped via a setup script — no hardcoded credentials anywhere in the codebase
- Audit log covering target creation/deletion and scan trigger/cancel/completion/failure, with IP attribution
- **Docker Compose** deployment — one command, six services, healthchecked dependencies

---

## Security posture

This is a tool that performs active scanning, so its own security matters.

- **Authorization gate enforced at the API layer, not just the UI.** A target cannot be created without `authorized: true`, and a scan cannot be triggered against an unauthorized or deactivated target — checked again at trigger time, not just at creation.
- **No hardcoded credentials.** The admin account is created interactively via `backend/scripts/create_admin.py`, which hides password input and hashes it with bcrypt before it touches the database.
- **JWT auth on every route**, with active-status re-checked on every request — deactivating a user takes effect immediately, not just for future logins.
- **Domain input validation** — regex-enforced hostname format, length caps, and a bounded rate-limit field (1-100 req/s) so a misconfigured scan can't become unintentional DoS traffic.
- **Audit trail** for all destructive/sensitive actions, including source IP.
- **Secrets are gitignored** (`.env`, `.env.docker`) and never committed; `SECRET_KEY` has no default — the app refuses to start without one explicitly set.

---

## Installation

### Requirements

| | |
|---|---|
| Docker | Engine 24+ and Compose v2 |
| RAM | 4 GB+ available to Docker |
| Disk | 15-20 GB+ free — scan artifacts (screenshots, PDFs) accumulate with use; running low causes Redis write failures and silent scan crashes with no obvious UI error |
| Ports | `3000`, `8000`, `5432`, `6379` free on the host |

### 1. Clone the repository

```bash
git clone https://github.com/TurlaFSB/ASM-.git
cd ASM-
```

### 2. Configure secrets

```bash
cp .env.docker.example .env.docker
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)" > .env
```

Open `.env.docker` and set:

```env
DATABASE_URL=postgresql+psycopg://asm_user:<same password as .env>@postgres:5432/asm_db
SECRET_KEY=<generate with: openssl rand -hex 32>
```

`.env` and `.env.docker` are gitignored — never commit real secrets.

### 3. Build and start the stack

```bash
docker compose up -d --build
docker compose ps
```

Confirm all six services are `Up`, with `postgres` and `redis` showing `(healthy)`:

```
NAME                 STATUS
asm_backend          Up
asm_celery_beat      Up
asm_celery_worker    Up
asm_frontend         Up
asm_postgres         Up (healthy)
asm_redis            Up (healthy)
```

### 4. Create your admin account

```bash
docker exec -it asm_backend python3 -m backend.scripts.create_admin
```

Follow the interactive prompt — username, password (hidden input), confirmation.

### 5. Log in

```
http://<host-ip>:3000
```

Use `localhost` if Docker runs directly on your machine, or the host's LAN/VM IP if accessing from another device.

---

## Usage guide

| Step | What to do |
|---|---|
| **1. Targets** | Click *Add Target* — domain, who authorized it, rate limit (req/s). Check the authorization confirmation box; the request is rejected server-side without it. |
| **2. Scans** | Click *Scan* next to a target. Watch live progress in the Scans table; cancel anytime. |
| **3. Assets** | Populated as each scan completes — open ports, detected technologies, HTTP metadata, risk score. |
| **4. Infrastructure** | Expand this on any target for WHOIS/ASN data, the fingerprinted tech stack, and TLS/SSL findings in one view. |
| **5. Vulnerabilities** | Nuclei findings and TLS/SSL misconfigurations, with severity, CVE, and CVSS score where available. |
| **6. Alerts** | Every new/changed/disappeared asset generates an alert; mark read individually or in bulk. |
| **7. Schedules** | Set up recurring scans (cron or preset interval) so targets get re-checked automatically. |
| **8. Reports** | Download a PDF or CSV export from a completed scan. The PDF includes a dedicated Infrastructure section. |

---

## Scanning private / lab-only targets

Subfinder and Amass query public DNS and certificate transparency logs — they cannot discover a private, lab-only hostname like a local Metasploitable VM. The pipeline always includes the apex domain as a scan candidate regardless of what these tools find, but the scanning container still needs to be able to **resolve** that hostname.

If your lab target only resolves via your host's `/etc/hosts`, add a matching entry to the `backend` and `celery_worker` services in `docker-compose.yml`:

```yaml
    extra_hosts:
      - "your-lab-host.local:192.168.x.x"
```

Then recreate the containers — a plain rebuild isn't enough, since `extra_hosts` is applied at container-creation time:

```bash
docker compose up -d --force-recreate backend celery_worker
```

---

## Backup & restore

`docker compose down -v` deletes all data permanently. Back up before doing anything destructive:

```bash
docker exec -it asm_postgres pg_dump -U asm_user -F c -d asm_db -f /tmp/backup.dump
docker cp asm_postgres:/tmp/backup.dump ./backups/asm_db_$(date +%Y%m%d).dump
```

Restore:

```bash
docker cp ./backups/asm_db_YYYYMMDD.dump asm_postgres:/tmp/restore.dump
docker exec -it asm_postgres pg_restore -U asm_user -d asm_db --clean --if-exists -v /tmp/restore.dump
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Port 5432 / 6379 already in use | Native Postgres/Redis running on host | `sudo systemctl stop postgresql redis-server && sudo systemctl disable postgresql redis-server` |
| `asm_postgres` restart-looping, mount error | Postgres 18 image needs `/var/lib/postgresql`, not `/var/lib/postgresql/data` | Already fixed in this repo's `docker-compose.yml` — don't revert the volume path |
| CORS error in browser console | Frontend origin not in backend's allow-list | Add your host IP to `allow_origins` in `backend/main.py` |
| 401 on login with correct credentials | `users` table empty (usually after `down -v`) | Recreate admin: `docker exec -it asm_backend python3 -m backend.scripts.create_admin` |
| Scan stuck on `pending` forever | A second Celery worker (native, outside Docker) grabbed the task | `ps aux \| grep celery` on the host — kill any non-Docker worker; only the Docker `celery_worker` service should run |
| Scan crashes with `redis.exceptions.ResponseError: MISCONF` | Host disk is full — Redis can't write its snapshot | `df -h`, free space with `docker image prune -a` / `docker builder prune`, restart affected containers |
| Task fails with `ModuleNotFoundError` | A scanner dependency isn't in `requirements.txt` | Add the missing package, `docker compose up -d --build backend celery_worker` |
| Task fails with a scanner tool "not found" | Binary name mismatch between scanner code and the installed tool | `docker exec -it asm_celery_worker which <tool-name>` — fix the Dockerfile install step to match |
| Frontend changes don't appear after editing source | Frontend is a multi-stage Docker build serving a static bundle via nginx — not a live dev server | `docker compose build frontend && docker compose up -d frontend`, then hard-refresh the browser |
| `celery_worker` doesn't pick up backend code changes | No auto-reload on `celery_worker`, unlike the backend's `--reload` uvicorn process | `docker compose restart celery_worker` after editing `backend/tasks.py` or any scanner module |

---

## Roadmap

Planned additions to the scanner pipeline, in build order:

| # | Module | What it adds |
|---|---|---|
| 10 | **Directory / content discovery** (ffuf / gobuster / feroxbuster) | Hidden path and endpoint enumeration per host. Needs wordlist management and a rate-limit hookup into the existing `Target.rate_limit` field, feeding into the same Celery progress tracking every other stage already uses. |
| 11 | **Screenshot diff on rescan** | Pixel/perceptual-hash comparison against stored EyeWitness screenshots from the previous scan, to flag visually significant page changes. Needs a tuned "meaningful change" threshold so routine content (ads, timestamps, carousels) doesn't trigger false positives. |

---

## Known limitations

- **No Alembic migrations yet** — schema changes are applied via direct SQL or `Base.metadata.create_all()` on startup. Fine for single-instance lab use; not suitable for a team environment without setting this up properly first.
- **No self-service registration** — admin account creation is script-only, by design, for a single-operator deployment.
- **TLS/SSL findings are not deduplicated on rescan** — each scan cycle re-inserts findings rather than upserting, so recurring TLS issues accumulate as duplicate rows over repeated scans.
- **Nuclei stage can time out on larger targets** — the vulnerability scanning stage has a hard timeout and reports zero findings if it doesn't complete in time, rather than returning partial results.
- **Directory/content discovery and screenshot diffing are not yet implemented** — see [Roadmap](#roadmap).

---

## Scope & responsible use

Built for authorized security assessments only. Scan assets you own or have explicit written permission to test. The authorization gate in this platform is a technical safeguard, not a substitute for actual legal authorization.

## License

MIT
Medium Writeup for more detailed understanding :https://medium.com/@PranavVerma/asm-a-self-hosted-attack-surface-management-platform-and-a-postmortem-on-the-bug-that-took-four-452444338968
<img width="1919" height="844" alt="image" src="https://github.com/user-attachments/assets/00e9a39f-ea7c-407f-9c53-bbac324f65b6" />
<img width="1919" height="868" alt="image" src="https://github.com/user-attachments/assets/1bccaf6a-05a7-4225-b38b-28fd8d17cc8e" />
<img width="1916" height="868" alt="image" src="https://github.com/user-attachments/assets/35fb8c84-c2b8-4d0f-8e8c-f3a1e562d80e" />
<img width="1913" height="862" alt="image" src="https://github.com/user-attachments/assets/aab178d2-eee9-4441-9b82-f876c45ae3a0" />
<img width="1911" height="871" alt="image" src="https://github.com/user-attachments/assets/421fd757-9b82-4ad3-a9bc-2c03633a1ca7" />

Here is the Sample Industry Grade Report that you can get for every scan :
[asm_report_scan_91.pdf](https://github.com/user-attachments/files/30161571/asm_report_scan_91.pdf)


