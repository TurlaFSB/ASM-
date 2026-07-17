## ASM(Attack Surface Machine)

A self-hosted Attack Surface Management (ASM) platform for continuous external reconnaissance, vulnerability scanning, and change detection — built for authorized security teams who need to know what's exposed, what changed, and what's actually exploitable.

Point it at a domain. It enumerates subdomains, resolves DNS, scans ports, probes HTTP services, runs vulnerability templates, and captures screenshots — then tracks every asset over time and alerts the moment something new, changed, or disappeared.

![Stack](https://img.shields.io/badge/stack-FastAPI%20%7C%20PostgreSQL%20%7C%20Celery%20%7C%20React-9b5de5)
![License](https://img.shields.io/badge/license-MIT-informational)

---

## Table of Contents

- [Why this exists](#why-this-exists)
- [Architecture](#architecture)
- [Features](#features)
- [Security posture](#security-posture)
- [Installation](#installation)
- [Usage guide](#usage-guide)
- [Scanning private / lab-only targets](#scanning-private--lab-only-targets)
- [Backup & restore](#backup--restore)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Scope & responsible use](#scope--responsible-use)

---

## Why this exists

Most ASM tooling is either a paid SaaS product or a loose collection of scripts glued together with cron. This project is a single, self-hosted platform that runs the full recon-to-report pipeline, keeps a point-in-time history of every scan, and scores risk using real-world exploitation data (CISA KEV) instead of raw CVSS alone — so a Critical finding actually means something is being exploited in the wild, not just that it scored high on paper.

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
                ┌───────────────────────────────┐
                │ Scanner Pipeline (Sequential) │
                │                               │
                │ Subfinder → Amass → DNS       │
                │ → Nmap → httpx → Nuclei       │
                │ → EyeWitness                  │
                └───────────────────────────────┘
```
Every scan runs as a single Celery task, updating scan state at each stage so the frontend can show live progress. Results are diffed against the previous scan's asset state on save — that diff is what drives alerts and webhook delivery.

---

## Features

### Recon & scanning
- Subdomain enumeration via Subfinder + Amass, with the apex domain always included as a candidate even when both tools return nothing (covers private/lab-only targets)
- DNS resolution, Nmap port scanning, httpx HTTP probing, Nuclei vulnerability scanning, EyeWitness screenshot capture — run sequentially per scan with per-stage timing and status recorded
- Live scan progress in the UI, polling actual Celery task state
- Real scan cancellation — sends SIGTERM to the running Celery task, not just a DB status flag

### Detection & alerting
- Content-hash based change detection (ports, technologies, HTTP status/title) — flags assets as **new**, **changed**, or **disappeared** on every scan
- Point-in-time scan/asset snapshotting, so historical scan reports stay accurate even as an asset's current state changes
- Webhook alert delivery per target, with delivery status tracked and failure isolation (a webhook outage never breaks the scan pipeline)
- Alert list filterable by target and alert type, paginated

### Risk & reporting
- Per-asset risk scoring: CVSS-driven baseline, boosted for high-risk open ports (databases, RDP, WinRM, Telnet, FTP) and admin-surface keywords, and force-escalated to Critical if any matched CVE is in **CISA's Known Exploited Vulnerabilities (KEV) catalog** — because a Critical CVSS score with no real-world exploitation is a different risk than one actively being used in attacks
- Client-ready PDF reports: executive summary, asset inventory, findings with CVE links, change detection, and severity-tiered remediation SLAs (24-48h for Critical, 7 days for High, etc.)
- CSV export for assets and vulnerabilities

### Operations
- Scheduled recurring scans via Celery Beat — cron expressions or hourly/daily/weekly presets, full create/update/toggle/delete
- JWT-authenticated API, every route protected, admin bootstrapped via a setup script (no hardcoded credentials anywhere in the codebase)
- Audit log covering target creation/deletion and scan trigger/cancel/completion/failure, with IP address attribution on user-initiated actions
- Docker Compose deployment — one command, six services, healthchecked dependencies

---

## Security posture

This is a tool that performs active scanning, so its own security matters. Specifics:

- **Authorization gate enforced at the API layer, not just the UI.** A target cannot be created without `authorized: true`, and a scan cannot be triggered against an unauthorized or deactivated target — checked again at trigger time, not just at target creation.
- **No hardcoded credentials.** The admin account is created interactively via `backend/scripts/create_admin.py`, which hides password input and hashes it with bcrypt before it ever touches the database.
- **JWT auth on every route**, with active-status re-checked on every request (not just at login) — deactivating a user takes effect immediately, not just for future logins.
- **Domain input validation** — regex-enforced hostname format, length caps, and a bounded rate-limit field (1-100 req/s) to prevent misconfigured scans from becoming unintentional DoS traffic.
- **Audit trail** for all destructive/sensitive actions (target create/delete, scan trigger/cancel), including source IP.
- **Secrets are gitignored** (`.env`, `.env.docker`) and never committed; `SECRET_KEY` has no default, so the app refuses to start without one being explicitly set.

---

## Installation

### Requirements

- Docker Engine 24+ and Docker Compose v2
- 4 GB+ RAM available to Docker
- **15-20 GB+ free disk space.** Docker images, build cache, and scan artifacts (screenshots, PDF reports) accumulate with use — running low on disk causes Redis write failures and silent scan crashes with no obvious error in the UI.
- Ports `3000`, `8000`, `5432`, `6379` free on the host

### Step 1 — Clone the repository

```bash
git clone https://github.com/TurlaFSB/ASM-.git
cd ASM-
```

### Step 2 — Configure secrets

```bash
cp .env.docker.example .env.docker
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)" > .env
```

Open `.env.docker` and set:
DATABASE_URL=postgresql+psycopg://asm_user:<same password as .env>@postgres:5432/asm_db
SECRET_KEY=<generate with: openssl rand -hex 32>

`.env` and `.env.docker` are gitignored — never commit real secrets.

### Step 3 — Build and start the stack

```bash
docker compose up -d --build
docker compose ps
```

Confirm all six services are `Up`, with `postgres` and `redis` showing `(healthy)`:
NAME                 STATUS
asm_backend          Up
asm_celery_beat      Up
asm_celery_worker    Up
asm_frontend         Up
asm_postgres         Up (healthy)
asm_redis            Up (healthy)

### Step 4 — Create your admin account

```bash
docker exec -it asm_backend python3 -m backend.scripts.create_admin
```

Follow the interactive prompt — username, password (hidden input), confirmation.

### Step 5 — Log in
http://<host-ip>:3000

Use `localhost` if Docker is running directly on your machine, or the host's LAN/VM IP if accessing from another device.

---

## Usage guide

1. **Targets** → click *Add Target*, enter the domain, who authorized it, and a rate limit (requests/sec). Check the authorization confirmation box — the request is rejected server-side without it.
2. **Scans** → click *Scan* next to a target to launch it. Watch live progress in the Scans table; cancel anytime with the Cancel button.
3. **Assets** → populated as each scan completes, showing open ports, detected technologies, HTTP metadata, and risk score.
4. **Vulnerabilities** → Nuclei findings with severity, CVE, and CVSS score where available.
5. **Alerts** → every new/changed/disappeared asset generates an alert here; mark as read individually or in bulk.
6. **Schedules** → set up recurring scans (cron or preset interval) so targets get re-checked automatically without manual triggering.
7. **Reports** → download a PDF or CSV export from a completed scan for client delivery or record-keeping.

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
| Scan stuck on `pending` forever | A second Celery worker (native, outside Docker) grabbed the task | `ps aux \| grep celery` on the host — kill any non-Docker worker process; only the Docker `celery_worker` service should be running |
| Scan crashes with `redis.exceptions.ResponseError: MISCONF` | Host disk is full — Redis can't write its snapshot | `df -h`, free space with `docker image prune -a` / `docker builder prune`, then restart affected containers |
| Task fails with `ModuleNotFoundError` | A scanner dependency isn't in `requirements.txt` | Add the missing package, `docker compose up -d --build backend celery_worker` |
| Task fails with a scanner tool "not found" | Binary name mismatch between scanner code and the installed tool | `docker exec -it asm_celery_worker which <tool-name>` — symlink or fix the Dockerfile install step to match |

---

## Known limitations

- **No Alembic migrations yet** — schema changes are applied via direct SQL or `Base.metadata.create_all()` on startup. Fine for single-instance lab use; not suitable for a team environment without setting this up properly first.
- **No self-service registration** — admin account creation is script-only, by design, for a single-operator deployment.
- **Not yet implemented:** SSL/TLS analysis, WhatWeb integration, WHOIS/ASN lookup, directory/content discovery (ffuf/gobuster), screenshot diffing on rescan.

---

## Scope & responsible use

Built for authorized security assessments only. Scan assets you own or have explicit written permission to test. The authorization gate in this platform is a technical safeguard, not a substitute for actual legal authorization.

## License
MIT 
