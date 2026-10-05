# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- **`cryptography` upgraded to 50.x**, clearing four published advisories (a bundled OpenSSL issue, PKCS#7 decryption leak, and two X.509 verifier issues) that were previously accepted. `sslyze` caps `cryptography` below 47 in its metadata, so it is now installed separately without dependency resolution (`requirements-sslyze.txt`). A new test runs a real TLS scan with the combination in CI.

- **Login throttle counters can no longer get stuck.** A counter is now created together with its 15-minute expiry. Before, a crash between the two Redis calls could leave one with no expiry and lock that user or address out permanently.

### Fixed
- **amass results were always discarded.** amass 4.x prints a relationship graph (`name (FQDN) --> a_record --> ip`), not bare names, and the parser dropped every line, so amass contributed nothing to any scan. It now reads the names from the graph. Its normal run takes about 110 s (the `-timeout 1` flag only limits the gathering phase), so the default `ASM_AMASS_TIMEOUT` is 150 s instead of 90, which raced with normal completion.

### Changed
- **Public-bucket findings are no longer rated high.** The bucket name is a guess, so a hit is now *medium*, or *info* when the domain label is short or a common word (a bucket called `example-files` says nothing about `example.com`).
- Profile time estimates now match measurements: Quick about 2-3 minutes, Standard about 10-12 (directory discovery is most of it).
- The change-detection note for a skipped section now says that absence is not treated as fixed, instead of the misleading "did not run cleanly".
- **Redis keeps its data across restarts** (append-only file, one-second fsync, named `redis_data` volume, `noeviction`). Before, `docker compose down` or a Redis crash dropped the task queue (queued scans sat in the list for up to 12 hours) and every scan lock (running scans were failed by the watchdog while still working). A test restarts a real Redis and checks the queue and locks come back.
- **Subdomain tools are bounded and reported precisely.** amass now stops after `ASM_AMASS_TIMEOUT` seconds (default 150) and can be switched off with `ASM_AMASS_ENABLED=false`; before, a hung amass added two and a half minutes to every scan. Tool status now says `ok`, `empty`, `timeout`, `not installed` or `failed` instead of calling every non-result `empty`.
- The production worker container has a memory cap (`ASM_WORKER_MEM_LIMIT`, default `4g`). A scan peaks near 2 GiB.

### Fixed
- **Deleting a target now stops everything for it**: its schedules are paused (and hidden), and a scan that is queued or running is cancelled. Before, a scan kept running and schedules stayed armed.
- **Resuming a paused schedule** waits for its next time slot instead of firing at once for a time that passed while it was paused. The Schedules switch now sets the state explicitly, so a double click can no longer undo itself.
- **Saving notification settings with only some fields** (for example just the email recipients) no longer resets the alert threshold and webhook format to their defaults.
- **Nuclei did not run in the production overlay.** Its template lookup depends on a config file that is empty in a read-only container, so it looked in `/app/nuclei-templates` and scanned nothing. The scanner now passes the installed template folder explicitly.
- **Zombie `chromium` processes** piled up in the worker after screenshot stages. The backend, worker and beat containers now run with a minimal init that reaps them.

### Added
- **Restore drill and restore script** (`deploy/restore.sh`): `verify` checks the checksum, restores a backup into a scratch database, compares tables and the schema revision, then drops the scratch database without touching live data; `apply` replaces the live database in one transaction, so a failed restore changes nothing.
- **Posture checks** in every scan: subdomain takeover (dangling CNAMEs and unclaimed GitHub Pages, Azure, Heroku, S3, Shopify and similar), email security (SPF, DMARC, DKIM key strength, MTA-STS), public cloud storage listings (S3, GCS, Azure Blob) named after the domain, and exposed `.git`, `.env`, backup, credential and debug files confirmed by content. Quick runs the two DNS-only checks. Findings flow through change detection with their own coverage, so a check that could not run never reports something as fixed.
- **Screenshot viewing**: a gallery of the pictures taken during a scan, opened from the scan's menu on the Scans page. Pictures are matched to their host, served only to signed-in users, and removed with the retention cleanup.
- **Target tags**: label targets (up to 10 each), edit them from the row menu, and filter the Targets list by tag. `GET /targets/?tag=` filters through the API.
- **Email notifications**: one digest email per scan and per exposure run to up to 10 recipients per target, with the same severity threshold as webhooks. Set up with `ASM_SMTP_*`; deliveries show on the Alerts page.
- **Scheduled database backups** (`docker-compose.backup.yml`): daily verified dumps with checksums and retention.
- **API tokens** for scripts and CI (Account page): read-only or full access, optional expiry, shown once, stored as a hash, revoked automatically when the password changes or is reset.
- JSON and SARIF 2.1.0 finding exports, and an export menu on the Scans page (CSV, JSON, SARIF).
- Frontend component tests (Vitest) run in CI.
- `GET /metrics` (Prometheus format, admin only) and `ASM_LOG_FORMAT=json` structured logs.

## [0.2.0] - 2026-10-04

### Added
- **Finding triage**: mark findings, components or CVEs as In progress, False positive, Accepted risk (expires, default 90 days) or Resolved, with a required reason for the first two. Triaged findings are excluded from counts, PDF reports and CSV rows keep their triage status.
- **Accounts and sessions**: admin Users page, password change, first-run setup screen guarded by a code printed in the backend log, and real sign-out (token revocation; password changes sign a user out everywhere).
- **Exposure monitoring**: GitHub code, breach records, lookalike domains, ransomware listings and infostealer counts, for public domain targets.
- **Tamper-evident scan history**: signed, chained seals per scan.
- Global API rate limit (`API_RATE_LIMIT_PER_MINUTE`), data retention job (`ASM_RETENTION_DAYS`), HTTPS overlay with Caddy (`docker-compose.tls.yml`).
- CI: CodeQL, Trivy image scans and secret scanning.

### Changed
- The frontend image runs as an unprivileged nginx on port 8080 and builds on Node 22 LTS.
- The scan pipeline is split into small, tested stages (`backend/pipeline_stages.py`); backend test coverage is now 87%.
- The web app talks to the API over the same scheme as the page.

### Fixed
- EyeWitness failing in the read-only production overlay (each run now writes to its own folder).
- Exposure switches and the Targets scan button giving no feedback or flickering other controls.
- Missing CSRF cookie leaving the UI unable to save changes.

### Removed
- Unused `ScrollHint` component.

## [0.1.0]

Initial release: scan pipeline (subdomains, DNS, WHOIS/ASN, ports, HTTP, technologies, directories, Nuclei, TLS, screenshots), change detection, alerts and webhooks, PDF reports, scan profiles, schedules, role-based access.
