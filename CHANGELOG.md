# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-10-10

The first published release since 0.2.0; it includes everything prepared as 0.3.0 below.

### Security
- Redis requires a password in the production overlay (`REDIS_PASSWORD` in `.env.docker`); the backend adds it to `REDIS_URL`, and a test confirms a real Redis rejects unauthenticated clients.
- Nuclei 3.11.1, Subfinder 2.17.0 and HTTPX 1.12.0 (Go 1.26 builds) replace older pins that carried fixable CRITICAL findings; the release image scan now checks vulnerabilities only and skips the unmaintained Amass 4.2.0 binary, which is documented in SECURITY.md.

### Added
- **End-to-end lab** (`lab/`): a deliberately misconfigured web server and a script that scans it through the real API; CI runs it on relevant pull requests, on `main` and nightly, and fails if the scan misses the exposed `.git` or `.env`, a stage fails, or the open port is not seen.
- **DNS hygiene** posture check: dangling name servers (high), missing CAA and DNSSEC (info), with its own change-detection coverage, report advice and a filter on the Vulnerabilities page.
- **Two-step sign-in** (optional per account): authenticator-app codes (TOTP, RFC 6238 test vectors in the tests), single-use codes, ten recovery codes, encrypted secrets, lockout on wrong codes, and an admin reset for lost devices. Migration 0017.
- `python -m backend.scripts.reset_password` to recover an account (for example the only admin) from the server shell.
- **Audit log page** (admins) with filters by kind of event and username, and paging on `GET /audit`.
- Code of Conduct (Contributor Covenant 2.1).
- `limit`/`offset` and an `X-Total-Count` header on the per-scan asset list and on findings by scan or target (default 5000, maximum 20000); a test exercises six thousand rows of each.

### Changed
- Amass is now opt-in (`ASM_AMASS_ENABLED=true`): on real targets it added little beyond subfinder and held the subdomain stage open for about two minutes.
- The interface font (Inter) is bundled with the app instead of loaded from Google, so the page makes no third-party requests and the Content Security Policy no longer lists external hosts.
- The API version in `/health` and the docs comes from one place (`backend/version.py`), and the release workflow refuses a tag that does not match it.
- The backend image starts with a JSON-form `CMD`; release jobs run on `ubuntu-24.04`.

## [0.3.0] - 2026-10-09

Not tagged on its own: these changes ship as part of 0.4.0.

### Added
- **Posture checks** in every scan: subdomain takeover (dangling CNAMEs and unclaimed GitHub Pages, Azure, Heroku, S3, Shopify and similar), email security (SPF, DMARC, DKIM key strength, MTA-STS), public cloud storage listings (S3, GCS, Azure Blob) named after the domain, and exposed `.git`, `.env`, backup, credential and debug files confirmed by content. Quick runs the two DNS-only checks. Findings flow through change detection with their own coverage, so a check that could not run never reports something as fixed.
- **Posture filter** on the Vulnerabilities page: show only posture-check findings, or narrow to takeover, email security, cloud storage or exposed files. The severity tiles follow the filter, rows carry a badge for their check, and guessed storage names are labelled *Ownership unconfirmed*.
- **`severity` and `tag` filters** on `GET /vulnerabilities/`, `/summary` and `/rollup` for scripts and pipelines (for example `?tag=posture&severity=high,critical`). Values are validated, tags match exactly, and wildcard characters are never interpreted. Before, the endpoint ignored such parameters and returned everything; only the web page filtered.
- **Signed, published releases**: tagged versions publish the backend and frontend images to GitHub Container Registry with build provenance, an SBOM and a keyless signature, after the full test suite and a fixable-CRITICAL vulnerability gate. `docker-compose.images.yml` runs them instead of building from source, and `docs/RELEASING.md` covers cutting, verifying, pinning by digest and rolling back.
- **Restore drill and restore script** (`deploy/restore.sh`): `verify` checks the checksum, restores a backup into a scratch database, compares tables and the schema revision, then drops the scratch database without touching live data; `apply` replaces the live database in one transaction, so a failed restore changes nothing.
- **Screenshot viewing**: a gallery of the pictures taken during a scan, opened from the scan's menu on the Scans page. Pictures are matched to their host, served only to signed-in users, and removed with the retention cleanup.
- **Target tags**: label targets (up to 10 each), edit them from the row menu, and filter the Targets list by tag. `GET /targets/?tag=` filters through the API.
- **Email notifications**: one digest email per scan and per exposure run to up to 10 recipients per target, with the same severity threshold as webhooks. Set up with `ASM_SMTP_*`; deliveries show on the Alerts page.
- **Scheduled database backups** (`docker-compose.backup.yml`): daily verified dumps with checksums and retention.
- **API tokens** for scripts and CI (Account page): read-only or full access, optional expiry, shown once, stored as a hash, revoked automatically when the password changes or is reset.
- JSON and SARIF 2.1.0 finding exports, and an export menu on the Scans page (CSV, JSON, SARIF).
- `GET /metrics` (Prometheus format, admin only) and `ASM_LOG_FORMAT=json` structured logs.
- Frontend component tests (Vitest) run in CI. Issue and pull request templates, `CODEOWNERS`, and an expanded architecture document.

### Security
- **`cryptography` upgraded to 50.x**, clearing four published advisories (a bundled OpenSSL issue, PKCS#7 decryption leak, and two X.509 verifier issues) that were previously accepted. `sslyze` caps `cryptography` below 47 in its metadata, so it is now installed separately without dependency resolution (`requirements-sslyze.txt`). A new test runs a real TLS scan with the combination in CI. `pip check` reports the sslyze cap; that message is expected.
- **Login throttle counters can no longer get stuck.** A counter is now created together with its 15-minute expiry. Before, a crash between the two Redis calls could leave one with no expiry and lock that user or address out permanently.

### Changed
- **Redis keeps its data across restarts** (append-only file, one-second fsync, named `redis_data` volume, `noeviction`). Before, `docker compose down` or a Redis crash dropped the task queue (queued scans sat in the list for up to 12 hours) and every scan lock (running scans were failed by the watchdog while still working). A test restarts a real Redis and checks the queue and locks come back.
- **Public-bucket findings are no longer rated high.** The bucket name is a guess, so a hit is now *medium*, or *info* when the domain label is short or a common word (a bucket called `example-files` says nothing about `example.com`).
- **Subdomain tools are bounded and reported precisely.** amass stops after `ASM_AMASS_TIMEOUT` seconds (default 150) and can be switched off with `ASM_AMASS_ENABLED=false`. Tool status says `ok`, `empty`, `timeout`, `not installed` or `failed` instead of calling every non-result `empty`.
- The production worker container has a memory cap (`ASM_WORKER_MEM_LIMIT`, default `4g`). A scan peaks near 2 GiB.
- Profile time estimates match measurements: Quick about 2-3 minutes, Standard about 3-12 depending on how many hosts are found (about 2 minutes for a single small host).
- The change-detection note for a skipped section says that absence is not treated as fixed, instead of the misleading "did not run cleanly".
- README Features lists optional AI notes, the restore drill, resilience, login protection and which posture checks each profile runs.

### Fixed
- **amass results were always discarded.** amass 4.x prints a relationship graph (`name (FQDN) --> a_record --> ip`), not bare names, and the parser dropped every line. It now reads the names from the graph. A normal run takes about 110 s (`-timeout 1` limits only the gathering phase), so the timeout default is 150 s.
- **Celery beat could crash at start-up** with a `PermissionError` on its schedule file when the image ran as the non-root production user without the production overlay. The base compose file now writes the schedule to `/tmp`, as the overlay already did.
- **Deleting a target now stops everything for it**: its schedules are paused (and hidden), and a scan that is queued or running is cancelled.
- **Resuming a paused schedule** waits for its next time slot instead of firing at once for a time that passed while it was paused. The Schedules switch sets the state explicitly, so a double click can no longer undo itself.
- **Saving notification settings with only some fields** (for example just the email recipients) no longer resets the alert threshold and webhook format to their defaults.
- **Nuclei did not run in the production overlay.** Its template lookup depends on a config file that is empty in a read-only container, so it scanned nothing. The scanner now passes the installed template folder explicitly.
- **Zombie `chromium` processes** piled up in the worker after screenshot stages. The backend, worker and beat containers now run with a minimal init that reaps them.

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
