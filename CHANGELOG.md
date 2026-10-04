# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- **Nuclei did not run in the production overlay.** Its template lookup depends on a config file that is empty in a read-only container, so it looked in `/app/nuclei-templates` and scanned nothing. The scanner now passes the installed template folder explicitly.
- **Zombie `chromium` processes** piled up in the worker after screenshot stages. The backend, worker and beat containers now run with a minimal init that reaps them.

### Added
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
