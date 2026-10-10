# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub: **Security > Report a vulnerability** on this repository.
Do not open a public issue for a vulnerability. Include what you found, how to reproduce it, and the version or
commit. You can expect an acknowledgement within a few days.

## Scope

ASM actively scans targets, so its own safety matters: authorization gate, authentication, throttling, webhook and
outbound-request safety, and handling of untrusted scan data are all in scope.

## Dependency audit and accepted risks

CI runs `pip-audit` and `npm audit` on every push and fails on new known vulnerabilities. There are currently no
accepted Python or npm advisories.

`sslyze` (the TLS scanner) declares `cryptography<47`, but those versions carry known advisories. ASM therefore pins
`cryptography` 50 in `requirements.txt` and installs `sslyze` separately without its own dependency resolution
(`requirements-sslyze.txt`). A test (`backend/tests/test_sslyze_compat.py`) runs a real TLS scan with this
combination on every CI run, so a future release that breaks it fails the build instead of the scanner. The split can
go once `sslyze` allows a newer `cryptography`. `pip check` will therefore print "sslyze has requirement cryptography<47"; that message is expected and does not indicate a fault.

### Container image scan (Trivy)

The image scan lists fixable HIGH and CRITICAL findings as annotations on the Security workflow, and the release workflow refuses to publish an image with a fixable CRITICAL vulnerability. On 2026-10-10 Nuclei, Subfinder and HTTPX were raised to releases built with Go 1.26 (the older pins carried fixable CRITICAL findings in their bundled Go runtime and libraries); their flags and output were checked against the scanner modules.

Known exception: Amass 4.2.0 is the last release of the v4 line and is no longer updated upstream, so its bundled Go runtime and `pgx` library are old. The release gate skips that one binary (`--skip-files usr/local/bin/amass`) and scans everything else. Amass runs only against targets the operator has authorized, is not exposed as a network service, and does not use its PostgreSQL support here. It will be replaced once a maintained release (or a source build) is verified against the subdomain parser.

Removed on 2026-10-03: `python-jose` (and its `ecdsa` dependency) was replaced by `PyJWT`.
