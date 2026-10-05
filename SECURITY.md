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

The image scan lists fixable HIGH and CRITICAL findings as annotations on the Security workflow. As of 2026-10-04 they are all inside the bundled third-party command-line tools (Nuclei, Subfinder, HTTPX and Amass are pinned to older releases built with older Go toolchains and libraries). These tools run only against targets the operator has authorized and are not exposed as network services, so the practical risk is limited, but the pins will be raised once each newer release is verified against the scanner modules (output format and flags). Until then the CRITICAL gate reports without failing the build.

Removed on 2026-10-03: `python-jose` (and its `ecdsa` dependency) was replaced by `PyJWT`.
