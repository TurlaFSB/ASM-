# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub: **Security > Report a vulnerability** on this repository.
Do not open a public issue for a vulnerability. Include what you found, how to reproduce it, and the version or
commit. You can expect an acknowledgement within a few days.

## Scope

ASM actively scans targets, so its own safety matters: authorization gate, authentication, throttling, webhook and
outbound-request safety, and handling of untrusted scan data are all in scope.

## Dependency audit and accepted risks

CI runs `pip-audit` and `npm audit` on every push and fails on new known vulnerabilities. The following findings are
accepted for now, with the reason:

| Advisory | Package | Why it is accepted |
|---|---|---|
| PYSEC-2026-3552, PYSEC-2026-3553, PYSEC-2026-3554, GHSA-537c-gmf6-5ccf | `cryptography` 46.x | `sslyze` (the TLS scanner) pins `cryptography<47` in its latest release, so the fixed versions cannot be installed alongside it. ASM does not call the affected PKCS#7 decrypt or X.509 path-verification APIs itself, and certificate validation in the TLS scan runs through `sslyze`/`nassl`. Revisit when `sslyze` allows a newer `cryptography`. |

Removed on 2026-10-03: `python-jose` (and its `ecdsa` dependency) was replaced by `PyJWT`.
