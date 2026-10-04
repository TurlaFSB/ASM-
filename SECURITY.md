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

### Container image scan (Trivy)

The image scan lists fixable HIGH and CRITICAL findings as annotations on the Security workflow. As of 2026-10-04 they are all inside the bundled third-party command-line tools (Nuclei, Subfinder, HTTPX and Amass are pinned to older releases built with older Go toolchains and libraries) plus the `cryptography` entry above. These tools run only against targets the operator has authorized and are not exposed as network services, so the practical risk is limited, but the pins will be raised once each newer release is verified against the scanner modules (output format and flags). Until then the CRITICAL gate reports without failing the build.

Removed on 2026-10-03: `python-jose` (and its `ecdsa` dependency) was replaced by `PyJWT`.
