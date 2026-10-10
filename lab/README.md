# End-to-end lab

A tiny, deliberately misconfigured web server (`172.28.0.80`) plus a script that scans it through the real API and
checks that the platform found what it must. It exists to catch what unit tests cannot: a tool upgrade that changes a
flag, a stage that quietly stops producing results, a migration that breaks a running stack.

What the lab serves (all fake): a `.git/HEAD` and a `.env` in the web root. A healthy scan must produce:

- scan status `completed`, and no stage reporting `failed`, `timeout` or `not installed`
- the findings `exposed-git` (high or worse) and `exposed-env` (high or worse) on the lab host
- an asset for `172.28.0.80` with port 80 open

The exact expectations live in `expected.py`; `backend/tests/test_lab.py` checks them offline, including that the lab's
files trip the platform's own exposed-file check.

## Run it

```bash
cp .env.docker.example .env.docker
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)" > .env
# put the same password in DATABASE_URL and a fresh SECRET_KEY (openssl rand -hex 32) in .env.docker, then:
docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml up -d --build
python3 lab/e2e.py
docker compose -f docker-compose.yml -f lab/docker-compose.lab.yml down -v
```

It needs a **fresh** stack (it creates the first admin account), takes about 10 to 15 minutes with the Standard profile
(`ASM_E2E_PROFILE=quick` is faster but skips the exposed-file stage, so it will report that finding missing), and
prints the stage statuses so a failure is easy to read. CI runs it on pull requests that touch the backend or lab,
on pushes to `main`, and nightly (`.github/workflows/e2e.yml`).

The overlay turns on `ASM_ALLOW_PRIVATE_TARGETS`, which lets the platform scan private addresses. Use it only in this
lab, never on a real deployment.
