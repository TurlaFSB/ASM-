# Contributing

Thanks for helping improve the ASM Platform. This page covers how to set up, what a good change looks like, and what the checks expect.

## Ground rules

- Only scan systems you own or have written permission to test. Do not add features that bypass the target authorization gate.
- Report vulnerabilities privately (see [SECURITY.md](SECURITY.md)), never in a public issue.
- Keep changes small and focused: one concern per pull request.

## Set up

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r backend/requirements-dev.txt
pytest
cd frontend && npm ci && npm run lint && npm test && npm run build
```

The backend tests use in-memory SQLite and stubbed scanners, so they need no Docker, Redis or network access. To run the whole stack, follow the Quick start in the [README](README.md#quick-start).

## Before you open a pull request

1. `pytest` passes. CI enforces a coverage floor; new behaviour needs tests (a failing test first is ideal).
2. `npm run lint`, `npm test` and `npm run build` pass in `frontend/`. Component tests live next to the component (`*.test.jsx`) and mock `../api`.
3. Schema changes come with an Alembic revision in `backend/migrations/versions/`. Never edit an applied revision.
4. User-visible changes update the README and the [CHANGELOG](CHANGELOG.md).
5. No secrets, tokens or real target data in code, tests or screenshots.

## Where things live

| Area | Location |
|---|---|
| API routes | `backend/api/` |
| Scan pipeline | `backend/tasks.py` (orchestration), `backend/pipeline_stages.py` (decisions and data transforms), `backend/scanner/` (one module per tool) |
| Change detection | `backend/diffing/` |
| Exposure sources | `backend/exposure/` (add a source by implementing the base class and registering it) |
| Reports | `backend/reports.py`, `backend/templates/report.html` |
| Frontend | `frontend/src/pages/`, `frontend/src/components/`, design tokens in `frontend/src/design.css` |

More background is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Style

- Python: clear names, small functions, docstrings that explain *why*. Keep scanner modules free of database access; persistence belongs in `scan_persist.py` and the pipeline.
- Frontend: reuse the existing components (`Sheet`, `RowMenu`, `Segmented`, `ToggleSwitch`, `Toast`) and tokens; keep controls keyboard-accessible, and do not add inline scripts (the Content Security Policy forbids them).
- Commit messages: a short imperative summary line, then the reason if it is not obvious.

## Reviewing dependency updates

Dependabot opens pull requests for Python, npm and GitHub Actions. CI must be green, and anything that touches the runtime (Celery, Docker base images, scanners) should also be checked with a real scan before merging.
