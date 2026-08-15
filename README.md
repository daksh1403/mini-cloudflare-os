# Mini Cloudflare OS

[![CI](https://github.com/daksh1403/mini-cloudflare-os/actions/workflows/ci.yml/badge.svg)](https://github.com/daksh1403/mini-cloudflare-os/actions/workflows/ci.yml)

A small, working implementation of the **Cloudflare OS** concept — sandboxed
per-user **Gadgets** with **platform-enforced access control** and
**Gatekeeper-style approvals** — built with the exact stack and discipline
from the [Daksh AI Engineer Academy](https://github.com/daksh1403/daksh-ai-engineer-academy).

> **The idea (from Kenton Varda's Cloudflare OS announcement):** each document
> runs as a separate instance of the app (a "Gadget"). The platform owns all
> access control — a Gadget can never accidentally leak itself — and
> side-effecting actions go through human-in-the-loop approvals.
>
> This repo is the educational reference implementation of that model.

---

## The stack (from the academy's tech stack report)

| Layer | Tool | Why |
|---|---|---|
| Language | **Python 3.12** | Deepest coverage in the academy notes (★★★★★) |
| Web framework | **FastAPI** | Documented API framework (path ops, Pydantic, OpenAPI) |
| TDD | **pytest + pytest-cov** | The notes' TDD workflow (Red/Green/Refactor, fixtures, coverage) |
| BDD | **behave + Gherkin** | The notes' BDD tool (Given/When/Then, feature files) |
| Lint | **ruff** | Modern Python linter |
| Typecheck | **mypy** (strict) | Type-safe Python |
| Container | **Docker** (multi-stage) | The notes' strongest area (★★★★★) |
| CI/CD | **GitHub Actions** | Pipeline shape from `09_microservices_and_cicd` |

---

## What it does

The platform (`cloudflare_os/main.py`) is the single entry point. It maps a
caller to a `Principal` (via `x-user-id`; swap for a JWT in production) and
routes `/gadgets/:id/...` to a per-gadget `GadgetService` — the Python analog
of a Cloudflare Durable Object (one instance per Gadget, own state, own ACL).

**Security model:** the Gadget never checks access itself. Every operation
goes through `check_access()` in `cloudflare_os/domain/gadget.py`, which the
platform enforces. A Gadget cannot grant itself access — exactly the
Cloudflare OS claim.

```
┌──────────────────────────────────────────────────────────┐
│  Platform Worker (FastAPI)                               │
│  · mints Principal from request                          │
│  · routes to per-gadget GadgetService                    │
│  · enforces ACL on every operation                       │
└───────────────┬──────────────────────────────────────────┘
                │
    ┌───────────▼────────────┐      ┌──────────────────────┐
    │ GadgetService (g-123)  │      │ Gatekeeper           │
    │ · meta/ACL             │──────│ · side effects queue │
    │ · data (per-gadget)    │      │ · owner approves     │
    │ · audit log            │      └──────────────────────┘
    └────────────────────────┘
```

### API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/gadgets/{id}/init` | Create/name a gadget (owner minted) |
| `GET` | `/gadgets/{id}/meta` | Gadget metadata + ACL |
| `POST` | `/gadgets/{id}/share` | Share with a user (owner only) |
| `POST` | `/gadgets/{id}/revoke` | Revoke a user (owner only) |
| `GET/POST` | `/gadgets/{id}/data` | Read/write gadget data |
| `POST` | `/gadgets/{id}/gatekeeper` | Queue a side-effect action |
| `GET` | `/gadgets/{id}/approvals` | List approvals |
| `POST` | `/gadgets/{id}/approvals/decide` | Approve/reject (owner only) |
| `GET` | `/gadgets/{id}/audit` | Audit log |

---

## TDD — how it was built

The unit tests in `tests/unit/` follow the notes' Red/Green/Refactor
discipline:

- **`test_gadget.py`** — domain logic: happy paths (owner can do everything)
  and sad paths (stranger denied, invalid roles, missing fields), plus
  parametrized validation tests.
- **`test_gadget_service.py`** — per-instance service: init, write/read
  round-trip, viewer-can't-write, gatekeeper queue, audit log.
- **`test_api.py`** — platform API through FastAPI `TestClient`: 403s for
  strangers and anonymous callers, full flow.

Every test file uses fixtures (`@pytest.fixture`) for isolation, exactly per
the notes' Module 4 (fresh state per test, no order dependencies).

```bash
make test        # pytest with coverage
```

## BDD — the living documentation

`features/*.feature` are Gherkin feature files (the notes' Module 12),
driving the real API via behave:

```gherkin
Feature: Gadget access control
  Scenario: A stranger cannot open a gadget they were not invited to
    Given user "alice" owns a notes gadget "g-private"
    When mallory tries to read the gadget "g-private"
    Then the platform denies access with status 403
```

```bash
make bdd         # behave features
```

---

## CI/CD — the pipeline

`.github/workflows/ci.yml` implements the exact pipeline shape from the notes
(`03_cicd_pipelines.md`): **lint → typecheck → unit tests → BDD → build →
deploy**. The Docker build stage re-runs the full gate, so a failing test
can't even produce an image. Deploy stages are wired to secrets.

---

## Running it locally

```bash
# 1. Set up
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# 2. Full gate (what CI runs)
make check        # ruff + mypy + pytest + behave

# 3. Run the API
make run          # uvicorn on :8000
```

Try it:

```bash
curl -X POST localhost:8000/gadgets/notes1/init \
  -H 'x-user-id: alice' -H 'content-type: application/json' \
  -d '{"name":"Study Notes","app":"notes"}'

curl localhost:8000/gadgets/notes1/data -H 'x-user-id: alice'

# Mallory gets 403:
curl localhost:8000/gadgets/notes1/data -H 'x-user-id: mallory'
```

Docker:

```bash
docker build -t mini-cloudflare-os .   # runs the full gate inside the build
docker run -p 8000:8000 mini-cloudflare-os
```

---

## Layout

```
cloudflare_os/
  main.py            # Platform Worker (FastAPI)
  gadget_service.py  # Per-gadget service (Durable Object analog)
  storage.py         # Gadget registry (swap for SQLite/DO in prod)
  domain/
    types.py         # Data shapes
    gadget.py        # ACL/access-control logic (TDD core)
    gatekeeper.py    # Approval logic
tests/unit/          # TDD: pytest (unit + service + API)
features/            # BDD: Gherkin features + behave steps
.github/workflows/   # CI/CD
Dockerfile           # Multi-stage, test-gated build
```

## Next steps (production hardening)

- Replace `x-user-id` with validated sessions/JWTs.
- Replace `MemoryStorage` with SQLite (per-gadget DB) or Cloudflare Durable
  Objects.
- Wire real Gatekeeper targets (Slack, Twitter) behind the approval queue.
- Add a frontend so a non-technical user can "vibe code" a gadget.
