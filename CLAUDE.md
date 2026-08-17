# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

Monorepo with two git submodules that live in separate GitHub repos:

- `backend/` — Django 6 + DRF + Channels API, workers, and the agentic runtime.
- `frontend/` — Vite + React 19 + Ant Design 6 SPA (pnpm).
- `cli/` — `asp-cli` (Typer/httpx), published to PyPI as the `asp` command; talks to `/api/agent/v1/`.
- `deploy/` — release tooling (`release_tool.py`, `release-manifest.json`) and the `asp-compose` production bundle.
- `development/docker/compose.yaml` — local Postgres 17 / redis-stack / RustFS dependencies.
- `docs/specs/<version>/` — implementation-level specs (Chinese). `Confirmed` specs are binding; do not change confirmed behavior on your own.
- `asp-doc/` (submodule) — VitePress docs site. `asp-marketplace/` (submodule) — Claude Code plugin code. Both are usually uninitialized; run `git submodule update --init <name>` only when the user asks.

## Commands

Backend (run from `backend/`, Python 3.14, deps via `uv`; the venv interpreter is `backend/.venv/Scripts/python.exe`):

```powershell
uv sync
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver           # WSGI, no websockets
.\.venv\Scripts\python.exe -m uvicorn asp.asgi:application --host 127.0.0.1 --port 8001   # ASGI, needed for /ws
.\.venv\Scripts\python.exe manage.py test                # all tests
.\.venv\Scripts\python.exe manage.py test apps.webhook   # single app / module / TestCase
.\.venv\Scripts\python.exe manage.py spectacular --file openapi.yaml
.\.venv\Scripts\python.exe manage.py createsuperuser     # ASP admins are Django superusers
```

Workers (each is a management command; all accept `--once` and `--interval`, so `--once` is the fastest way to exercise one iteration):

```powershell
manage.py run_agentic_module_worker          # consumes Redis streams -> Modules
manage.py run_agentic_case_analysis_worker   # LLM case analysis jobs
manage.py run_agentic_playbook_worker        # Playbook runs
manage.py run_elk_action_worker              # ELK alert actions
manage.py run_dashboard_cache_worker         # dashboard snapshots
```

Frontend (run from `frontend/`, Node 24, pnpm 10):

```powershell
pnpm install
pnpm dev            # proxies /api and /ws to http://localhost:8001
pnpm exec eslint .
pnpm exec tsc -b
```

CI (`.github/workflows/ci.yml`) runs: `python deploy/release_tool.py check`, backend `manage.py check` + `spectacular` + `test`, frontend `eslint` + `tsc -b` + `build`, and a compose-package validation that fails if development sample Modules/Playbooks/SIEM definitions leak into the release template.

Mock data: `manage.py shell -c "from mock.import_mock_data import run; run()"` (idempotent, creates a new batch each run).

## Architecture

### Alert ingestion pipeline

Webhook (`apps/webhook`) receives Splunk / Kibana payloads and writes each event to a **Redis Stream named after the detection rule** (`search_name` / `rule.name`). `run_agentic_module_worker` discovers Module scripts, reads its stream via a consumer group, and each Module maps the raw event into ASP domain objects through `apps.agentic.services.alerts.create_alert_with_context` — which correlates into an existing Case by `correlation_uid` (guarded by a Postgres advisory lock), creates the Alert, Artifacts, and Enrichments, and enqueues a `CaseAnalysisJob`. `run_agentic_case_analysis_worker` then runs the LLM investigation (`apps/agentic/analysis/`) and writes the `*_ai` verdict/severity/impact/priority/confidence fields plus the structured report back onto the Case.

So: **stream name is the contract** between a SIEM rule and its Module.

### Script runtime (Modules and Playbooks)

`apps/agentic/runtime/loader.py` loads plain `.py` files by path and picks out a class literally named `Module` or `Playbook` that subclasses `BaseModule` / `BasePlaybook` (`runtime/base.py`). Relative imports inside script files are rejected.

- Modules: only `backend/custom/modules/`. Keyed by `STREAM_NAME`.
- Playbooks: `backend/playbooks/` (built-in) overlaid by `backend/custom/playbooks/` — same filename in custom **shadows** the built-in one. `RISK_LEVEL` must be one of Low/Medium/High/Critical or the definition is rejected at scan time.
- Prompts and data files live under `backend/custom/data/{modules,playbooks,siem}/<slug>/`, resolved per language via `BasePlaybook.read_prompt()` (`<name>_<lang>.md`).
- Extra pip deps for custom scripts go in `backend/custom/requirements.txt`; in production the compose stack installs them into a separate volume on `PYTHONPATH`.

Playbook runs are DB-queued rows (`apps.playbooks.Playbook` with `job_status`), claimed with `select_for_update`; progress is reported by `self.add_run_message(...)`, and messages/remarks are scrubbed of `authorization`/password/token/secret patterns before storage. Orphaned `Running` rows are failed on worker startup.

### Workers

All workers go through `apps.common.worker_runner.run_worker`, which handles the loop, interval, `--once`, per-iteration runtime-config cache invalidation, file logging role, and heartbeat reporting to Redis via `apps.common.worker_health` (surfaced in the admin UI). New workers should use it rather than writing their own loop.

### Configuration

Two layers: process env (`backend/.env`, see `.env.example` — Postgres, Redis, RustFS/S3, Django) and **runtime config stored in the database** (`apps/settings/models.py`: LLM providers, Splunk/ELK, OTX/OpenCTI, LDAP, CMDB, custom variables). Runtime config is read through `apps.settings.runtime_config`, which is `lru_cache`d — mutating those models requires `invalidate()`, and workers refresh it every iteration.

### API conventions

- REST under `/api/` (JWT or API key auth, `apps.accounts.authentication.ApiKeyAuthentication`), OpenAPI at `/api/schema/`, Swagger at `/api/docs/`.
- A separate, deliberately stable agent-facing surface lives at `/api/agent/v1/` (`apps/agent_api`) for the CLI, Claude Code plugins, and other harness agents — SIEM search, threat intel, CMDB, cases, playbook runs, file upload. `cli/src/asp_cli/spec/operations.json` mirrors it.
- `apps/common` holds the cross-cutting pieces: cursor pagination, the JSON `advanced_filters` query backend, `metadata.py` (drives frontend column/filter config from Django model fields via `RESOURCE_CONFIGS`), readable IDs (`case_000123`, backed by Postgres sequences), audit signals, exception handler.
- Realtime: Channels over Redis; `apps/realtime` publishes comment/inbox events to per-user and per-record groups. Websockets only work under the ASGI server.

### Frontend

The record UIs are **config-driven**: `src/config/resources.tsx` declares each resource (columns, tabs, filters, detail views) and generic `ResourceListPage` / `DataTable` / `ResourceDetailRoute` components render it; column and filter metadata is fetched from the backend metadata API. Adding a field to a list/detail view usually means editing `resources.tsx` (plus the backend serializer/metadata), not writing a new page. Auth state is a small zustand store (`src/stores/auth.ts`); axios interceptors attach the JWT and redirect to login on 401.

## Project conventions

- Do not run `superpower` skills unless the user explicitly asks. With `superpower:writing-plan` disabled, implement directly from the spec.
- Do not write test code while implementing a feature unless the user asks for it.
- `docs/TODO.md` is hand-maintained by the user — never edit it, and don't mention it in commits.
- Any model change must ship with the Django migration.
- Frontend: prefer Ant Design component features and default CSS; only customize when the default cannot do it. Never run `pnpm build` just to validate a change.
- Docs (`asp-doc`): update the `zh` page first, settle it, then mirror to `en`. Image placeholders get no caption text and are named `img.png`, `img_1.png`, … Do not build VitePress unless asked.
- Releases follow `docs/release-runbook.md` — version bumps across CLI, compose env, and docs are driven by `deploy/release-manifest.json` + `deploy/release_tool.py`, never by hand.
