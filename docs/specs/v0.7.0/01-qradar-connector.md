# S1 — QRadar connector and ingestion

Status: Draft

## 1. Purpose

Add IBM QRadar (on-prem) as a first-class SIEM backend alongside Splunk and ELK, and ingest QRadar offences into the existing Case pipeline without changing the ingestion contract.

Splunk and ELK stay fully supported. Nothing may be replaced or special-cased away.

## 2. Extension points in the existing code

The SIEM layer is closed over two backends. Each of these must be widened, not bypassed:

| Location | Current state | Required change |
| --- | --- | --- |
| `integrations/siem/registry.py:40` | raises unless `backend ∈ {ELK, Splunk}` | accept `QRadar` |
| `integrations/siem/service.py:80` `_get_query_backend()` | if/elif over two backends | add QRadar branch |
| `integrations/siem/service.py:88` `get_indices_by_backend()` | dict literal with two keys | derive keys from the registry instead |
| `integrations/siem/backends.py:42` `BackendQueryResult.backend` | `Literal["ELK","Splunk"]` | widen the literal |
| `integrations/siem/clients.py` | `get_splunk_service()`, `get_elk_client()`, `reset_clients()` | add `get_qradar_client()` and clear it in `reset_clients()` |
| `apps/agent_api/views.py:495–556` | six SIEM views | add QRadar query and offence views |

`QRadarQueryBackend` implements the same classmethod contract as the existing backends: `execute_structured_query`, `execute_keyword_query`, `discover_keyword_hit_indices`, `discover_index_fields`, plus `execute_aql_query` (parallel to `execute_spl_query` / `execute_esql_query`).

## 3. Runtime configuration

New singleton `SiemQRadarConfig` in `apps/settings/models.py` (migration required), read through `apps.settings.runtime_config` with `invalidate()` on write:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `base_url` | url | — | e.g. `https://qradar.internal` |
| `api_token` | text | — | sent as the `SEC` header |
| `api_version` | string | `22.0` | sent as `Version` header |
| `verify_ssl` | bool | `True` | on-prem uses an internal CA |
| `ca_bundle_path` | string | `""` | path inside the container; empty means system store |
| `search_timeout_seconds` | int | `300` | Ariel search completion budget |
| `metadata_timeout_seconds` | int | `30` | offence/reference-data calls |
| `max_rows` | int | `1000` | hard ceiling on returned rows |
| `default_window_minutes` | int | `60` | applied when a query omits a range |
| `max_window_hours` | int | `24` | ceiling enforced by the guard |
| `max_concurrent_searches` | int | `2` | protects the production SIEM |
| `allow_write` | bool | `False` | see §5 |
| `poll_enabled` | bool | `False` | enables the pull worker |
| `poll_interval_seconds` | int | `60` | |

## 4. Client

`integrations/siem/qradar_client.py`:

**Ariel searches** — `POST /api/ariel/searches` with the AQL, poll `GET /api/ariel/searches/{id}` until `COMPLETED`, then `GET /api/ariel/searches/{id}/results` with `Range: items=0-N`. On timeout or cancellation the search is deleted so it does not keep consuming SIEM resources.

**Offences** — list and detail, offence notes, source and local destination addresses, offence types, closing reasons. Pagination via the `Range` header.

**Reference data** — read only: `GET /api/reference_data/sets/...`.

Retry with backoff on 5xx and connection errors; separate timeouts for search versus metadata; QRadar error bodies normalised into `QRadarApiError` carrying the QRadar error code.

## 5. Read-only posture

The API token issued to ASP has full read and no write. The client is therefore read-only by construction:

- No method closes an offence, adds a note, or mutates a reference set is reachable while `allow_write=False`.
- Those operations exist as stubs that raise `QRadarWriteDisabled` with an explicit message, so a future permission grant is a configuration change rather than an architectural one.
- The flag is checked in the client, not in the caller, so no skill can route around it.

## 6. AQL guard

New module `integrations/siem/aql_guard.py`. Every AQL statement — hand-written or LLM-generated — passes through it before execution.

Rules:

1. Single statement only. Reject `;`-separated statements and comment sequences used to smuggle them.
2. `SELECT` only, `FROM events` or `FROM flows` only. Any other verb is rejected.
3. A time range is mandatory: `LAST N MINUTES|HOURS|DAYS` or explicit `START`/`STOP`. Missing range is replaced by `default_window_minutes`; a range wider than `max_window_hours` is rejected.
4. `LIMIT` is mandatory and capped at `max_rows`; a missing or larger limit is rewritten down.
5. Result row count is capped again at read time, independently of the query text.

The guard returns either the normalised query or a structured rejection carrying a machine-readable reason, so the hunting layer in S4 can feed the reason back to the model and retry up to a configured number of attempts.

Note for reviewers: SPL currently has no equivalent guard (`backends.py:351` only prepends `search`) and ES|QL only forces a `LIMIT` (`backends.py:183`). That gap predates this release. This spec does not close it, but the guard is written so the same shape can be applied to SPL later.

## 7. Ingestion

Both directions are supported and selectable by configuration. They converge on one normaliser so that the payload reaching a Module is byte-identical either way.

**Push** — `POST /api/webhook/qradar/` in `apps/webhook`, fed by a QRadar Custom Action or forwarding rule.

**Pull** — `manage.py run_qradar_offense_worker`, built on `apps.common.worker_runner.run_worker` with `--once` and `--interval`. It polls offences by `last_persisted_time`, stores a watermark, and re-processes offences whose state changed. Each offence is enriched with source and destination addresses plus top events fetched via AQL.

Both call `normalize_offense()` and write to a Redis Stream named after the offence's rule name, falling back to offence type when the rule name is absent. The stream-name-equals-rule-name contract is unchanged.

**Correlation** — `correlation_uid` is derived from the QRadar offence id, so repeated events belonging to one offence collapse into a single Case, consistent with `create_alert_with_context` (`apps/agentic/services/alerts.py:44`).

## 8. Modules

- `backend/custom/modules/qradar_generic.py` — fallback mapper from a normalised offence to Alert, Artifacts and Enrichments.
- One rule-specific sample module to demonstrate field mapping.

Placement note: development samples belong under `backend/custom/`. They must never be placed under `deploy/asp-compose/custom/`, which the packaging script strips (`deploy/package-asp-compose.sh:61`) and the CI `compose-package` job actively fails on. `deploy/release_tool.py check` does not police this; it only checks release version consistency.

## 9. API surface

`/api/agent/v1/`:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `siem/qradar/search/` | POST | run a guarded AQL query |
| `siem/qradar/offenses/` | GET | list offences with filters |
| `siem/qradar/offenses/{id}/` | GET | offence detail with addresses and notes |

Each is registered in `cli/src/asp_cli/spec/operations.json` with `id`, `cli_path`, `method`, `endpoint`, `permission`, `capabilities`, `aliases`, `examples`, and gets a matching `asp` CLI command. All views use `run_with_operation_timeout` and `agent_response`, matching `apps/agent_api/views.py:539`.

## 10. Frontend

QRadar settings page section alongside Splunk and ELK, with a connection test button that surfaces the real QRadar error. No new resource pages; offences reach the UI as Cases through the normal pipeline.

## 11. Audit

Every executed AQL statement is written to the audit log with the actor, the normalised query text, row count, duration, and whether the guard rewrote it.

## 12. Acceptance criteria

1. A QRadar-backed index YAML loads without touching Splunk or ELK behaviour, and a keyword search with no index specified still fans out across all three backends.
2. An AQL statement without a time range is rewritten to the default window; one exceeding `max_window_hours` is rejected with a readable reason.
3. Write attempts raise `QRadarWriteDisabled` while `allow_write=False`.
4. Push and pull ingestion of the same offence produce identical Redis Stream payloads.
5. Two events of one offence produce one Case, not two.
6. `manage.py check`, `spectacular`, `eslint`, `tsc -b` all pass.

## 13. Open questions for SHB

1. **Concurrent Ariel search limit on production QRadar.** This is the real constraint on S4 `auto` hunting; the batch size and `max_concurrent_searches` default depend on it.
2. Exact API version string of the deployment, since Ariel response shapes vary across versions.
3. Whether QRadar forwarding (push) is permitted on this deployment, or ingestion must be pull-only.
4. Field names carrying asset and user identity in SHB's QRadar deployment, needed to map Artifacts correctly.
