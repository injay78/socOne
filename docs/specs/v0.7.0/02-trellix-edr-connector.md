# S2 — Trellix EDR connector

Status: Draft

## 1. Purpose

Integrate Trellix EDR (SaaS tenant) as an alert source and an investigation surface: ingest detections into the Case pipeline, and expose host, detection and search capabilities to analysts, playbooks and agents.

Only the cloud tenant is in scope. No on-prem ePO adapter is written.

## 2. Authentication

OAuth2 client-credentials against Trellix IAM, exchanged for a bearer token used on the API host.

Requirements:

- Tokens are cached in Redis, keyed by tenant, and refreshed before expiry. A token is never fetched per request.
- Refresh is guarded by a Redis lock so parallel workers do not stampede the IAM endpoint.
- On `401`, refresh once and retry the original request exactly once; a second `401` is a hard error.
- Requested scopes are declared in configuration and split into read scopes and action scopes. While `allow_containment=False`, action scopes are **not requested at all**.

## 3. Runtime configuration

New singleton `EdrTrellixConfig` in `apps/settings/models.py` (migration required):

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | bool | `False` | |
| `iam_token_url` | url | — | IAM token endpoint |
| `api_base_url` | url | — | tenant API host |
| `client_id` | string | — | |
| `client_secret` | text | — | write-only in the API |
| `tenant_id` | string | — | |
| `read_scopes` | json list | `[]` | |
| `action_scopes` | json list | `[]` | requested only when containment is enabled |
| `timeout_seconds` | int | `60` | |
| `rate_limit_per_minute` | int | `120` | |
| `max_rows` | int | `1000` | |
| `max_window_hours` | int | `24` | |
| `allow_containment` | bool | `False` | see §6 |
| `poll_enabled` | bool | `False` | |
| `poll_interval_seconds` | int | `60` | |

## 4. Endpoint constants

All request paths live in one module, `integrations/edr/trellix_endpoints.py`, separated from business logic. Paths this specification is not certain about are declared as constants with a `TODO(verify)` marker naming what must be checked against SHB's tenant documentation.

Guessed paths must not be buried inside client methods. The implementation reports the full list of paths used so it can be verified in one pass.

## 5. Client capabilities

`integrations/edr/trellix_client.py`. Methods are named after the investigation need, not the endpoint:

| Method | Purpose |
| --- | --- |
| `list_detections(since, filters)` | new detections for ingestion and review |
| `get_detection(id)` | detection detail |
| `get_detection_context(id)` | process tree / trace, where the tenant exposes it |
| `get_host(hostname \| ip \| agent_id)` | agent state, OS, last seen, tags |
| `search_realtime(query)` | real-time search across online endpoints |
| `search_historical(query, time_range)` | historical hunt across the estate |
| `list_affected_hosts(threat_id)` | blast radius for one threat |

## 6. Containment

`isolate_host`, `kill_process` and `quarantine_file` are implemented but inert by default:

- Reachable only when `allow_containment=True`.
- Exposed exclusively through a Playbook with `RISK_LEVEL = "Critical"`.
- Require explicit human approval recorded on the run.
- With the flag off, the call returns a dry-run plan describing what would be done, and changes nothing.
- Every invocation, including dry runs, is written to the audit log.

## 7. Query guard

`integrations/edr/trellix_guard.py`, same shape as the AQL guard in S1: mandatory and capped time range, capped host count, capped row count, and rejection of query forms that would sweep the entire estate without bounds. Rejections carry a machine-readable reason so S4 can repair and retry.

## 8. Ingestion

`manage.py run_trellix_detection_worker`, built on `apps.common.worker_runner.run_worker`, polls detections since a stored watermark and writes each to a Redis Stream named after the rule or threat name — the same contract used by Splunk, ELK and QRadar.

`backend/custom/modules/trellix_generic.py` maps a detection to Alert plus Artifacts (file hash, process, command line, user, host) through `create_alert_with_context`.

Detections sharing a threat and host within a configurable window share a `correlation_uid`, so a burst on one machine becomes one Case.

## 9. API surface

`/api/agent/v1/`:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `edr/trellix/detections/` | GET | list detections |
| `edr/trellix/detections/{id}/` | GET | detection detail and context |
| `edr/trellix/hosts/` | GET | host lookup by hostname, IP or agent id |
| `edr/trellix/search/` | POST | guarded historical or real-time search |

Registered in `cli/src/asp_cli/spec/operations.json` with matching CLI commands.

## 10. Frontend

Trellix section on the settings page: credentials, scopes, containment flag with an explicit warning, and a connection test that reports the actual IAM error (invalid client, insufficient scope, wrong tenant). Detections surface as Cases through the normal pipeline; no new resource page.

## 11. Acceptance criteria

1. One token is fetched and reused across many requests; expiry triggers exactly one refresh even under parallel workers.
2. A `401` mid-run recovers transparently once, and fails loudly on the second occurrence.
3. With `allow_containment=False`, no action scope is requested and every containment call returns a dry-run plan.
4. A search without a time bound is rejected with a readable reason; a bounded search returns at most `max_rows`.
5. Two detections of one threat on one host produce one Case.
6. Every endpoint path used by the client appears in `trellix_endpoints.py`, none inline.

## 12. Open questions for SHB

1. Exact IAM token URL, API host and scope names for SHB's tenant — the implementation will list every assumed path for verification.
2. Whether the tenant exposes process-tree/trace data, which decides whether `get_detection_context` returns real content or is disabled.
3. Detection volume per day, which drives poll interval and stream retention (`stream_maxlen` in `RuntimeConfig`).
4. Whether SHB intends to ever grant containment scopes; if not, the containment playbook ships disabled and undocumented for end users.
