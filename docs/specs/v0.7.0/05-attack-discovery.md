# S5 — Attack Discovery

Status: Draft

## 1. Purpose

Periodically hand the open alerts in a time window to the LLM and let it identify attack chains, then narrate each chain as one story with a timeline. Analysts stop assembling scattered alerts by hand.

The reference behaviour is Elastic Security's Attack Discovery. The implementation here reuses ASP's own pipeline and the S0 LLM layer.

## 2. Model

New model `AttackDiscovery` (migration required):

| Field | Type | Notes |
| --- | --- | --- |
| `discovery_id` | readable id | follows `apps/common/readable_ids.py` |
| `title` | string | |
| `entity_summary` | json | primary hosts, users, addresses |
| `summary_markdown` | text | short, shown in the list |
| `details_markdown` | text | full narrative with a kill-chain timeline |
| `mitre_tactics`, `mitre_techniques` | json list | |
| `alert_ids`, `case_ids` | json list | members |
| `cluster` | nullable FK | link to `IncidentCluster` from S4 |
| `confidence` | float 0–1 | |
| `status` | enum | `open`, `acknowledged`, `promoted`, `dismissed` |
| `dismiss_reason` | text | required when dismissed |
| `window_start`, `window_end`, `generated_at` | datetime | |
| `fingerprint` | string, indexed | dedup key |
| `llm_call` | FK to `LlmCallRecord` | model, prompt version, tokens, raw response |

## 3. Worker

`manage.py run_attack_discovery_worker`, built on `apps.common.worker_runner.run_worker`, supporting `--once` and `--interval`.

Each cycle:

1. Collect open alerts and Cases in the sliding window (configurable).
2. Rank by severity and asset criticality, then trim to the S0 token budget. Trimming is reported, not silent.
3. Call the LLM through `invoke_structured()`.
4. Deduplicate, persist, and refresh statuses.

## 4. Deduplication

`fingerprint` is computed over the sorted entity set plus the technique set. A new discovery matching an existing fingerprint **updates** that record and appends newly seen alerts. Creating a second record for the same attack chain is a defect: without this, every cycle would spam analysts with the same story.

A discovery whose member alerts are all closed transitions status automatically. Records are never deleted.

## 5. Anonymisation

Implemented in the shared LLM layer (S0 §6), not here, so every skill inherits it. Default off.

Rationale: SHB's model is self-hosted, data does not leave the bank, and real hostnames and usernames materially improve narrative quality. The layer exists for the case where SHB later routes any skill to an external endpoint.

## 6. Frontend

- Attack Discovery list as cards: title, primary entity, member count, MITRE badges, confidence, status.
- Detail view rendering `details_markdown` with the timeline and links back to member alerts and Cases.
- **Promote to Case** — creates a new Case linked to every member alert, setting status `promoted`.
- **Dismiss** — requires a reason.
- Registered in `apps/common/metadata.py` `RESOURCE_CONFIGS` and `frontend/src/config/resources.tsx`.

Markdown rendering reuses the existing sanitiser used elsewhere in the frontend (`frontend/src/components/markdownSecurity.ts`); LLM-produced markdown is untrusted input.

## 7. API surface

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/agent/v1/discoveries/` | GET | list |
| `/api/agent/v1/discoveries/{id}/` | GET | detail |
| `/api/agent/v1/discoveries/{id}/promote/` | POST | promote to Case |
| `/api/agent/v1/discoveries/{id}/dismiss/` | POST | dismiss with reason |

Registered in `cli/src/asp_cli/spec/operations.json`.

## 8. Interoperability with S4

A discovery can generate a `HuntPlan` for its entity set, so the narrative leads directly into expansion hunting. Conversely a `confirmed` hunt finding can be attached to an existing discovery as new evidence.

## 9. Acceptance criteria

1. Two consecutive cycles over an unchanged alert set produce one discovery, not two.
2. A discovery gaining a new alert is updated in place and its timeline reflects the addition.
3. Promoting creates one Case linked to every member alert and sets status `promoted`.
4. Dismissal without a reason is rejected.
5. An oversized window is trimmed deterministically and the trimming is visible in the record.
6. Markdown containing script content renders inert.

## 10. Open questions for SHB

1. Discovery cadence and window length — hourly over 24 hours is the proposed default.
2. Maximum alerts per call, bounded by the self-hosted model's context window (S0 open question 2).
3. Whether discoveries should be visible to all analysts or only to Tier 2 and above.
