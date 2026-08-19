# S4 — Alert clustering and threat hunting expansion

Status: Draft

## 1. Purpose

Two capabilities that share an entity model:

1. Group scattered alerts and Cases into incident clusters by shared entity, time proximity and ATT&CK relationship.
2. Turn a cluster plus its triage result into a hunting plan — hypotheses and concrete QRadar/Trellix queries — and, optionally, execute them read-only.

## 2. Data model decision: new `IncidentCluster`, not an extended Case

The specification asks this to be argued before implementation.

**Why not reuse `Case`.** A Case is already the correlation unit at one level down: `create_alert_with_context` (`apps/agentic/services/alerts.py:44`) collapses alerts sharing a `correlation_uid` into one Case. Making a Case also the container of other Cases overloads one model with two different grouping semantics, and every existing list view, metric and SLA rule would silently start counting container Cases as ordinary Cases.

**Why not reuse `CaseRelationship`** (`apps/cases/models.py:137`, types `Related` / `Duplicate of` / `Parent of`). It is a pairwise, human-curated, weak link introduced in v0.6.0. Clustering is an N-way machine-generated grouping with a score, a time window and a lifecycle. Forcing it into pairwise rows loses the cluster identity, and machine-generated edges would pollute the analyst-curated relationship graph.

**Decision.** New model `IncidentCluster` plus a membership table. It links to Cases and Alerts rather than replacing them, and it may *propose* `CaseRelationship` rows, which remain a human-owned surface.

## 3. Clustering

New package `apps/agentic/correlation/`, worker `manage.py run_agentic_correlation_worker` on `apps.common.worker_runner.run_worker`.

**Entity extraction** — host, user, source and destination IP, file hash, domain, process, account, drawn from Alert and Artifact records.

**Clustering** — sliding window (configurable). Edges are scored by shared entities, time proximity and ATT&CK tactic adjacency; a configurable threshold decides membership.

**Models** (migration required):

| Model | Fields |
| --- | --- |
| `IncidentCluster` | `cluster_id` (readable id), `title`, `primary_entities` (json), `window_start`, `window_end`, `link_score`, `status` (`open`, `merged`, `closed`), `case_count`, `alert_count`, `created_at`, `updated_at`, `fingerprint` |
| `IncidentClusterMember` | FK cluster, nullable FK case, nullable FK alert, `joined_at`, `contribution_score` |

**Idempotency is a hard requirement.** Clusters are keyed by a fingerprint over the sorted primary entity set. A re-run must update an existing cluster and add members, never create a duplicate. A cluster that grows is extended; a cluster that splits is recorded as a merge/split event rather than silently replaced.

## 4. Hunt plans

New package `apps/agentic/hunting/`.

The LLM receives a cluster plus its triage results and returns a `HuntPlan` through the S0 structured contract.

| Model | Fields |
| --- | --- |
| `HuntPlan` | FK cluster, `status`, `mode` (`advisory` / `auto`), `hypotheses_count`, `llm_call` FK, `created_by`, timestamps |
| `HuntHypothesis` | FK plan, `statement`, `mitre_technique`, `rationale`, `status` |
| `HuntQuery` | FK hypothesis, `target` (`qradar` / `trellix`), `query_text`, `purpose`, `expected_evidence`, `negative_interpretation`, `status`, `row_count`, `sample_rows` (json), `duration_ms`, `guard_rejection_reason`, `executed_at`, `executed_by` |
| `HuntFinding` | FK hypothesis, `conclusion` (`confirmed` / `refuted` / `inconclusive`), `evidence` (json with record references), `llm_call` FK |

## 5. Execution modes

**`advisory` (default)** — nothing is executed. The UI renders each query with its purpose, how to read a positive versus negative result, a copy button, and a deep link into the QRadar or Trellix console. This is the mode SHB starts in.

**`auto`** — each query passes through the S1 AQL guard or the S2 Trellix guard, executes read-only, and results return to the model for a conclusion, for at most N iterations.

Guard rejections are shown to the analyst with the reason. A rejected query is never silently skipped.

## 6. Budget and guardrails

Runtime configuration: maximum queries per plan, plans per hour, time-window ceiling, row ceiling, token ceiling per plan, and maximum concurrent SIEM searches. Exceeding any ceiling stops the plan and records why.

The concurrency ceiling matters beyond ASP: this is a production bank SIEM, and `auto` mode is the one feature in this release capable of degrading it. Its default is deliberately conservative and tied to S1 open question 1.

Executed queries are written to the audit log. Stored rows pass through the same secret scrubber used for playbook run messages (`apps/agentic/services/playbooks.py:_sanitize_visible_text`).

A `confirmed` finding proposes raising Case severity or opening a new Case. It never does so on its own.

## 7. Frontend

Hunt Plan list plus a detail page rendering hypothesis → query → finding as a tree, with a per-query Run action (confirmation required) available in advisory mode. Cluster list and detail showing members and the entity graph summary. Both registered in `apps/common/metadata.py` and `frontend/src/config/resources.tsx`.

## 8. API surface

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/agent/v1/clusters/` | GET | list clusters |
| `/api/agent/v1/clusters/{id}/` | GET | cluster detail with members |
| `/api/agent/v1/hunt/plans/` | GET, POST | list or generate a plan |
| `/api/agent/v1/hunt/plans/{id}/` | GET | plan detail |
| `/api/agent/v1/hunt/queries/{id}/run/` | POST | execute one guarded query |

Registered in `cli/src/asp_cli/spec/operations.json` so Tier 3 analysts can drive hunting from a Claude Code plugin.

## 9. Acceptance criteria

1. Running the correlation worker twice over the same window produces the same clusters, with no duplicates.
2. A cluster that gains a new alert is updated, not recreated.
3. In `advisory` mode no query executes and nothing touches QRadar or Trellix.
4. In `auto` mode a query exceeding the window ceiling is rejected, the reason is displayed, and the plan continues.
5. Plan budget exhaustion stops execution and is visible in the UI.
6. Every executed query appears in the audit log with actor, duration and row count.

## 10. Open questions for SHB

1. Concurrent Ariel search limit (shared with S1) — sets the `auto` mode ceiling.
2. Whether `auto` mode is permitted at all on production QRadar, or hunting stays advisory-only for the first phase.
3. Clustering window length appropriate to SHB's alert volume and shift pattern.
