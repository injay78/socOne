# S3 — AI triage for every alert

Status: Draft

## 1. Purpose

Every alert, offence and detection reaching ASP is triaged by the AI layer, producing a structured, evidence-backed, auditable verdict. Analysts stop reading raw alerts and start reviewing conclusions.

## 2. Reuse before extension

The pipeline already exists and must be extended, not duplicated:

| Existing | Location | Disposition |
| --- | --- | --- |
| Analysis job queue | `apps/agentic/models.py` `CaseAnalysisJob` | reuse as is |
| Worker | `run_agentic_case_analysis_worker` | reuse; triage becomes part of this run |
| Runner | `apps/agentic/analysis/analysis.py` `CaseAnalysisRunner` | extend |
| Case serialisation | `apps/agentic/analysis/profiles.py` `serialize_case_for_investigation` | extend with the new context tiers |
| Knowledge context | `apps/agentic/analysis/knowledge.py` | reuse |
| Result fields | `apps/agentic/services/cases.py:7` `CASE_ANALYSIS_RESULT_FIELDS` | keep; the existing `*_ai` fields stay the compatibility surface |

Structured invocation goes through S0. This spec assumes `invoke_structured()` exists and that `with_structured_output` is gone.

## 3. Deterministic pre-triage

Runs before any LLM call, to cut cost and noise.

**Deduplication** — by `correlation_uid` and by a fingerprint of rule plus primary entity plus time bucket. Already-triaged fingerprints attach to the existing result instead of re-running.

**Suppression** — new model `TriageSuppression` (migration required): `match_type` (rule / entity / subnet / user), `pattern`, `reason`, `created_by`, `expires_at`, `enabled`. Expiry is mandatory; a suppression without an end date is not allowed. Managed from the UI, fully audited. Suppressed alerts are recorded as suppressed with the matching rule, never silently dropped.

**Context assembly**, each tier fetched only if the previous ones leave budget (see S0 §5):

1. Case, alert and artifact fields.
2. CMDB (`integrations/cmdb/service.py:lookup_artifact_context`) — asset criticality, owner, environment.
3. LDAP identity — department, title, account state.
4. Threat intel (`integrations/threat_intel/service.py:query_indicator`) and, once S6 lands, IOC verification.
5. Alert history for the same entity over the last N days.

## 4. Result model

New model `TriageResult` (migration required), one per Case per run, previous runs retained:

| Field | Type | Notes |
| --- | --- | --- |
| `case` | FK | |
| `verdict` | enum | `true_positive`, `false_positive`, `benign_true_positive`, `needs_more_info` |
| `false_positive_class` | enum, nullable | `suppressed`, `verified_legitimate`, `rule_misconfiguration`, `other` — required when verdict is `false_positive` |
| `severity_ai`, `impact_ai`, `priority_ai` | enum | mirrored into the existing Case `*_ai` fields |
| `confidence` | float 0–1 | |
| `mitre_tactics`, `mitre_techniques` | json list | |
| `kill_chain_phase` | string | |
| `evidence` | json list | see below |
| `recommended_actions` | json list | each classified `investigate` / `contain` / `close` |
| `reasoning_vi`, `reasoning_en` | text | rendered rationale, not raw chain-of-thought |
| `needs_human` | bool | set when confidence is below threshold |
| `human_verdict`, `human_verdict_by`, `human_verdict_at`, `human_verdict_note` | nullable | analyst override |
| `llm_call` | FK to `LlmCallRecord` | model, prompt version, tokens, latency, raw response |

**Evidence items** carry `kind` (log / enrichment / intel / cmdb / history), `source`, `summary`, and a reference to the real record (artifact id, enrichment id, alert id). An evidence item without a resolvable reference is rejected at validation time — the model may not invent evidence.

## 5. Quality discipline

- Output is validated against the schema; failure retries with the error fed back, up to the S0 limit; terminal failure produces `needs_more_info` plus an error marker. No ambiguous state is ever persisted.
- A configurable confidence threshold sets `needs_human`, surfaced prominently in the UI.
- The LLM is not called at all when the minimum context is missing; the result is `needs_more_info` with the reason.
- `false_positive` requires a `false_positive_class`.

## 6. Prompt library

`backend/custom/data/playbooks/ai_triage/` with `system_vi.md` and `system_en.md`, plus per-family prompts: `auth`, `malware`, `network`, `data_exfil`, `insider`. Family selection is derived from alert category with a documented fallback.

Prompt version and hash are recorded on every result via `LlmCallRecord`, so a verdict can always be traced to the exact prompt text that produced it.

## 7. Frontend

- Case list: verdict, confidence and MITRE columns, plus a "needs review" badge. Registered in `apps/common/metadata.py` `RESOURCE_CONFIGS` and `frontend/src/config/resources.tsx`.
- Case detail: a triage panel showing verdict, confidence, evidence with links to the referenced records, reasoning in the user's language, and recommended actions.
- Analyst override control writing `human_verdict`. Both AI and human verdicts are retained — this pair is the ground truth used by S7 to measure AI accuracy.
- Suppression management screen.

## 8. API surface

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/agent/v1/cases/{id}/triage/` | GET | current triage result |
| `/api/agent/v1/cases/{id}/triage/` | POST | request re-triage |

Registered in `cli/src/asp_cli/spec/operations.json` with CLI commands.

## 9. Acceptance criteria

1. Every ingested alert reaches a terminal triage state; none stays unprocessed.
2. A suppressed alert is recorded as suppressed with the matching rule and consumes no LLM call.
3. An evidence item referencing a non-existent record fails validation and the result is not persisted.
4. Below-threshold confidence sets `needs_human` and shows the badge.
5. An analyst override stores both verdicts and leaves the AI verdict intact.
6. Prompt version and model name on a stored result match the files and provider that produced it.

## 10. Open questions for SHB

1. Confidence threshold for `needs_human`, and whether it varies by severity.
2. Alert volume per day, which sets the LLM throughput requirement against the self-hosted model's capacity (S0 open question 2).
3. Whether existing suppression lists already exist at VCS that should be imported rather than rebuilt.
