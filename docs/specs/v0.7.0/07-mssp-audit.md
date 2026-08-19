# S7 — MSSP audit of Tier 1 handling

Status: Draft

## 1. Purpose

SHB outsources monitoring to Viettel Cyber Security. VCS Tier 1 works alerts, cases and tickets in VCS's own SOAR. ASP pulls those outcomes in, matches them to its own Cases, and compares them against AI triage (S3) to find divergence.

This output is used in supplier conversations. It must be precise, evidence-backed, and never conclusive without human review.

New app `apps/mssp`.

## 2. Ticket ingestion

VCS SOAR exposes an API for alerts, cases, tickets and report export. `rest_api` is the primary adapter and is built first.

**Interface** `MsspTicketSource` with three implementations:

| Adapter | Role |
| --- | --- |
| `rest_api` | primary; incremental sync |
| `file_import` | fallback; CSV/XLSX via UI and CLI |
| `manual` | single-record entry |

**`rest_api` requirements:**

- Base URL plus auth, supporting both API-key header and OAuth2 client-credentials, selected by configuration.
- **Incremental sync by `updated_at` watermark.** Never a full re-pull.
- Backfill over an explicit date range through a management command.
- Upsert by `external_id`.
- Tickets change state over time (open → in progress → closed → reopened). Every transition is stored in `MsspTicketEvent`, because SLA auditing and closure auditing need real timestamps, not just the final state.
- Where VCS exposes a report-export endpoint, wrap it as a second comparison source: VCS's self-reported numbers versus ASP's numbers computed from raw tickets. A divergence is its own finding category.
- **Field mapping is JSON configuration**, not code. A ticket format change must not require a deployment.

Worker `manage.py run_mssp_sync_worker` on `apps.common.worker_runner.run_worker`.

## 3. Models

| Model | Key fields |
| --- | --- |
| `MsspTicket` | `external_id`, `source_system`, `title`, `rule_name`, `siem_offense_id`, `entities` (json), `severity_tier1`, `verdict_tier1`, `status`, `assignee`, `created_at`, `acknowledged_at`, `closed_at`, `closure_reason`, `closure_note`, `actions_taken` (json), `escalated_to_tier`, `raw_payload` |
| `MsspTicketEvent` | FK ticket, `from_status`, `to_status`, `occurred_at`, `actor`, `note` |
| `MsspTicketMatch` | FK ticket, nullable FK case, nullable FK alert, `match_method`, `match_confidence`, `confirmed_by`, `confirmed_at` |
| `AuditFinding` | FK ticket and/or case, `category`, `severity`, `detail`, `evidence` (json), `status`, `reviewed_by`, `reviewed_at`, `review_note`, `ai_was_wrong` (bool), `llm_call` nullable FK |

All require migrations.

## 4. Matching

Keys in descending confidence:

1. QRadar offence id present on both sides.
2. Explicit external reference stored on the Case.
3. Rule name plus time window plus overlapping entity.
4. Entity similarity score.

`match_method` and `match_confidence` are stored. Ambiguous matches go to a human confirmation queue; the engine does not decide them.

Both unmatched directions are business signals and are displayed separately:

- **Ticket with no ASP Case** — an ASP visibility gap, or VCS acting on data ASP does not see.
- **ASP Case triaged `true_positive` with no ticket** — Tier 1 missed it. This is the single most important number the system produces.

## 5. Audit engine

**Deterministic checks run first.** The LLM never computes timing or counting:

- SLA acknowledge and resolve against contractual thresholds, configurable per severity.
- Missing mandatory handling steps.
- Missing ticket.
- Closure without a valid closure reason.

**Comparison checks** produce `AuditFinding` records:

| Category | Meaning |
| --- | --- |
| `missed_true_positive` | AI says TP, Tier 1 closed as FP — highest severity |
| `no_ticket_created` | TP Case with no ticket |
| `over_escalation` | AI says FP or benign, Tier 1 escalated |
| `severity_mismatch` | severity differs beyond tolerance |
| `sla_breach` | acknowledge or resolve threshold exceeded |
| `missing_investigation_step` | required step absent |
| `insufficient_evidence` | closure note fails the rubric |
| `incorrect_closure_reason` | closure reason inconsistent with the evidence |
| `reported_metric_mismatch` | VCS-reported figures differ from ASP's computation over raw tickets |

**Closure-note rubric** lives at `backend/custom/data/playbooks/mssp_audit/rubric_vi.md` (plus `_en`) so SHB can tune it without a deployment. Scoring is 0–100 across criteria, and **every criterion score must quote the closure note text it is based on**. Unquoted criticism is not admissible.

**Sampling** — audit everything, or a configurable percentage, optionally stratified by severity.

## 6. Two-way review — mandatory

- Every `AuditFinding` carries `status` ∈ `open`, `accepted`, `disputed`, `resolved`, `invalid`, with reviewer and note. **No finding is a conclusion until a human has reviewed it.**
- When a reviewer marks a finding `invalid` or `disputed` because the **AI** was wrong, `ai_was_wrong` is set. The dashboard shows Tier 1 error rate and AI error rate side by side.
- This is not a one-way supplier-policing tool. The same data is the feedback loop for tuning S3 prompts.
- Metrics default to team level. Per-analyst metrics are off unless explicitly enabled, and enabling them displays a warning about data limitations and contractual meaning.
- There is no automatic transmission of audit results to VCS. Export is a manual, confirmed action.

## 7. Reporting

Metrics: coverage (share of Cases with a ticket), AI↔Tier 1 agreement rate, missed-TP rate, over-escalation rate, SLA compliance by severity, MTTA/MTTD/MTTR, finding distribution by category, weekly and monthly trend.

Dashboard page plus XLSX and PDF export, reusing the existing dashboard cache mechanism (`run_dashboard_cache_worker`).

**Every number drills down** to the underlying tickets, Cases and findings. A figure that cannot be traced to records is unusable in a supplier meeting and is therefore not shipped.

## 8. Frontend

- `MSSP Ticket` and `Audit Finding` resources registered in `apps/common/metadata.py` and `frontend/src/config/resources.tsx`.
- Side-by-side reconciliation view: Tier 1 ticket | AI triage | divergence.
- Match confirmation queue.
- Finding review screen with status, note, and the `ai_was_wrong` control.

## 9. API surface

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/agent/v1/mssp/tickets/` | GET, POST | list, or import a batch |
| `/api/agent/v1/mssp/tickets/import/` | POST | file import |
| `/api/agent/v1/mssp/findings/` | GET | list findings |
| `/api/agent/v1/mssp/findings/{id}/review/` | POST | record a review decision |
| `/api/agent/v1/mssp/reports/` | GET | metrics with drill-down references |

Registered in `cli/src/asp_cli/spec/operations.json`.

## 10. Acceptance criteria

1. A ticket that changes state three times yields three `MsspTicketEvent` rows and one `MsspTicket`.
2. Re-running sync imports only records changed since the watermark.
3. An ambiguous match is queued for confirmation rather than auto-assigned.
4. A TP Case without a ticket produces `no_ticket_created`.
5. Every rubric criterion score quotes the closure-note text supporting it.
6. Marking a finding `invalid` with AI at fault moves the AI error-rate metric.
7. Every dashboard figure drills down to the underlying records.
8. Changing the ticket field mapping requires no code change.

## 11. Open questions for SHB and VCS

1. **Ticket payload shape and completeness** — is `acknowledged_at` present, is a closure note mandatory, is there a normalised verdict field or only free text. If acknowledgement timestamps are absent, SLA auditing must be redefined against another field. Sample several dozen real tickets before building the matching engine.
2. Contractual SLA thresholds per severity.
3. Intended use of audit output — internal only, supplier discussion, or tied to contractual penalties. This sets the required strictness of human review and whether per-analyst metrics are ever enabled.
4. Whether VCS's report-export endpoint is available to SHB, which enables `reported_metric_mismatch`.
