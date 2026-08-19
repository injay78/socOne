# ASP v0.7.0 specification index

This directory is the cross-session basis for v0.7.0: the SHB deployment — IBM QRadar on-prem, Trellix EDR SaaS, a self-hosted OpenAI-compatible LLM, and MSSP audit of Viettel Cyber Security Tier 1 handling.

Every document here is `Draft`. Nothing in this directory is binding until it is reviewed and promoted to `Confirmed`.

## Documents

| Document | Status | Content |
| --- | --- | --- |
| [00-llm-runtime-hardening.md](00-llm-runtime-hardening.md) | Draft | Structured output without tool calling, token budget, call records, Vietnamese prompts |
| [01-qradar-connector.md](01-qradar-connector.md) | Draft | QRadar as a third SIEM backend, AQL guard, push and pull ingestion |
| [02-trellix-edr-connector.md](02-trellix-edr-connector.md) | Draft | Trellix SaaS OAuth2 client, detections, hunting search, containment behind a flag |
| [03-ai-triage.md](03-ai-triage.md) | Draft | Deterministic pre-triage, structured verdict with evidence, analyst override |
| [04-clustering-threat-hunting.md](04-clustering-threat-hunting.md) | Draft | Incident clusters, hunt plans, advisory and auto execution modes |
| [05-attack-discovery.md](05-attack-discovery.md) | Draft | Periodic attack-chain narratives, deduplication, promote to Case |
| [06-ioc-verification-mcp.md](06-ioc-verification-mcp.md) | Draft | MCP web verification with mandatory citations and injection defence |
| [07-mssp-audit.md](07-mssp-audit.md) | Draft | VCS ticket ingestion, matching, audit findings, two-way accuracy metrics |
| [08-telegram-notifications.md](08-telegram-notifications.md) | Draft | Notification layer with Telegram channel, aggregation, escaping |

S0 is not part of the original eight items. It was separated out because the survey found a single shared blocker — `with_structured_output` depends on tool calling (`apps/agentic/analysis/prompts.py:55`), and `prompt_language` rejects `vi` (`apps/settings/serializers.py:571`) — that would otherwise be re-solved, differently, inside each of S3 through S7.

## Implementation order

1. **S0** — nothing that calls an LLM is trustworthy until this lands.
2. **S1** and **S2** in parallel — independent connectors, no shared code beyond the guard pattern.
3. **S3** — needs S0, and needs S1/S2 for real alert volume.
4. **S6** — becomes a default enrichment step inside S3, so it lands close behind it.
5. **S4** — needs S3 verdicts and S1/S2 query surfaces.
6. **S5** — needs S3; links to S4 clusters when present.
7. **S7** — needs S3 verdicts to compare against; the deepest dependency in the release.
8. **S8** — last, because it subscribes to events emitted by S3, S4, S5 and S7.

## Cross-dependencies

| Depends on | Required by | Nature |
| --- | --- | --- |
| S0 | S3, S4, S5, S6, S7 | shared structured-output, budget, anonymisation and call-record layer |
| S1 | S3, S4 | alert source, AQL execution for hunting |
| S2 | S3, S4 | alert source, EDR search for hunting |
| S3 | S4, S5, S7, S8 | verdicts drive clustering input, discovery ranking, audit comparison, notification filtering |
| S4 | S5, S8 | clusters feed discovery; confirmed findings emit events |
| S5 | S4, S8 | discoveries can generate hunt plans and emit events |
| S6 | S3, S4 | IOC verification as an enrichment step |
| S7 | S3, S8 | audit consumes verdicts and returns AI accuracy; critical findings emit events |

## Prerequisite outside these specs

`apps/agentic/services/playbooks.py:recover_orphaned_playbook_runs()` used `select_for_update()` together with `select_related("user", ...)` on a nullable foreign key, which PostgreSQL rejects, crash-looping the playbook worker on every start. Fixed with `select_for_update(of=("self",))` during the survey. Without it, no playbook-based skill in S6 could run.

## Rules for using these specs

- `Draft` means the product decision is not settled. Do not implement against a Draft as though it were binding.
- Model names and URLs are target design. Equivalent adjustments are allowed where the existing codebase constrains naming, but externally observable behaviour must match.
- Each item must cover backend, frontend, permissions, audit, migrations and failure behaviour before it can move to `Confirmed`.
- Do not copy this directory into `asp-doc` as user documentation. User docs are written separately once behaviour is settled.
- Open questions listed at the end of each document are unresolved with SHB or VCS. They do not block coding, but every assumption made in their absence must be stated in the implementation.
