# S6 — IOC verification through web MCP

Status: Draft

## 1. Purpose

Verify indicators using both structured sources (OTX and OpenCTI, already integrated) and web search through MCP servers, then have the LLM synthesise a verdict **with citations**.

This is the one skill in the release whose traffic leaves SHB's network. Its guardrails are correspondingly strict.

## 2. MCP client layer

New package `integrations/mcp/`:

- Shared client supporting `stdio` and streamable HTTP transports.
- Runtime configuration `McpServerConfig` (migration required, non-singleton): `name`, `transport`, `url_or_command`, `auth_header`, `token` (write-only), `timeout_seconds`, `allowed_tools` (json list), `enabled`.
- Only tools named in `allowed_tools` may be invoked. An unlisted tool is a hard error, not a warning.
- Health check per server, surfaced on the settings page.
- Every tool result is treated as untrusted data (§5).

## 3. Verification pipeline

Ordered, with early exit once confidence is sufficient:

1. **Normalise and classify** — ip / domain / url / md5 / sha1 / sha256 / email. Handle defanged forms (`hxxp`, `[.]`, `(.)`). Validate syntax.
   Internal indicators (RFC1918, SHB-owned domains, internal mail domains) are flagged and **never sent to any external source**. The internal ranges are configurable.
2. **Cache** — new model `IocVerification` keyed by `(type, value)` with a per-type TTL (file hashes age slowly, IPs quickly).
3. **Structured sources** — OTX and OpenCTI through `integrations/threat_intel/service.py:query_indicator`, plus any provider registered there later.
4. **Web MCP** — vendor advisories, CERT bulletins, threat-intel reports, abuse feeds. Domains on a configurable reputable-source allowlist are weighted up; unknown sources are weighted down but retained.
5. **Synthesis** — through the S0 structured contract.

## 4. Result schema

| Field | Type |
| --- | --- |
| `verdict` | `malicious`, `suspicious`, `benign`, `unknown` |
| `confidence` | float 0–1 |
| `first_seen`, `last_seen` | nullable date |
| `categories` | json list — c2, phishing, malware family, tor, vpn, cdn, scanner … |
| `associated_actors`, `associated_campaigns` | json list |
| `references` | json list of `{url, title, published_at, quote}` |
| `notes_vi`, `notes_en` | text |
| `sources_used` | json list of provider and MCP server names |
| `llm_call` | FK to `LlmCallRecord` |

## 5. Anti-hallucination and anti-abuse rules

These are acceptance-blocking, not advisory:

1. A `malicious` or `suspicious` verdict **requires at least one reference actually retrieved** during this run. With no retrievable source the verdict is `unknown`.
2. The model may only select references from the collected candidate set. Every returned URL is validated against that set; an invented URL fails validation and triggers a retry.
3. **The indicator itself is never contacted.** No fetching a suspicious URL, no direct resolution that would reveal investigation activity to the adversary. Verification happens exclusively through intermediary sources.
4. Retrieved web content enters the prompt wrapped in explicit untrusted-data delimiters, labelled as data, and passed through a prompt-injection filter. Instructions found inside retrieved content are never followed.
5. Rate limiting and caching protect MCP quota.
6. The UI states plainly that indicators sent to external services may disclose investigation activity, and offers an internal-sources-only mode.

## 6. Exposure — three surfaces

1. **Playbook** — `backend/custom/playbooks/ioc_verify.py`, `RISK_LEVEL = "Low"`, prompts under `backend/custom/data/playbooks/ioc_verify/` with `_vi` and `_en`. Analysts run it from the Case UI.
2. **Agent API** — `/api/agent/v1/intel/verify/` for single and bulk verification, registered in `cli/src/asp_cli/spec/operations.json` with a CLI command.
3. **Internal function** — called by S3 triage as a default enrichment step and by S4 hunting when a new indicator appears.

Results are written as `Enrichment` records. This requires new `EnrichmentProvider` choices (`apps/enrichments/models.py:43`) for the MCP-derived sources, with a migration.

## 7. Frontend

Verification results render in the Artifact and Enrichment tabs of a Case: verdict badge, confidence, clickable references with titles and dates, source list, and a Re-verify action. Cached results show their age and TTL.

## 8. Acceptance criteria

1. An internal IP is classified as internal and produces no outbound request of any kind.
2. A verdict of `malicious` with no retrievable reference is impossible; the result degrades to `unknown`.
3. A fabricated URL in the model output fails validation and retries.
4. Retrieved page content containing instruction-like text does not alter the verdict; the injection filter records the attempt.
5. A repeat verification within TTL is served from cache with no external call.
6. Defanged input resolves to the same cache entry as its plain form.

## 9. Open questions for SHB

1. Which MCP servers are approved for use from the bank's network, and through which egress path or proxy.
2. Whether external verification is permitted at all for indicators drawn from customer-facing systems, or restricted to infrastructure indicators.
3. The reputable-source allowlist SHB wants to start with.
4. Whether a commercial feed (VirusTotal, AbuseIPDB — both already present as `EnrichmentProvider` choices) will be licensed, which would reduce reliance on web search.
