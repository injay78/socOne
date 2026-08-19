# S0 — LLM runtime hardening for self-hosted models

Status: Draft

## 1. Purpose

Every AI capability in this release (S3–S7) calls the same LLM layer. That layer currently assumes a commercial OpenAI-grade endpoint and breaks on the model SHB actually runs: a self-built model exposing an OpenAI-compatible `/v1/chat/completions` API.

This spec is a prerequisite, not a feature. It must land before S3.

## 2. Findings in the current code

| Item | Location | Problem |
| --- | --- | --- |
| Structured output | `apps/agentic/analysis/prompts.py:55` | `.with_structured_output(schema)` on `ChatOpenAI` defaults to **function/tool calling**. Self-hosted models frequently lack it or implement it unreliably. Single point of failure for S3–S7. |
| Provider config | `apps/settings/models.py:7` | Has `base_url`, `model`, `api_key`, `proxy`, `tags`, `priority`. Good: an arbitrary OpenAI-compatible endpoint already works. Missing: timeout, retries, JSON-mode capability, context budget. |
| Prompt language | `apps/settings/serializers.py:571` | Validator accepts only `{en, zh}`. Vietnamese is rejected at the API layer. |
| Prompt roots | `apps/agentic/analysis/prompts.py:36` vs `apps/agentic/runtime/base.py:47` | Built-in prompts live under `backend/data/playbooks/`, custom playbook prompts under `backend/custom/data/playbooks/`. Two different roots; new skills must state which they use. |
| Traceability | — | No record of model name, prompt version, token usage, latency, or raw response for any LLM call. |

## 3. Provider configuration additions

Extend `LLMProviderConfig` (migration required):

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `supports_json_mode` | bool | `False` | Send `response_format={"type":"json_object"}` only when true |
| `supports_tool_calling` | bool | `False` | Reserved; never required by any skill in this release |
| `context_window_tokens` | int | `32768` | Input budget ceiling used by the trimming layer |
| `max_output_tokens` | int | `4096` | Passed to the request |
| `request_timeout_seconds` | int | `120` | Per-call timeout, independent of `ASP_WEB_TIMEOUT` |
| `max_retries` | int | `2` | Transport-level retries |

No endpoint or model name may be hard-coded anywhere in the codebase. `base_url` and `model` always come from this table.

## 4. Structured invocation contract

New module `integrations/llm/structured.py`. Exactly one entry point for every skill:

```
invoke_structured(prompt_id, payload, output_schema, *, model_tag, budget=None) -> (instance, LlmCallRecord)
```

Pipeline, in order:

1. **Schema in the prompt.** Render the JSON Schema of `output_schema` into the system prompt with an explicit "respond with a single JSON object, no prose, no code fence" instruction. Never rely on the server enforcing it.
2. **Optional JSON mode.** Attach `response_format={"type":"json_object"}` only when the selected provider has `supports_json_mode=True`.
3. **Extraction and repair** (`extract_json_object()`), applied to every response: strip ```` ```json ```` fences, cut leading/trailing prose around the outermost balanced `{...}`, remove trailing commas, normalise smart quotes. Repair is best-effort and must never silently alter values inside strings.
4. **Validation** against the Pydantic schema.
5. **Retry with feedback** on failure: re-send with the validation error text appended, up to `max_retries` attempts. Attempts are logged individually.
6. **Terminal failure is explicit.** Raise `StructuredOutputError`. Callers decide the fallback; no caller may substitute a guessed object.

`apps/agentic/analysis/prompts.py:invoke_structured_llm` is rewritten to delegate here. `with_structured_output` is removed from the codebase.

## 5. Token budget

New `integrations/llm/budget.py`. Callers pass a `PayloadBudget` describing priority tiers (for example: case fields > latest alerts > enrichments > historical alerts). The layer serialises highest tier first and drops or truncates lower tiers until the estimated token count fits `context_window_tokens` minus `max_output_tokens` and a fixed prompt allowance.

Dropped content is not silent: the record reports which tiers were trimmed, and skills must surface that in their output metadata.

Token estimation uses a character-per-token ratio configurable per provider; exact tokenisation is out of scope because the self-hosted tokenizer is unknown.

## 6. Anonymisation hook (default off)

The placeholder-substitution layer required by S5 is implemented here, not in Attack Discovery, so every skill inherits it:

- `anonymization_enabled` (bool, default `False`) plus a configurable field list in `RuntimeConfig`.
- When enabled, hostnames, usernames, internal IPs and emails are replaced with stable placeholders before the request and rehydrated in the response before persistence.
- Rationale for defaulting off: the model runs inside SHB, data does not leave the bank, and real identifiers materially improve analysis quality.

## 7. Call record

New model `LlmCallRecord` (migration required): `prompt_id`, `prompt_version`, `prompt_hash`, `provider_name`, `model_name`, `attempts`, `success`, `error`, `tokens_in`, `tokens_out`, `latency_ms`, `trimmed_tiers`, `raw_response` (truncated to a configurable ceiling), `created_at`, plus nullable references to the originating Case / Playbook run / discovery.

Token counts come from the `usage` block when the server returns one; absent usage is recorded as null, never estimated as fact.

`raw_response` passes through the same secret scrubber already used for playbook run messages (`apps/agentic/services/playbooks.py:_sanitize_visible_text`) before storage.

## 8. Vietnamese prompt language

- Extend the `prompt_language` validator to `{en, zh, vi}` and the frontend selector accordingly.
- Add `System_vi.md` and `KnowledgeKeywords_vi.md` under `backend/data/playbooks/investigation/`, and `System_vi.md` under `backend/data/playbooks/knowledge_extraction/`.
- Every new prompt directory introduced by S3–S8 ships `_vi` and `_en` at minimum.
- Missing prompt file must raise a clear error naming the expected path, matching current `read_prompt()` behaviour.

## 9. Acceptance criteria

1. A provider with `supports_json_mode=False` and no tool-calling support completes an investigation successfully.
2. A response wrapped in a code fence, and a response with trailing prose, both validate after repair.
3. A response that never validates produces `StructuredOutputError` and an `LlmCallRecord` with `success=False` and all attempts recorded — no partial write to the Case.
4. An oversized payload is trimmed deterministically and the trimmed tiers are reported.
5. `prompt_language=vi` is accepted and Vietnamese prompts are used end to end.
6. No file in the repository contains a hard-coded model name or provider endpoint.

## 10. Open questions for SHB

1. Does the self-hosted endpoint accept `response_format: {"type":"json_object"}`? If yes, `supports_json_mode` can default on for that provider record.
2. Actual context window and practical throughput (requests/minute, concurrent requests). Drives budget defaults in S3 and the batch size in S5.
3. Does the endpoint return a `usage` block? Without it, cost and token reporting in S7 dashboards is unavailable and must be marked as such rather than estimated.
