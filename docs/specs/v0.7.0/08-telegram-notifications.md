# S8 — Telegram notification channel

Status: Draft

## 1. Purpose

Deliver AI outcomes to the security team over Telegram. Built as a general notification layer with Telegram as the first channel, so email, Teams or webhook can be added later without touching any call site.

New app `apps/notifications`.

## 2. Configuration

Managed from the settings page (`apps/settings/models.py` plus serializer, UI and migration).

**Global:** `bot_token` (write-only — the API never returns it, the UI shows `••••` and a replace action), `enabled`, `retry_limit`, `rate_limit_per_minute`, `quiet_hours_start`, `quiet_hours_end` (inside quiet hours only Critical events are sent), `asp_base_url` (for deep links).

**Destinations** — `NotificationDestination`, many rows:

| Field | Notes |
| --- | --- |
| `name` | |
| `chat_id` | supports channels (`-100…`) and groups |
| `message_thread_id` | topic id, nullable |
| `enabled` | |
| `language` | `vi` or `en` |
| `event_types` | json list of subscribed events |
| `min_severity`, `min_confidence` | thresholds |
| `verdict_filter`, `source_filter` | verdicts, and QRadar / Trellix / other |
| `min_asset_criticality` | from CMDB |

**Test message button** on the settings page, returning the real Telegram error — wrong token, bot not a channel member, invalid topic id. This is where misconfiguration concentrates; errors must not be swallowed.

## 3. Event catalogue

Registered by name so each destination can subscribe selectively:

| Event | Source |
| --- | --- |
| `triage.completed` | S3 — only TP or review-needed verdicts, never every FP |
| `triage.needs_human` | S3 — below confidence threshold |
| `discovery.created` | S5 |
| `hunt.finding_confirmed` | S4 |
| `audit.critical_finding` | S7 — `missed_true_positive`, `no_ticket_created` |
| `system.worker_unhealthy` | `apps.common.worker_health` |
| `mssp.sync_failed`, `integration.auth_failed` | S7, S1, S2 |

## 4. Delivery

**Never in the request cycle and never inside alert processing.** Events are written to `NotificationOutbox` and delivered by `manage.py run_notification_worker` on `apps.common.worker_runner.run_worker`.

- Retry with backoff up to `retry_limit`; delivery state stored per record.
- A Telegram failure or timeout must never break triage. Failures are logged and marked, never raised into the pipeline.
- Honour Telegram `429` with its `retry_after`, and stay within roughly one message per second per chat.
- **Aggregation is mandatory, not optional.** Events of the same type within a configurable window collapse into one summary message ("12 new TP alerts across 3 hosts"). An alert storm that fires 500 messages makes the channel useless.
- Deduplication: the same Case or discovery does not resend identical content. A material update sends a new message referencing the previous one rather than repeating it.

## 5. Message content

- Templates live at `backend/custom/data/notifications/<event>_<lang>.md`, following the existing `<name>_<lang>.md` convention, so SHB edits them without a deployment. `_vi` and `_en` ship for every event.
- `parse_mode=HTML`, chosen over MarkdownV2 for simpler escaping. **Every dynamic value is HTML-escaped** — hostnames, usernames, analyst closure notes and IOCs are all uncontrolled input, and indicators routinely contain format-breaking characters.
- Default body: severity and verdict, confidence, primary entity, MITRE technique, two or three lines of rationale, and a deep link to the Case or discovery in ASP.
- Content passes through the existing secret scrubber (`apps/agentic/services/playbooks.py:_sanitize_visible_text`).
- Truncated to Telegram's 4096-character limit with a "… see details in ASP" suffix, never mid-tag.
- The settings page states plainly that Telegram is an external service and messages traverse Telegram infrastructure. The default posture is **summary plus link**, never raw logs.

## 6. Models

| Model | Fields |
| --- | --- |
| `NotificationDestination` | as §2 |
| `NotificationOutbox` | `event_type`, `payload` (json), `destination` FK, `status` (`pending`, `sent`, `failed`, `suppressed`), `attempts`, `last_error`, `aggregated_count`, `dedup_key`, `scheduled_for`, `sent_at` |

Both registered in `apps/common/metadata.py` and `frontend/src/config/resources.tsx` so delivery history is visible and failed messages can be retried from the UI.

## 7. API surface

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/agent/v1/notifications/test/` | POST | send a test message |
| `/api/agent/v1/notifications/send/` | POST | emit a registered event, rate-limited |

Registered in `cli/src/asp_cli/spec/operations.json`. `send` accepts only registered event types; arbitrary message injection is not exposed.

## 8. Acceptance criteria

1. Telegram being unreachable leaves triage unaffected; messages queue and retry.
2. Fifty events of one type inside the aggregation window produce one summary message.
3. A hostname containing `<`, `&` or `>` renders correctly and does not break the message.
4. A message exceeding 4096 characters is truncated cleanly with the suffix, never mid-tag.
5. `429` with `retry_after` defers rather than hammering.
6. Quiet hours suppress non-Critical events and record them as `suppressed`, not `failed`.
7. `bot_token` never appears in any API response.
8. The test button surfaces the genuine Telegram error text.

## 9. Open questions for SHB

1. Dedicated channel or a group with topics, and who is admitted. Messages carry internal hostnames and account names, so channel membership should be approved like access to a sensitive system, not like a chat group.
2. Whether Telegram egress is permitted from the ASP host, or a proxy is required.
3. Which events each audience subscribes to — SOC shift, management, integration owners.
4. Whether Vietnamese is the default message language for all destinations.
