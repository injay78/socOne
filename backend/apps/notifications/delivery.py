"""Outbox delivery: rendering, aggregation, rate limiting and retry."""

import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.common.worker_runner import WorkerIterationResult
from apps.notifications.models import NotificationOutbox, OutboxStatus
from apps.notifications.rendering import render_aggregate, render_message
from apps.notifications.telegram import (
    TelegramError,
    TelegramRateLimited,
    send_message,
)

logger = logging.getLogger(__name__)

BATCH_SIZE = 20
MIN_INTERVAL_SECONDS = 1.0


def _config():
    from apps.settings.runtime_config import get_telegram_config

    return get_telegram_config()


def claim_batch(limit=BATCH_SIZE):
    """Claim due pending messages, oldest first."""
    now = timezone.now()
    with transaction.atomic():
        rows = list(
            NotificationOutbox.objects.select_for_update(skip_locked=True)
            .filter(status=OutboxStatus.PENDING)
            .filter(scheduled_for__lte=now)
            .order_by("created_at")[:limit]
        )
    return rows


def _group_for_aggregation(rows, threshold):
    """Split rows into (single, aggregated) work items per destination+event."""
    buckets = {}
    for row in rows:
        buckets.setdefault((row.destination_id, row.event_type), []).append(row)

    singles, aggregates = [], []
    for (_destination_id, _event_type), bucket in buckets.items():
        if len(bucket) >= threshold:
            aggregates.append(bucket)
        else:
            singles.extend(bucket)
    return singles, aggregates


def _mark_sent(rows, text):
    now = timezone.now()
    for row in rows:
        row.status = OutboxStatus.SENT
        row.sent_at = now
        row.attempts += 1
        row.rendered_text = text[:8000]
        row.save(update_fields=["status", "sent_at", "attempts", "rendered_text", "updated_at"])


def _mark_failure(rows, error, *, retry_limit, retry_after=None):
    now = timezone.now()
    for row in rows:
        row.attempts += 1
        row.last_error = str(error)[:1000]
        if row.attempts >= retry_limit:
            row.status = OutboxStatus.FAILED
        else:
            backoff = retry_after if retry_after else min(2 ** row.attempts, 300)
            row.scheduled_for = now + timedelta(seconds=backoff)
        row.save(update_fields=["attempts", "last_error", "status", "scheduled_for", "updated_at"])


def _send(rows, text, config):
    destination = rows[0].destination
    if destination is None:
        _mark_failure(rows, "Destination was deleted.", retry_limit=1)
        return False

    try:
        send_message(
            bot_token=config["bot_token"],
            chat_id=destination.chat_id,
            text=text,
            message_thread_id=destination.message_thread_id,
        )
    except TelegramRateLimited as exc:
        logger.warning("Telegram rate limited; deferring %d message(s)", len(rows))
        _mark_failure(rows, exc, retry_limit=config["retry_limit"], retry_after=exc.retry_after or 30)
        return False
    except TelegramError as exc:
        logger.warning("Telegram delivery failed: %s", exc)
        _mark_failure(rows, exc, retry_limit=config["retry_limit"])
        return False

    _mark_sent(rows, text)
    return True


def deliver_once(limit=BATCH_SIZE):
    """One delivery iteration for run_worker."""
    config = _config()
    if not config["enabled"]:
        return WorkerIterationResult(processed=False)
    if not config["bot_token"]:
        return WorkerIterationResult(processed=False, message="Telegram bot token is not configured.")

    rows = claim_batch(limit)
    if not rows:
        return WorkerIterationResult(processed=False)

    singles, aggregates = _group_for_aggregation(rows, config["aggregation_threshold"])
    sent = 0

    for bucket in aggregates:
        language = bucket[0].destination.language if bucket[0].destination else "vi"
        text = render_aggregate(
            bucket[0].event_type,
            [row.payload for row in bucket],
            language=language,
        )
        if _send(bucket, text, config):
            sent += len(bucket)

    for row in singles:
        language = row.destination.language if row.destination else "vi"
        text = render_message(row.event_type, row.payload, language=language)
        if _send([row], text, config):
            sent += 1

    return WorkerIterationResult(
        processed=bool(rows),
        message=f"delivered {sent}/{len(rows)} notification(s)",
    )
