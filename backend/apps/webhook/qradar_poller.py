"""Pull ingestion for QRadar offences.

Polls offences by `last_persisted_time`, keeps a watermark in the cache, and
writes the same normalised payload the webhook path produces. Offences that
change after ingestion are re-emitted so downstream correlation sees the update.
"""

import logging

from django.core.cache import caches

from apps.common.redis_stream import RedisStreamClient
from apps.common.worker_runner import WorkerIterationResult
from apps.settings.runtime_config import get_qradar_config, get_stream_maxlen

logger = logging.getLogger(__name__)

WATERMARK_CACHE_KEY = "asp:qradar:offense_watermark"
WATERMARK_TTL_SECONDS = 90 * 24 * 3600
DEFAULT_BATCH_SIZE = 50


def _cache():
    return caches["default"]


def get_watermark():
    try:
        return int(_cache().get(WATERMARK_CACHE_KEY) or 0)
    except (TypeError, ValueError):
        return 0


def set_watermark(value):
    if value:
        _cache().set(WATERMARK_CACHE_KEY, int(value), WATERMARK_TTL_SECONDS)


def reset_watermark():
    _cache().delete(WATERMARK_CACHE_KEY)


def _offense_timestamp(offense):
    for key in ("last_persisted_time", "last_updated_time", "start_time"):
        value = offense.get(key)
        if isinstance(value, (int, float)) and value:
            return int(value)
    return 0


def poll_offenses_once(*, redis_client=None, client=None, batch_size=DEFAULT_BATCH_SIZE, since=None):
    """One polling iteration. Returns a WorkerIterationResult for run_worker."""
    from integrations.siem.clients import get_qradar_client
    from integrations.siem.qradar_normalize import load_offense_with_context, resolve_ingest_stream

    config = get_qradar_config()
    if not config["enabled"] or not config["poll_enabled"]:
        return WorkerIterationResult(processed=False)

    client = client or get_qradar_client()
    redis_client = redis_client or RedisStreamClient()
    watermark = get_watermark() if since is None else int(since)

    filter_expression = f"last_persisted_time > {watermark}" if watermark else None
    offenses = client.list_offenses(filter_expression=filter_expression, limit=batch_size) or []
    if not offenses:
        return WorkerIterationResult(processed=False)

    offenses = sorted(offenses, key=_offense_timestamp)
    sent = 0
    highest = watermark

    for offense in offenses:
        offense_id = offense.get("id")
        if offense_id is None:
            continue
        try:
            normalized = load_offense_with_context(offense_id, client=client)
            redis_client.send_message(
                resolve_ingest_stream(normalized["stream_name"]),
                normalized,
                maxlen=get_stream_maxlen(),
            )
        except Exception:
            logger.exception("Failed to ingest QRadar offence %s", offense_id)
            continue

        sent += 1
        highest = max(highest, _offense_timestamp(offense))

    if highest > watermark:
        set_watermark(highest)

    return WorkerIterationResult(
        processed=sent > 0,
        message=f"ingested {sent} QRadar offence(s), watermark={highest}",
    )
