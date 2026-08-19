"""Pull ingestion for Trellix EDR detections.

Walks threats → affected hosts → detections, exactly as the tenant API is
structured, and writes one Redis Stream message per detection. The watermark is
the newest `lastDetected` seen, so a re-run picks up where the last one stopped.
"""

import logging
from datetime import datetime, timedelta, timezone

from django.core.cache import caches

from apps.common.redis_stream import RedisStreamClient
from apps.common.worker_runner import WorkerIterationResult
from apps.settings.runtime_config import get_stream_maxlen, get_trellix_config

logger = logging.getLogger(__name__)

WATERMARK_CACHE_KEY = "asp:trellix:detection_watermark"
WATERMARK_TTL_SECONDS = 90 * 24 * 3600
TRELLIX_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_BATCH_SIZE = 50
DEFAULT_LOOKBACK_DAYS = 7
MAX_THREATS_PER_RUN = 25


def get_watermark():
    return caches["default"].get(WATERMARK_CACHE_KEY)


def set_watermark(value):
    if value:
        caches["default"].set(WATERMARK_CACHE_KEY, value, WATERMARK_TTL_SECONDS)


def reset_watermark():
    caches["default"].delete(WATERMARK_CACHE_KEY)


def parse_trellix_time(value):
    if not value:
        return None
    try:
        return datetime.strptime(str(value), TRELLIX_TIME_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        logger.warning("Unparsable Trellix timestamp: %r", value)
        return None


def to_epoch_ms(moment):
    return int(moment.timestamp() * 1000)


def _since(watermark, lookback_days=DEFAULT_LOOKBACK_DAYS):
    parsed = parse_trellix_time(watermark)
    if parsed is None:
        parsed = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    return parsed


def poll_detections_once(
    *,
    redis_client=None,
    client=None,
    batch_size=DEFAULT_BATCH_SIZE,
    since=None,
    max_threats=MAX_THREATS_PER_RUN,
):
    from integrations.edr.trellix_client import get_trellix_client
    from integrations.edr.trellix_normalize import normalize_detection, resolve_ingest_stream

    config = get_trellix_config()
    if not config["enabled"] or not config["poll_enabled"]:
        return WorkerIterationResult(processed=False)

    client = client or get_trellix_client()
    redis_client = redis_client or RedisStreamClient()

    watermark = since or get_watermark()
    since_moment = _since(watermark, config.get("ingest_lookback_days") or DEFAULT_LOOKBACK_DAYS)
    since_epoch_ms = to_epoch_ms(since_moment)

    threats = client.list_threats(
        since_epoch_ms=since_epoch_ms,
        severities=config.get("threat_severities"),
        score_range=[config.get("threat_score_min") or 30],
        page_size=batch_size,
    )
    if not threats:
        return WorkerIterationResult(processed=False)

    newest = since_moment
    sent = 0
    seen_detections = set()

    for listed_threat in threats[:max_threats]:
        threat_id = listed_threat.get("id")
        if threat_id is None:
            continue

        # The list payload omits file hashes and the interpreter process; one
        # detail call per threat buys artifacts the analyst can actually pivot on.
        threat = dict(listed_threat)
        try:
            threat.update(client.get_threat(threat_id) or {})
        except Exception:
            logger.warning("Falling back to list fields for Trellix threat %s", threat_id, exc_info=True)

        try:
            hosts = client.list_affected_hosts(threat_id, since_epoch_ms=since_epoch_ms, page_size=batch_size)
        except Exception:
            logger.exception("Failed to load affected hosts for Trellix threat %s", threat_id)
            continue

        for affected_host in hosts:
            host_id = affected_host.get("id")
            if host_id is None:
                continue
            try:
                detections = client.list_detections(
                    threat_id, host_id, since_epoch_ms=since_epoch_ms, page_size=batch_size
                )
            except Exception:
                logger.exception(
                    "Failed to load detections for Trellix threat %s host %s", threat_id, host_id
                )
                continue

            for detection in detections:
                detection_id = str(detection.get("id") or "")
                if not detection_id or detection_id in seen_detections:
                    continue
                seen_detections.add(detection_id)

                detected_at = parse_trellix_time(detection.get("lastDetected"))
                if detected_at is not None and detected_at <= since_moment:
                    # Already ingested on a previous run.
                    continue

                try:
                    normalized = normalize_detection(
                        threat,
                        affected_host,
                        detection,
                        console_url=client.console_url(
                            threat_id=threat_id,
                            trace_id=detection.get("traceId", ""),
                            ma_guid=((detection.get("host") or {}).get("maGuid") or ""),
                            sha256=detection.get("sha256", ""),
                        ),
                    )
                    redis_client.send_message(
                        resolve_ingest_stream(normalized["stream_name"]),
                        normalized,
                        maxlen=get_stream_maxlen(),
                    )
                except Exception:
                    logger.exception("Failed to ingest Trellix detection %s", detection_id)
                    continue

                sent += 1
                if detected_at is not None and detected_at > newest:
                    newest = detected_at

    if newest > since_moment:
        set_watermark(newest.strftime(TRELLIX_TIME_FORMAT))

    return WorkerIterationResult(
        processed=sent > 0,
        message=(
            f"ingested {sent} Trellix detection(s) from {len(threats)} threat(s), "
            f"watermark={newest.strftime(TRELLIX_TIME_FORMAT)}"
        ),
    )
