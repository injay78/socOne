"""Audit trail for SIEM and EDR queries executed by ASP.

Every statement that reaches a production security system is recorded with the
normalised text, whether the guard rewrote it, how many rows came back and how
long it ran, so a query storm can always be traced back to its origin.
"""

import logging

logger = logging.getLogger("asp.siem.audit")

MAX_QUERY_LENGTH = 4000


def _anchor_model(target):
    """Audit rows need a content object; anchor a query to the configuration
    of the system it ran against."""
    from apps.settings.models import EdrTrellixConfig, SiemQRadarConfig

    return EdrTrellixConfig if target == "trellix" else SiemQRadarConfig


def _write(action, metadata):
    from django.contrib.contenttypes.models import ContentType

    from apps.audit.context import get_current_actor
    from apps.audit.models import AuditLog

    try:
        anchor = _anchor_model(metadata.get("target", "")).get_current()
        actor = get_current_actor()
        AuditLog.objects.create(
            content_type=ContentType.objects.get_for_model(type(anchor)),
            object_id=str(anchor.pk),
            action=action,
            actor=actor if getattr(actor, "is_authenticated", False) else None,
            changes={},
            metadata=metadata,
        )
    except Exception:
        logger.exception("Failed to write %s audit record", action)


def record_aql_execution(*, query, rewrites=(), row_count=0, duration_ms=0):
    metadata = {
        "target": "qradar",
        "query": str(query)[:MAX_QUERY_LENGTH],
        "guard_rewrites": list(rewrites),
        "row_count": row_count,
        "duration_ms": duration_ms,
    }
    logger.info(
        "QRadar AQL executed rows=%s duration_ms=%s rewrites=%s",
        row_count,
        duration_ms,
        list(rewrites),
    )
    _write("siem.qradar.query", metadata)


def record_edr_search(*, query, mode, rewrites=(), row_count=0, duration_ms=0):
    metadata = {
        "target": "trellix",
        "mode": mode,
        "query": str(query)[:MAX_QUERY_LENGTH],
        "guard_rewrites": list(rewrites),
        "row_count": row_count,
        "duration_ms": duration_ms,
    }
    logger.info(
        "Trellix %s search executed rows=%s duration_ms=%s",
        mode,
        row_count,
        duration_ms,
    )
    _write("edr.trellix.search", metadata)


def record_blocked_query(*, target, query, reason, detail):
    metadata = {
        "target": target,
        "query": str(query)[:MAX_QUERY_LENGTH],
        "reason": reason,
        "detail": detail,
    }
    logger.warning("%s query rejected by guard reason=%s", target, reason)
    _write(f"{target}.query.blocked", metadata)
