"""Queueing side of notifications.

Emitting never touches the network: events land in the outbox and a worker
delivers them. A Telegram outage must never break alert processing.
"""

import hashlib
import html
import logging
import re
from datetime import timedelta

from django.utils import timezone

from apps.notifications.events import (
    CRITICAL_EVENTS,
    NotificationEvent,
    severity_rank,
)
from apps.notifications.models import (
    NotificationDestination,
    NotificationOutbox,
    OutboxStatus,
)

logger = logging.getLogger(__name__)

VALID_EVENTS = {choice.value for choice in NotificationEvent}


def _config():
    from apps.settings.runtime_config import get_telegram_config

    return get_telegram_config()


def _in_quiet_hours(config, now=None):
    start = config.get("quiet_hours_start")
    end = config.get("quiet_hours_end")
    if start is None or end is None:
        return False

    hour = (now or timezone.localtime()).hour
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _passes_filters(destination, event_type, payload):
    if not destination.subscribes_to(event_type):
        return False

    if destination.min_severity:
        if severity_rank(payload.get("severity")) < severity_rank(destination.min_severity):
            return False

    # needs_human exists precisely because confidence is low; gating it on
    # min_confidence would filter out the one event a human must see.
    if destination.min_confidence and event_type != NotificationEvent.TRIAGE_NEEDS_HUMAN.value:
        try:
            if float(payload.get("confidence") or 0.0) < destination.min_confidence:
                return False
        except (TypeError, ValueError):
            return False

    if destination.verdict_filter and payload.get("verdict") not in destination.verdict_filter:
        return False

    if destination.source_filter and payload.get("source") not in destination.source_filter:
        return False

    if destination.min_asset_criticality:
        if severity_rank(payload.get("asset_criticality")) < severity_rank(destination.min_asset_criticality):
            return False

    return True


def build_dedup_key(event_type, payload):
    subject = str(payload.get("case_id") or payload.get("discovery_id") or payload.get("entity") or "")
    raw = f"{event_type}|{subject}|{payload.get('verdict', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def emit(event_type, payload, *, destinations=None):
    """Queue one event for every subscribed destination.

    Returns the created outbox rows. Failures here are logged, never raised,
    so a notification problem cannot break the pipeline that emitted it.
    """
    try:
        return _emit(event_type, payload, destinations=destinations)
    except Exception:
        logger.exception("Failed to queue notification event %s", event_type)
        return []


def _emit(event_type, payload, *, destinations=None):
    if event_type not in VALID_EVENTS:
        raise ValueError(f"Unknown notification event: {event_type}")

    config = _config()
    if not config["enabled"]:
        return []

    quiet = _in_quiet_hours(config)
    is_critical = event_type in CRITICAL_EVENTS

    targets = destinations if destinations is not None else NotificationDestination.objects.filter(enabled=True)
    dedup_key = build_dedup_key(event_type, payload)
    window = timedelta(seconds=config["aggregation_window_seconds"])
    created = []

    for destination in targets:
        if not _passes_filters(destination, event_type, payload):
            continue

        if quiet and not is_critical:
            created.append(
                NotificationOutbox.objects.create(
                    event_type=event_type,
                    destination=destination,
                    payload=payload,
                    status=OutboxStatus.SUPPRESSED,
                    last_error="Suppressed by quiet hours.",
                    dedup_key=dedup_key,
                )
            )
            continue

        duplicate = (
            NotificationOutbox.objects.filter(
                destination=destination,
                dedup_key=dedup_key,
                created_at__gte=timezone.now() - window,
            )
            .exclude(status=OutboxStatus.FAILED)
            .first()
        )
        if duplicate is not None:
            # Same subject inside the window: count it instead of resending.
            duplicate.aggregated_count += 1
            duplicate.save(update_fields=["aggregated_count", "updated_at"])
            continue

        created.append(
            NotificationOutbox.objects.create(
                event_type=event_type,
                destination=destination,
                payload=payload,
                status=OutboxStatus.PENDING,
                dedup_key=dedup_key,
                scheduled_for=timezone.now(),
            )
        )

    return created


NO_DATA_VI = "— (không có dữ liệu)"
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")

# Emoji by verdict/severity for the message title. Kept here (not in the
# template) because it varies per verdict inside one template.
HIGH_SEVERITIES = {"High", "Critical"}


def _public_base_url():
    """Externally reachable base URL, or '' when only localhost is configured.

    A localhost link sent to Telegram is useless to the reader and leaks the
    internal deployment layout, so it is treated as not configured.
    """
    config = _config()
    base = (config.get("asp_base_url") or "").strip().rstrip("/")
    if not base:
        return ""
    lowered = base.lower()
    if "127.0.0.1" in lowered or "localhost" in lowered:
        return ""
    return base


def case_link(case):
    base = _public_base_url()
    if not base:
        return ""
    return f"{base}/cases/{case.pk}"


def _verdict_emoji(verdict, severity):
    if verdict == "true_positive":
        return "🔴" if str(severity) in HIGH_SEVERITIES else "🟠"
    if verdict in ("false_positive", "benign_true_positive"):
        return "🟢"
    return "🟡"


def _limit_sentences(text, limit):
    text = str(text or "").strip()
    if not text:
        return ""
    return " ".join(SENTENCE_SPLIT_RE.split(text)[:limit]).strip()


def _artifact_values(case):
    """Deterministic field block from the case's artifacts — never the LLM."""
    from apps.artifacts.models import ArtifactName, ArtifactType

    values = {"hostname": "", "username": "", "process_path": "", "parent_process": "", "cmdline": "", "sha256": ""}
    for alert in case.alerts.prefetch_related("artifacts"):
        for artifact in alert.artifacts.all():
            value = str(artifact.value or "").strip()
            if not value:
                continue
            artifact_type = str(artifact.type)
            if artifact_type == ArtifactType.HOSTNAME and not values["hostname"]:
                values["hostname"] = value
            elif artifact_type == ArtifactType.USER_NAME and not values["username"]:
                values["username"] = value
            elif artifact_type == ArtifactType.PROCESS_NAME:
                if str(artifact.name) == ArtifactName.PARENT_PROCESS_NAME and not values["parent_process"]:
                    values["parent_process"] = value
                elif not values["process_path"]:
                    values["process_path"] = value
            elif artifact_type == ArtifactType.COMMAND_LINE and not values["cmdline"]:
                values["cmdline"] = value
            elif artifact_type == ArtifactType.HASH and len(value) == 64 and not values["sha256"]:
                values["sha256"] = value
    return values


def _threat_intel_summary(case, sha256):
    """One short parenthetical from stored TI enrichment, e.g. VT ratio."""
    from apps.enrichments.models import Enrichment, EnrichmentType

    rows = Enrichment.objects.filter(
        artifact__alerts__case=case, type=EnrichmentType.THREAT_INTELLIGENCE
    ).order_by("-created_at")[:20]
    for row in rows:
        data = row.data if isinstance(row.data, dict) else {}
        raw = data.get("raw") or {}
        ratio = raw.get("vt_detection_ratio")
        if ratio and (not sha256 or row.value == sha256):
            return f"(VirusTotal {ratio})"
        if data.get("risk_level") in ("high", "medium"):
            return f"({row.provider}: {data.get('risk_level')})"
    return ""


def _missing_fields_summary(fields):
    labels = {
        "cmdline": "command line",
        "parent_process": "parent process",
        "username": "username",
        "process_path": "process",
        "sha256": "SHA256",
    }
    missing = [labels[key] for key in ("cmdline", "parent_process", "username", "process_path", "sha256") if not fields.get(key)]
    return ", ".join(missing)


def _title_line(*, emoji, case_id, rule_name, hostname, case_url):
    """Pre-escaped HTML title: [case_id as link] — rule_name on hostname."""
    safe_id = html.escape(case_id, quote=False)
    if case_url:
        head = f'<a href="{case_url}">{safe_id}</a>'
    else:
        head = f"{safe_id} [link chưa cấu hình]"
    detail = html.escape(rule_name or "", quote=False)
    if hostname:
        detail = f"{detail} on {html.escape(hostname, quote=False)}"
    return f"{emoji} {head} — {detail}".strip()


def _missing_block(summary):
    if not summary:
        return ""
    return f"\n<b>Còn thiếu:</b> {html.escape(summary, quote=False)}"


def emit_triage_result(result):
    """Emit for a stored TriageResult, respecting the no-spam rule.

    Only true positives and results that need a human are notified; a channel
    that receives every false positive stops being read. The field block is
    deterministic (DB values); the LLM only contributes reasoning_vi.
    """
    from apps.agentic.models import TriageVerdict

    case = result.case
    config = _config()
    first_alert = case.alerts.order_by("created_at").first()
    rule_name = getattr(first_alert, "rule_name", "") or getattr(first_alert, "analytic_name", "") or case.title
    fields = _artifact_values(case)
    asset = result.asset_context or {}
    case_url = case_link(case)
    base = _public_base_url()

    is_fp = result.verdict in (TriageVerdict.FALSE_POSITIVE, TriageVerdict.BENIGN_TRUE_POSITIVE)
    reasoning = _limit_sentences(result.reasoning_vi or result.reasoning_en, 2 if is_fp else 5)

    payload = {
        # Pre-escaped HTML blocks, substituted raw via {{{...}}}.
        "title_line": _title_line(
            emoji=_verdict_emoji(result.verdict, result.severity_ai or case.severity),
            case_id=case.case_id,
            rule_name=rule_name,
            hostname=fields["hostname"],
            case_url=case_url,
        ),
        "missing_block": _missing_block(_missing_fields_summary(fields)),
        # Plain values, escaped by the renderer.
        "case_id": case.case_id,
        "title": case.title,
        "rule_name": rule_name,
        "verdict": result.verdict,
        "confidence": round(result.confidence, 2),
        "severity_source": str(case.severity) or "—",
        "severity_ai": result.severity_ai or "—",
        "severity": result.severity_ai or case.severity,
        "priority": result.priority_ai or case.priority,
        "source": _source_of(case),
        "hostname": fields["hostname"] or NO_DATA_VI,
        "device_type": asset.get("device_type") or "unknown",
        "asset_owner": asset.get("owner") or "unknown owner",
        "asset_context_source": asset.get("asset_context_source_label") or "không khớp CMDB",
        "username": fields["username"] or NO_DATA_VI,
        "process_path": fields["process_path"] or NO_DATA_VI,
        "parent_process": fields["parent_process"] or NO_DATA_VI,
        "cmdline": fields["cmdline"] or NO_DATA_VI,
        "sha256": fields["sha256"] or "—",
        "threat_intel_summary": _threat_intel_summary(case, fields["sha256"]),
        "mitre": ", ".join(result.mitre_techniques or []) or NO_DATA_VI,
        "reasoning_vi": reasoning,
        "reasoning": reasoning,
        "product_name": _product_name(),
        "entity": _primary_entity(case),
        "link": case_url,
        "case_url": case_url,
        "dashboard_url": f"{base}/cases" if base else "",
        "aggregation_window_seconds": config.get("aggregation_window_seconds") or 300,
        "needs_human": result.needs_human,
    }

    events = []
    if result.verdict == TriageVerdict.TRUE_POSITIVE:
        events.append(NotificationEvent.TRIAGE_COMPLETED.value)
    if result.needs_human:
        events.append(NotificationEvent.TRIAGE_NEEDS_HUMAN.value)

    queued = []
    for event_type in events:
        queued.extend(emit(event_type, payload))
    return queued


def _primary_entity(case):
    """Typed entity, never an agent GUID or detection id."""
    from apps.agentic.triage.entities import entity_display, extract_entities

    try:
        return entity_display(extract_entities(case))
    except Exception:
        logger.exception("Failed to extract entities for case %s", case.pk)
        return ""


def _product_name():
    """Deployment product name, so notifications carry the local identity."""
    from apps.settings.runtime_config import get_branding_config

    try:
        return get_branding_config()["product_name"]
    except Exception:
        return "SOC Platform"


def _source_of(case):
    alert = case.alerts.first()
    return getattr(alert, "product_name", "") or ""
