"""Context assembly for AI triage.

Tiers are fetched cheapest-and-most-important first and handed to the shared
token budget layer, so an oversized Case degrades by dropping the least
important context rather than by failing.
"""

import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

HISTORY_DAYS = 30
HISTORY_LIMIT = 20
MAX_ENRICHED_ARTIFACTS = 10


def _artifact_values(case_payload):
    seen = []
    for alert in case_payload.get("alerts") or []:
        for artifact in (alert or {}).get("artifacts") or []:
            value = str((artifact or {}).get("value") or "").strip()
            artifact_type = str((artifact or {}).get("type") or "").strip()
            if value and (artifact_type, value) not in seen:
                seen.append((artifact_type, value))
    return seen[:MAX_ENRICHED_ARTIFACTS]


def build_cmdb_context(case_payload):
    from integrations.cmdb.service import lookup_artifact_context

    results = []
    for artifact_type, value in _artifact_values(case_payload):
        try:
            output = lookup_artifact_context(artifact_type, value)
        except Exception:
            logger.warning("CMDB lookup failed for %s=%s", artifact_type, value, exc_info=True)
            continue
        payload = output.model_dump() if hasattr(output, "model_dump") else output
        if payload and payload.get("results"):
            results.append({"artifact": value, "type": artifact_type, "context": payload["results"]})
    return results


def build_identity_context(case_payload):
    """Directory attributes for the users named in the Case."""
    from apps.accounts.models import User

    usernames = [
        value
        for artifact_type, value in _artifact_values(case_payload)
        if "user" in artifact_type.lower()
    ]
    if not usernames:
        return []

    records = []
    for user in User.objects.filter(username__in=usernames):
        records.append({
            "username": user.username,
            "auth_type": user.auth_type,
            "role": user.role,
            "is_active": user.is_active,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        })
    return records


def build_threat_intel_context(case_payload):
    from integrations.threat_intel.service import query_indicator

    results = []
    for artifact_type, value in _artifact_values(case_payload):
        try:
            output = query_indicator(value, artifact_type=artifact_type)
        except Exception:
            logger.warning("Threat intel lookup failed for %s", value, exc_info=True)
            continue
        payload = output.model_dump() if hasattr(output, "model_dump") else output
        if payload and payload.get("results"):
            results.append({"indicator": value, "type": artifact_type, "intel": payload["results"]})
    return results


def build_ioc_verification_context(case):
    """Cached IOC verdicts for this Case's indicators.

    Triage reads whatever verification already exists rather than triggering
    external lookups on every analysis: verification is rate-limited and leaves
    the network, so it stays an explicit action (playbook, API) or a cache hit.
    """
    from apps.agentic.ioc.normalize import IOC_UNKNOWN, classify
    from apps.agentic.ioc.service import get_cached

    records = []
    seen = set()
    for artifact_type, value in _artifact_values(_case_payload_of(case)):
        indicator_type, normalised = classify(value)
        if indicator_type == IOC_UNKNOWN or normalised in seen:
            continue
        seen.add(normalised)
        cached = get_cached(indicator_type, normalised)
        if cached is None:
            continue
        records.append({
            "indicator": normalised,
            "type": indicator_type,
            "verdict": cached.verdict,
            "confidence": cached.confidence,
            "categories": cached.categories,
            "reference_count": len(cached.references or []),
            "notes": cached.notes_vi or cached.notes_en,
        })
        del artifact_type
    return records


def _case_payload_of(case):
    from apps.agentic.analysis.profiles import serialize_case_for_investigation

    return serialize_case_for_investigation(case)


def build_history_context(case):
    """Recent Cases touching the same entities, to spot repeat offenders."""
    from apps.cases.models import Case

    since = timezone.now() - timedelta(days=HISTORY_DAYS)
    queryset = (
        Case.objects.filter(created_at__gte=since)
        .exclude(pk=case.pk)
        .order_by("-created_at")
    )
    if case.correlation_uid:
        queryset = queryset.filter(correlation_uid=case.correlation_uid)

    return [
        {
            "case_id": item.case_id,
            "title": item.title,
            "severity": item.severity,
            "status": item.status,
            "verdict": item.verdict or item.verdict_ai,
            "created_at": item.created_at.isoformat(),
        }
        for item in queryset[:HISTORY_LIMIT]
    ]


def has_minimum_context(case_payload):
    """Refuse to spend an LLM call on a Case with nothing to reason about."""
    if not case_payload:
        return False
    if not str(case_payload.get("title") or "").strip():
        return False
    alerts = case_payload.get("alerts") or []
    artifacts = _artifact_values(case_payload)
    return bool(alerts or artifacts)
