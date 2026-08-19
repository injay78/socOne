"""Deterministic suppression checked before any LLM call.

A suppressed Case is recorded as suppressed with the rule that matched — never
silently dropped — so the suppression list itself stays auditable.
"""

import ipaddress
import logging

from django.utils import timezone

from apps.agentic.models import SuppressionMatchType, TriageSuppression

logger = logging.getLogger(__name__)


def active_suppressions():
    return list(
        TriageSuppression.objects.filter(enabled=True, expires_at__gt=timezone.now())
    )


def _matches_rule(pattern, case_payload):
    pattern = pattern.strip().lower()
    for alert in case_payload.get("alerts") or []:
        for key in ("rule_name", "analytic_name"):
            value = str((alert or {}).get(key) or "").strip().lower()
            if value and (value == pattern or pattern in value):
                return True
    return False


def _entity_values(case_payload):
    values = []
    for alert in case_payload.get("alerts") or []:
        for artifact in (alert or {}).get("artifacts") or []:
            value = str((artifact or {}).get("value") or "").strip()
            if value:
                values.append(value)
    for artifact in case_payload.get("artifacts") or []:
        value = str((artifact or {}).get("value") or "").strip()
        if value:
            values.append(value)
    return values


def _matches_entity(pattern, case_payload):
    pattern = pattern.strip().lower()
    return any(pattern == value.lower() for value in _entity_values(case_payload))


def _matches_subnet(pattern, case_payload):
    try:
        network = ipaddress.ip_network(pattern.strip(), strict=False)
    except ValueError:
        logger.warning("Invalid suppression subnet pattern: %s", pattern)
        return False

    for value in _entity_values(case_payload):
        try:
            if ipaddress.ip_address(value.strip()) in network:
                return True
        except ValueError:
            continue
    return False


def _matches_user(pattern, case_payload):
    pattern = pattern.strip().lower()
    for alert in case_payload.get("alerts") or []:
        for artifact in (alert or {}).get("artifacts") or []:
            artifact_type = str((artifact or {}).get("type") or "").lower()
            if "user" not in artifact_type:
                continue
            if str((artifact or {}).get("value") or "").strip().lower() == pattern:
                return True
    return False


MATCHERS = {
    SuppressionMatchType.RULE: _matches_rule,
    SuppressionMatchType.ENTITY: _matches_entity,
    SuppressionMatchType.SUBNET: _matches_subnet,
    SuppressionMatchType.USER: _matches_user,
}


def find_matching_suppression(case_payload):
    """Return the first active suppression matching this Case, or None."""
    for suppression in active_suppressions():
        matcher = MATCHERS.get(suppression.match_type)
        if matcher is None:
            continue
        try:
            if matcher(suppression.pattern, case_payload):
                return suppression
        except Exception:
            logger.exception("Suppression matcher failed for %s", suppression)
    return None
