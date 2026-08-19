from apps.agentic.runtime.base import BaseModule, correlation_identity, parse_event_time
from apps.agentic.services.alerts import create_alert_with_context
from apps.alerts.models import (
    AlertAction,
    AlertAnalyticType,
    AlertPolicyType,
    AlertRiskLevel,
    AlertStatus,
    Confidence,
    Disposition,
    Impact,
    ProductCategory,
    Severity,
)
from apps.artifacts.models import ArtifactName, ArtifactRole, ArtifactType
from apps.cases.models import CaseConfidence, CaseImpact, CasePriority, CaseSeverity


class Module(BaseModule):
    NAME = "QRadar Offense (Generic)"
    DESC = "Fallback mapper turning a normalised QRadar offence into a Case, Alert and Artifacts."
    STREAM_NAME = "QRadar-Offense"

    def run(self, message):
        if not isinstance(message, dict):
            raise ValueError("QRadar module expects a dict message.")
        if message.get("source") != "qradar":
            raise ValueError("QRadar module received a payload from another source.")

        offense_id = message.get("offense_id")
        if offense_id is None:
            raise ValueError("QRadar offence payload has no offense_id.")

        event_time, time_unmapped = parse_event_time(_millis_to_iso(message.get("start_time")))
        magnitude = _as_int(message.get("magnitude"), 0)
        severity_value = _as_int(message.get("severity"), 0)
        rule_name = (message.get("rule_names") or [""])[0] or message.get("offense_type") or "QRadar Offense"
        description = (message.get("description") or rule_name).strip()

        risk_level, severity, case_severity = _severity_for(magnitude, severity_value)

        # One Case per offence: repeated events of the same offence collapse together.
        correlation_uid = correlation_identity(
            rule_id=f"qradar-offense:{offense_id}",
            keys=[str(offense_id)],
        )

        artifacts = _artifacts(message)
        unmapped = {
            **time_unmapped,
            "qradar_offense_id": offense_id,
            "qradar_status": message.get("status"),
            "qradar_magnitude": magnitude,
            "qradar_credibility": message.get("credibility"),
            "qradar_relevance": message.get("relevance"),
            "qradar_event_count": message.get("event_count"),
            "qradar_flow_count": message.get("flow_count"),
            "qradar_categories": message.get("categories"),
            "qradar_top_events": message.get("top_events"),
        }

        return create_alert_with_context(
            case_defaults={
                "title": f"QRadar #{offense_id}: {description[:200]}",
                "description": description,
                "severity": case_severity,
                "impact": CaseImpact.MEDIUM,
                "priority": _priority_for(magnitude),
                "confidence": CaseConfidence.MEDIUM,
                "category": ProductCategory.SIEM,
                "correlation_uid": correlation_uid,
            },
            alert_fields={
                "title": description[:200] or rule_name,
                "desc": description,
                "rule_id": str(offense_id),
                "rule_name": rule_name,
                "source_uid": str(offense_id),
                "product_category": ProductCategory.SIEM,
                "product_vendor": "IBM",
                "product_name": "IBM QRadar",
                "product_feature": "Offense",
                "analytic_type": AlertAnalyticType.RULE,
                "analytic_name": rule_name,
                "analytic_desc": description,
                "policy_type": AlertPolicyType.OTHER,
                "risk_level": risk_level,
                "severity": severity,
                "confidence": Confidence.MEDIUM,
                "impact": Impact.MEDIUM,
                "disposition": Disposition.DETECTED,
                "action": AlertAction.OBSERVED,
                "status": AlertStatus.NEW,
                "status_detail": f"QRadar status: {message.get('status') or 'unknown'}",
                "first_seen_time": event_time,
                "last_seen_time": event_time,
                "data_sources": ["qradar.offense"],
                "correlation_uid": correlation_uid,
                "raw_data": message.get("raw_offense") or {},
                "unmapped": unmapped,
            },
            artifacts=artifacts,
            enrichments=[],
        )


def _severity_for(magnitude, severity_value):
    score = max(magnitude, severity_value)
    if score >= 8:
        return AlertRiskLevel.CRITICAL, Severity.CRITICAL, CaseSeverity.CRITICAL
    if score >= 6:
        return AlertRiskLevel.HIGH, Severity.HIGH, CaseSeverity.HIGH
    if score >= 4:
        return AlertRiskLevel.MEDIUM, Severity.MEDIUM, CaseSeverity.MEDIUM
    return AlertRiskLevel.LOW, Severity.LOW, CaseSeverity.LOW


def _priority_for(magnitude):
    if magnitude >= 8:
        return CasePriority.CRITICAL
    if magnitude >= 6:
        return CasePriority.HIGH
    if magnitude >= 4:
        return CasePriority.MEDIUM
    return CasePriority.LOW


def _artifacts(message):
    artifacts = []
    seen = set()

    def add(value, artifact_type, role, name):
        text = str(value or "").strip()
        if not text or (artifact_type, text) in seen:
            return
        seen.add((artifact_type, text))
        artifacts.append({"value": text, "type": artifact_type, "role": role, "name": name})

    for address in message.get("source_addresses") or []:
        add(address, ArtifactType.IP_ADDRESS, ArtifactRole.ACTOR, ArtifactName.SOURCE_IP)
    for address in message.get("destination_addresses") or []:
        add(address, ArtifactType.IP_ADDRESS, ArtifactRole.AFFECTED, ArtifactName.DESTINATION_IP)

    add(message.get("offense_source"), ArtifactType.OTHER, ArtifactRole.RELATED, ArtifactName.OTHER)

    for event in message.get("top_events") or []:
        if not isinstance(event, dict):
            continue
        add(event.get("sourceip"), ArtifactType.IP_ADDRESS, ArtifactRole.ACTOR, ArtifactName.SOURCE_IP)
        add(event.get("destinationip"), ArtifactType.IP_ADDRESS, ArtifactRole.AFFECTED, ArtifactName.DESTINATION_IP)
        add(event.get("username"), ArtifactType.USER_NAME, ArtifactRole.ACTOR, ArtifactName.SOURCE_USER)

    return artifacts


def _millis_to_iso(value):
    try:
        millis = int(value)
    except (TypeError, ValueError):
        return None
    if millis <= 0:
        return None
    from datetime import datetime, timezone

    return datetime.fromtimestamp(millis / 1000, tz=timezone.utc).isoformat()


def _as_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
