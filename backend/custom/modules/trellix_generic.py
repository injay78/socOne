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
from apps.alerts.models import AlertTactic
from apps.artifacts.models import ArtifactName, ArtifactRole, ArtifactType
from apps.cases.models import CaseConfidence, CaseImpact, CasePriority, CaseSeverity

# Trellix tags carry tactics in CamelCase ("DefenseEvasion"); the Alert field
# accepts exactly one of the spaced MITRE labels ("Defense Evasion").
TACTIC_BY_COMPACT = {choice.value.replace(" ", "").lower(): choice.value for choice in AlertTactic}

SEVERITY_MAP = {
    "critical": (AlertRiskLevel.CRITICAL, Severity.CRITICAL, CaseSeverity.CRITICAL, CasePriority.CRITICAL, CaseImpact.HIGH),
    "high": (AlertRiskLevel.HIGH, Severity.HIGH, CaseSeverity.HIGH, CasePriority.HIGH, CaseImpact.HIGH),
    "medium": (AlertRiskLevel.MEDIUM, Severity.MEDIUM, CaseSeverity.MEDIUM, CasePriority.MEDIUM, CaseImpact.MEDIUM),
    "low": (AlertRiskLevel.LOW, Severity.LOW, CaseSeverity.LOW, CasePriority.LOW, CaseImpact.LOW),
    "informational": (AlertRiskLevel.INFO, Severity.INFORMATIONAL, CaseSeverity.INFORMATIONAL, CasePriority.LOW, CaseImpact.LOW),
}
DEFAULT_SEVERITY = SEVERITY_MAP["medium"]


class Module(BaseModule):
    NAME = "Trellix Detection (Generic)"
    DESC = "Fallback mapper turning a normalised Trellix EDR detection into a Case, Alert and Artifacts."
    STREAM_NAME = "Trellix-Detection"

    def run(self, message):
        if not isinstance(message, dict):
            raise ValueError("Trellix module expects a dict message.")
        if message.get("source") != "trellix":
            raise ValueError("Trellix module received a payload from another source.")

        detection_id = message.get("detection_id")
        if detection_id is None:
            raise ValueError("Trellix detection payload has no detection_id.")

        event_time, time_unmapped = parse_event_time(message.get("detected_at"))
        risk_level, severity, case_severity, priority, impact = _severity_for(message)
        tactic = _primary_tactic(message.get("mitre_tactics"))
        technique = ", ".join(message.get("mitre_techniques") or [])[:100]

        hostname = message.get("hostname") or "unknown host"
        threat_name = message.get("threat_name") or message.get("rule_name") or "Trellix detection"

        # Same threat + same host collapse into one Case. Keyed by threat (not
        # the per-detection MSI rule tag — detections of one threat carry
        # different rule tags and would fragment into one case per tag).
        # Keys hold only the hostname: threat_id already identifies the threat,
        # and merge_duplicate_cases must be able to recompute this uid from
        # stored alerts (threat_type is not persisted).
        threat_key = message.get("threat_id") or message.get("threat_name") or message.get("rule_name") or "trellix"
        correlation_uid = correlation_identity(
            rule_id=f"trellix:{threat_key}",
            keys=[hostname],
        )

        unmapped = {
            **time_unmapped,
            "trellix_detection_id": detection_id,
            "trellix_threat_id": message.get("threat_id"),
            "trellix_affected_host_id": message.get("affected_host_id"),
            "trellix_trace_id": message.get("trace_id"),
            "trellix_severity_code": message.get("severity_code"),
            "trellix_rank": message.get("rank"),
            "trellix_agent_id": message.get("agent_id"),
            "trellix_os": message.get("os"),
            "trellix_detections_on_host": message.get("detections_on_host"),
            "trellix_tags": message.get("tags"),
            "trellix_console_url": message.get("console_url"),
            "trellix_mitre_tactics": message.get("mitre_tactics") or [],
            "trellix_mitre_techniques": message.get("mitre_techniques") or [],
        }

        return create_alert_with_context(
            case_defaults={
                "title": f"{threat_name} on {hostname}",
                "description": f"Trellix EDR detected {threat_name} on {hostname}.",
                "severity": case_severity,
                "impact": impact,
                "priority": priority,
                "confidence": CaseConfidence.MEDIUM,
                "category": ProductCategory.EDR,
                "tags": ["trellix", "edr"],
                "correlation_uid": correlation_uid,
            },
            alert_fields={
                "title": f"{threat_name} on {hostname}",
                "desc": f"Trellix EDR detected {threat_name} on {hostname}.",
                "rule_id": str(message.get("threat_id") or detection_id),
                "rule_name": message.get("rule_name") or threat_name,
                "source_uid": str(detection_id),
                "product_category": ProductCategory.EDR,
                "product_vendor": "Trellix",
                "product_name": "Trellix EDR",
                "product_feature": "Detection",
                "analytic_type": AlertAnalyticType.RULE,
                "analytic_name": message.get("rule_name") or threat_name,
                "analytic_desc": threat_name,
                "policy_type": AlertPolicyType.OTHER,
                "risk_level": risk_level,
                "severity": severity,
                "confidence": Confidence.MEDIUM,
                "impact": Impact.MEDIUM,
                "disposition": Disposition.DETECTED,
                "action": AlertAction.OBSERVED,
                "status": AlertStatus.NEW,
                "status_detail": f"Trellix rank {message.get('rank')} on {message.get('hostname') or 'unknown host'}",
                "src_url": message.get("console_url") or "",
                "tactic": tactic,
                "technique": technique,
                "first_seen_time": event_time,
                "last_seen_time": event_time,
                "data_sources": ["trellix.detection"],
                "labels": ["trellix", "edr"],
                "correlation_uid": correlation_uid,
                "raw_data": message.get("raw_detection") or {},
                "unmapped": unmapped,
            },
            artifacts=_artifacts(message),
            enrichments=[],
        )


def _primary_tactic(tactics):
    """First Trellix tactic that maps onto a valid AlertTactic choice."""
    for raw in tactics or []:
        mapped = TACTIC_BY_COMPACT.get(str(raw).replace(" ", "").lower())
        if mapped:
            return mapped
    return ""


def _severity_for(message):
    key = str(message.get("severity") or "").strip().lower()
    if key in SEVERITY_MAP:
        return SEVERITY_MAP[key]

    try:
        score = float(message.get("score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    if score >= 90:
        return SEVERITY_MAP["critical"]
    if score >= 70:
        return SEVERITY_MAP["high"]
    if score >= 40:
        return SEVERITY_MAP["medium"]
    if score > 0:
        return SEVERITY_MAP["low"]
    return DEFAULT_SEVERITY


def _artifacts(message):
    specs = [
        (message.get("hostname"), ArtifactType.HOSTNAME, ArtifactRole.AFFECTED, ArtifactName.AFFECTED_HOST),
        (message.get("username"), ArtifactType.USER_NAME, ArtifactRole.ACTOR, ArtifactName.SOURCE_USER),
        (message.get("threat_name"), ArtifactType.PROCESS_NAME, ArtifactRole.RELATED, ArtifactName.PROCESS_NAME),
        (message.get("interpreter_name"), ArtifactType.PROCESS_NAME, ArtifactRole.RELATED, ArtifactName.PARENT_PROCESS_NAME),
        (message.get("file_sha256"), ArtifactType.HASH, ArtifactRole.RELATED, ArtifactName.FILE_HASH),
        (message.get("file_sha1"), ArtifactType.HASH, ArtifactRole.RELATED, ArtifactName.FILE_HASH),
        (message.get("file_md5"), ArtifactType.HASH, ArtifactRole.RELATED, ArtifactName.FILE_HASH),
        (message.get("interpreter_sha256"), ArtifactType.HASH, ArtifactRole.RELATED, ArtifactName.FILE_HASH),
        (message.get("agent_id"), ArtifactType.OTHER, ArtifactRole.AFFECTED, ArtifactName.OTHER),
    ]
    artifacts = [
        {"value": value, "type": type_, "role": role, "name": name}
        for value, type_, role, name in specs
        if value
    ]

    # Every routable interface on the affected host, not just one address.
    for ip in message.get("host_ips") or []:
        artifacts.append({
            "value": ip,
            "type": ArtifactType.IP_ADDRESS,
            "role": ArtifactRole.AFFECTED,
            "name": ArtifactName.HOST_IP,
        })
    for mac in message.get("host_macs") or []:
        artifacts.append({
            "value": mac,
            "type": ArtifactType.MAC_ADDRESS,
            "role": ArtifactRole.AFFECTED,
            "name": ArtifactName.OTHER,
        })

    seen = set()
    unique = []
    for item in artifacts:
        key = (item["type"], item["value"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
