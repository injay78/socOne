"""Context completeness: try to fill the gaps before declaring them.

`needs_more_info` is only honest after enrichment has been attempted. Each
attempt records what was tried and why it failed, so the verdict names the exact
missing field and the exact reason rather than asking someone to "verify with
the IAM team".
"""

import logging

logger = logging.getLogger(__name__)

# Required fields per detection source. Anything absent triggers an enrichment
# attempt before the LLM is called.
REQUIRED_FIELDS = {
    "edr": ("hostname", "file_hash", "process"),
    "siem": ("hostname_or_ip",),
    "default": ("hostname_or_ip",),
}

FIELD_LABELS = {
    "hostname": "Hostname",
    "file_hash": "File hash",
    "process": "Process",
    "command_line": "Command line",
    "parent_process": "Parent process",
    "username": "User account",
    "hostname_or_ip": "Hostname or IP",
    "asset_context": "Asset context",
}


def _artifacts_by_type(case):
    grouped = {}
    for alert in case.alerts.all():
        for artifact in alert.artifacts.all():
            key = str(getattr(artifact, "type", "") or "").strip().lower()
            value = str(getattr(artifact, "value", "") or "").strip()
            if key and value:
                grouped.setdefault(key, []).append(value)
    return grouped


def _source_family(case):
    alert = case.alerts.first()
    category = str(getattr(alert, "product_category", "") or "").lower()
    if "edr" in category:
        return "edr"
    if "siem" in category:
        return "siem"
    return "default"


def _present(field, artifacts):
    checks = {
        "hostname": ("hostname",),
        "file_hash": ("hash",),
        "process": ("process name",),
        "command_line": ("command line",),
        "parent_process": ("parent process name",),
        "username": ("user name", "username"),
        "hostname_or_ip": ("hostname", "ip address"),
    }
    for key in checks.get(field, ()):
        if artifacts.get(key):
            return True
    return False


def _attempt_hash_verification(case, artifacts):
    """Verify file hashes through S6 so threat intel is present at triage time."""
    from apps.agentic.ioc.normalize import classify
    from apps.agentic.ioc.service import get_cached, verify_indicator

    attempted = []
    for value in (artifacts.get("hash") or [])[:3]:
        indicator_type, normalised = classify(value)
        if get_cached(indicator_type, normalised) is not None:
            continue
        try:
            record = verify_indicator(normalised)
            attempted.append({
                "field": "threat_intel",
                "source": "ioc_verification",
                "outcome": record.verdict,
            })
        except Exception as exc:
            logger.warning("IOC verification failed during triage enrichment", exc_info=True)
            attempted.append({
                "field": "threat_intel",
                "source": "ioc_verification",
                "outcome": f"failed: {type(exc).__name__}",
            })
    return attempted


def _attempt_asset_context(case, artifacts):
    from apps.agentic.triage.asset import resolve_asset_context

    hostname = (artifacts.get("hostname") or [""])[0]
    if not hostname:
        return {}, [{
            "field": "asset_context",
            "source": "cmdb/directory/naming_rule",
            "outcome": "skipped: no hostname on the case",
        }]

    context = resolve_asset_context(hostname)
    outcome = context.get("asset_context_source", "none")
    return context, [{
        "field": "asset_context",
        "source": "cmdb/directory/naming_rule",
        "outcome": f"resolved via {outcome}" if outcome != "none" else "no system of record matched",
    }]


def ensure_context(case):
    """Attempt enrichment, then report what is still missing.

    Returns (asset_context, missing, attempts). `missing` lists fields that are
    still absent after enrichment, each with the reason.
    """
    artifacts = _artifacts_by_type(case)
    family = _source_family(case)
    attempts = []

    asset_context, asset_attempts = _attempt_asset_context(case, artifacts)
    attempts.extend(asset_attempts)
    attempts.extend(_attempt_hash_verification(case, artifacts))

    # Re-read after enrichment; hash verification can add Enrichment records.
    artifacts = _artifacts_by_type(case)

    missing = []
    for field in REQUIRED_FIELDS.get(family, REQUIRED_FIELDS["default"]):
        if _present(field, artifacts):
            continue
        missing.append({
            "field": field,
            "label": FIELD_LABELS.get(field, field),
            "tried": _tried_for(field, family),
            "reason": _reason_for(field, family),
            "question": _question_for(field),
        })

    if not asset_context.get("cmdb_matched"):
        missing.append({
            "field": "asset_context",
            "label": FIELD_LABELS["asset_context"],
            "tried": "CMDB, directory, naming rules",
            "reason": (
                "No authoritative CMDB record matched this host. "
                f"Context source: {asset_context.get('asset_context_source', 'none')}."
            ),
            "question": "Máy này thuộc nhóm tài sản nào trong CMDB, và ai là chủ sở hữu?",
        })

    return asset_context, missing, attempts


def _tried_for(field, family):
    if family == "edr":
        return "Trellix threat detail, Trellix detection detail"
    if family == "siem":
        return "QRadar offence detail, AQL event lookup"
    return "source record"


def _reason_for(field, family):
    if family == "edr" and field in {"command_line", "parent_process", "username"}:
        return (
            "The Trellix ft/api/v2 detection payload does not carry this field, and extended "
            "trace visibility is disabled on this tenant (traceExtendedVisibility=0)."
        )
    return "The field is absent from the source record and no enrichment source provided it."


def _question_for(field):
    questions = {
        "command_line": "Command line đầy đủ của process này là gì? Lấy từ Trellix console hoặc EDR search.",
        "parent_process": "Parent process của process này là gì?",
        "username": "Tài khoản nào đã chạy process này?",
        "hostname": "Alert này xảy ra trên host nào?",
        "file_hash": "SHA256 của file liên quan là gì?",
        "process": "Process nào đã kích hoạt detection này?",
        "hostname_or_ip": "Host hoặc IP nào liên quan tới alert này?",
    }
    return questions.get(field, "Cần bổ sung field này từ hệ thống nguồn.")
