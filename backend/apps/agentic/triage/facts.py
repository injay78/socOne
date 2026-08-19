"""Deterministic fact block for a Case.

Every value here is read from a database record. The model never writes this
section — it only writes the assessment. A field with no data renders as
`— (không có dữ liệu)` rather than disappearing, because a visible gap tells the
analyst what to collect and tells us which Module is mapping too little.

Field labels stay in English (Hostname, Command line, Parent process); only the
prose around them is Vietnamese.
"""

from zoneinfo import ZoneInfo

NO_DATA = "— (không có dữ liệu)"
NOT_CHECKED = "— (chưa tra)"
DISPLAY_TIMEZONE = ZoneInfo("Asia/Ho_Chi_Minh")


def _value(raw, *, fallback=NO_DATA):
    if raw in (None, "", [], {}):
        return fallback
    if isinstance(raw, (list, tuple)):
        cleaned = [str(item).strip() for item in raw if str(item).strip()]
        return ", ".join(cleaned) if cleaned else fallback
    return str(raw).strip()


def _local_time(moment):
    if not moment:
        return NO_DATA
    try:
        return moment.astimezone(DISPLAY_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S %z")
    except (AttributeError, ValueError):
        return _value(moment)


def _section(key, title, rows):
    return {"key": key, "title": title, "rows": [{"label": label, "value": value} for label, value in rows]}


def _first_alert(case):
    return case.alerts.order_by("created_at").first()


def _artifact_map(alert):
    """Artifact values grouped by type, lowercased keys."""
    grouped = {}
    if alert is None:
        return grouped
    for artifact in alert.artifacts.all():
        key = str(getattr(artifact, "type", "") or "").strip().lower()
        value = str(getattr(artifact, "value", "") or "").strip()
        if key and value:
            grouped.setdefault(key, []).append(value)
    return grouped


def _ioc_summary(hashes):
    """Cached IOC verdicts for the file hashes on this alert."""
    from apps.agentic.ioc.normalize import classify
    from apps.agentic.ioc.service import get_cached

    for raw in hashes:
        indicator_type, value = classify(raw)
        record = get_cached(indicator_type, value)
        if record is None:
            continue
        references = len(record.references or [])
        return f"{record.verdict} ({record.confidence:.2f}, {references} reference)"
    return NOT_CHECKED


def build_facts(case, *, asset_context=None, extracted_entities=None):
    """Render the mandatory fact block. Always returns every section."""
    alert = _first_alert(case)
    artifacts = _artifact_map(alert)
    unmapped = (getattr(alert, "unmapped", None) or {}) if alert else {}
    asset_context = asset_context or {}
    extracted = extracted_entities or {}
    source_identifiers = extracted.get("source_identifiers") or []

    hostname = (artifacts.get("hostname") or [""])[0]
    username = (artifacts.get("user name") or artifacts.get("username") or [""])[0]
    hashes = artifacts.get("hash") or []

    detection = _section("detection", "Detection", [
        ("Source", _value(getattr(alert, "product_name", ""))),
        ("Rule", _value(getattr(alert, "rule_name", ""))),
        ("Severity (source)", _value(getattr(alert, "severity", ""))),
        ("Detected at", _local_time(getattr(alert, "first_seen_time", None))),
        ("Case created", _local_time(case.created_at)),
    ])

    host = _section("host", "Host", [
        ("Hostname", _value(hostname)),
        ("OS", _value(asset_context.get("os") if asset_context.get("os") != "unknown" else unmapped.get("trellix_os"))),
        ("Device type", _value(_unknown_as_no_data(asset_context.get("device_type")))),
        ("Owner", _value(_unknown_as_no_data(asset_context.get("owner")))),
        ("Environment", _value(_unknown_as_no_data(asset_context.get("environment")))),
        ("Criticality", _value(_unknown_as_no_data(asset_context.get("criticality")))),
        ("Asset context source", _value(asset_context.get("asset_context_source_label"))),
    ])

    user = _section("user", "User", [
        ("Account", _value(username)),
        ("Department", _value(_unknown_as_no_data(asset_context.get("owner")))),
        ("Account status", _value(_unknown_as_no_data(asset_context.get("account_status")))),
    ])

    process = _section("process", "Process", [
        ("Process", _value(artifacts.get("process name"))),
        ("Full path", _value(artifacts.get("file path"))),
        ("Command line", _value(artifacts.get("command line"))),
        ("Parent process", _value(unmapped.get("trellix_interpreter") or _parent_process(artifacts))),
        ("Run as user", _value(username)),
    ])

    file_section = _section("file", "File", [
        ("File name", _value(getattr(alert, "analytic_name", "") if alert else "")),
        ("SHA256", _value([h for h in hashes if len(h) == 64])),
        ("MD5", _value([h for h in hashes if len(h) == 32])),
        ("Signature status", _value(unmapped.get("signature_status"))),
        ("Threat intel", _ioc_summary(hashes) if hashes else NOT_CHECKED),
    ])

    network = _section("network", "Network", [
        ("Source IP", _value(artifacts.get("ip address"))),
        ("Destination IP", _value(unmapped.get("destination_ip"))),
        ("Port", _value(unmapped.get("port"))),
        ("Domain", _value(artifacts.get("domain"))),
    ])

    mitre = _section("mitre", "MITRE", [
        ("Tactic", _value(getattr(alert, "tactic", ""))),
        ("Technique", _value(getattr(alert, "technique", ""))),
    ])

    identifiers = _section("identifiers", "Source identifiers", [
        (item.get("type", "identifier"), _value(item.get("value")))
        for item in source_identifiers
    ] or [("Identifier", NO_DATA)])

    sections = [detection, host, user, process, file_section, network, mitre, identifiers]
    return {
        "sections": sections,
        "missing_count": sum(
            1 for section in sections for row in section["rows"] if row["value"] in (NO_DATA, NOT_CHECKED)
        ),
    }


def _unknown_as_no_data(value):
    return "" if str(value or "").strip().lower() in {"", "unknown"} else value


def _parent_process(artifacts):
    for key in ("parent process name", "process name"):
        values = artifacts.get(key) or []
        if len(values) > 1:
            return values[1]
    return ""
