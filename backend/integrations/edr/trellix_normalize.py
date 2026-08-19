"""Normalise Trellix threats and detections into the shape Modules consume.

One Trellix detection is one ASP alert. The threat and the affected host that
own it are folded into the same payload so a Module has the full context
without walking the API again.
"""

import hashlib
import logging
import re

logger = logging.getLogger(__name__)

DEFAULT_STREAM_NAME = "Trellix-Detection"

SEVERITY_LABELS = {
    "s0": "Informational",
    "s1": "Low",
    "s2": "Low",
    "s3": "Medium",
    "s4": "High",
    "s5": "Critical",
}

SEVERITY_ORDER = {"s0": 0, "s1": 1, "s2": 2, "s3": 3, "s4": 4, "s5": 5}

TECHNIQUE_TAG_RE = re.compile(r"^@ATE\.(T\d{4}(?:\.\d{3})?)$")
TACTIC_TAG_RE = re.compile(r"^@ATA\.(\w+)$")
RULE_TAG_RE = re.compile(r"^@MSI(?:_TOPRULE)?\.(.+)$")


def _first(source, *keys, default=None):
    for key in keys:
        value = (source or {}).get(key)
        if value not in (None, "", [], {}):
            return value
    return default


def parse_tags(tags):
    """Split Trellix detection tags into MITRE techniques, tactics and rules."""
    techniques, tactics, rules = [], [], []
    for tag in tags or []:
        text = str(tag).strip()
        technique = TECHNIQUE_TAG_RE.match(text)
        if technique:
            value = technique.group(1)
            if value not in techniques:
                techniques.append(value)
            continue
        tactic = TACTIC_TAG_RE.match(text)
        if tactic:
            value = tactic.group(1)
            if value not in tactics:
                tactics.append(value)
            continue
        rule = RULE_TAG_RE.match(text)
        if rule and rule.group(1) not in rules:
            rules.append(rule.group(1))
    return techniques, tactics, rules


def stream_name_for_threat(threat):
    """Redis stream name = threat name, matching the SIEM contract."""
    name = str(_first(threat, "name", "threatName", default="") or "").strip()
    return name or DEFAULT_STREAM_NAME


def resolve_ingest_stream(stream_name, *, default=DEFAULT_STREAM_NAME):
    """Honour a Module subscribed to this threat name, else the generic stream."""
    from apps.agentic.runtime.module import discover_module_definitions

    candidate = str(stream_name or "").strip()
    if not candidate:
        return default
    try:
        subscribed = {definition.stream_name for definition in discover_module_definitions()}
    except Exception:
        logger.exception("Failed to scan Module definitions while resolving the Trellix stream")
        return candidate
    return candidate if candidate in subscribed else default


def correlation_key(threat_id, host_key):
    raw = f"{threat_id or 'unknown'}|{host_key or 'unknown'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


PRIVATE_PREFIXES = ("10.", "192.168.", "172.")
LINK_LOCAL_PREFIX = "169.254."


def host_addresses(host):
    """Real host IPs and MACs live in host.netInterfaces, not on the host root.

    Link-local 169.254.* addresses are skipped: every Windows box has several
    and they identify nothing.
    """
    ips, macs = [], []
    for interface in (host or {}).get("netInterfaces") or []:
        if not isinstance(interface, dict):
            continue
        ip = str(interface.get("ip") or "").strip()
        mac = str(interface.get("macAddress") or "").strip()
        if ip and not ip.startswith(LINK_LOCAL_PREFIX) and ip not in ips:
            ips.append(ip)
        if mac and mac not in macs:
            macs.append(mac)
    return ips, macs


def primary_ip(ips):
    """Prefer a routable RFC1918 address over anything else."""
    for ip in ips:
        if ip.startswith(PRIVATE_PREFIXES):
            return ip
    return ips[0] if ips else ""


def normalize_detection(threat, affected_host, detection, *, console_url=""):
    """Build one ingestion payload from a threat, its host and one detection."""
    threat = dict(threat or {})
    affected_host = dict(affected_host or {})
    detection = dict(detection or {})

    detection_id = _first(detection, "id")
    if detection_id is None:
        raise ValueError("Trellix detection payload has no id.")

    threat_id = _first(threat, "id")
    host = _first(detection, "host", default={}) or _first(affected_host, "host", default={}) or {}
    operating_system = (host.get("os") or {}) if isinstance(host, dict) else {}

    # Trellix rates individual detections lower (s1/s2) than the threat that
    # owns them; the console shows the threat severity, so grade the alert by
    # whichever of the two is higher.
    detection_severity = str(_first(detection, "severity", default="") or "")
    threat_severity = str(_first(threat, "severity", default="") or "")
    severity_code = max(
        (code for code in (detection_severity, threat_severity) if code in SEVERITY_ORDER),
        key=SEVERITY_ORDER.get,
        default="",
    )
    techniques, tactics, rules = parse_tags(detection.get("tags"))

    hostname = _first(host, "hostname", "name", default="")
    ma_guid = _first(host, "maGuid", default="")
    ips, macs = host_addresses(host)

    # Threat detail fields; absent when only the list payload was fetched.
    hashes = _first(threat, "hashes", default={}) or {}
    interpreter = _first(threat, "interpreter", default={}) or {}
    interpreter_hashes = interpreter.get("hashes") or {}

    return {
        "source": "trellix",
        "detection_id": str(detection_id),
        "threat_id": str(threat_id) if threat_id is not None else "",
        "affected_host_id": str(_first(affected_host, "id", default="")),
        "stream_name": stream_name_for_threat(threat),
        "threat_name": _first(threat, "name", default=""),
        "rule_names": rules,
        "rule_name": rules[0] if rules else _first(threat, "name", default=""),
        "severity_code": severity_code,
        "severity": SEVERITY_LABELS.get(severity_code, ""),
        "detection_severity_code": detection_severity,
        "threat_severity_code": threat_severity,
        "rank": _first(detection, "rank", default=0),
        "score": _first(threat, "score", default=0),
        "trace_id": _first(detection, "traceId", default=""),
        "sha256": _first(detection, "sha256", default=""),
        "detected_at": _first(detection, "lastDetected", "firstDetected"),
        "first_detected": _first(detection, "firstDetected", default=""),
        "last_detected": _first(detection, "lastDetected", default=""),
        "threat_last_detected": _first(threat, "lastDetected", default=""),
        "hostname": hostname,
        "agent_id": ma_guid,
        "host_ip": primary_ip(ips),
        "host_ips": ips,
        "host_macs": macs,
        "os": _first(operating_system, "desc", default=""),
        "last_boot_time": _first(host, "lastBootTime", default=""),
        "threat_type": _first(threat, "type", default=""),
        "threat_status": _first(threat, "status", default=""),
        "top_rank_tag": _first(threat, "topRankTag", default=""),
        "aggregation_key": _first(threat, "aggregationKey", default=""),
        "file_sha256": hashes.get("sha256", "") or _first(detection, "sha256", default=""),
        "file_sha1": hashes.get("sha1", ""),
        "file_md5": hashes.get("md5", ""),
        "interpreter_name": interpreter.get("name", ""),
        "interpreter_sha256": interpreter_hashes.get("sha256", ""),
        "interpreter_md5": interpreter_hashes.get("md5", ""),
        "username": _first(detection, "username", default="") or _first(host, "user", default=""),
        "detections_on_host": _first(affected_host, "detectionsCount", default=0),
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
        "tags": detection.get("tags") or [],
        "console_url": console_url,
        "correlation_key": correlation_key(threat_id, ma_guid or hostname),
        "raw_detection": detection,
        "raw_threat": {key: threat.get(key) for key in ("id", "name", "severity", "score", "lastDetected")},
    }
