"""Typed entity extraction.

An entity is what a human recognises: a hostname, a user, a process. An agent
GUID, a detection id or an offence id identifies a record in the source system;
it is a source identifier, not an entity, and must never be shown as one.

Extraction is typed here rather than fixed at render time, so every consumer —
UI, notifications, prompts — sees the same ordering.
"""

import re

ENTITY_PRIORITY = ("hostname", "username", "process", "ip", "hash")

ARTIFACT_TYPE_TO_ENTITY = {
    "hostname": "hostname",
    "host name": "hostname",
    "user name": "username",
    "username": "username",
    "user": "username",
    "account": "username",
    "process name": "process",
    "process": "process",
    "command line": "process",
    "ip address": "ip",
    "ip": "ip",
    "hash": "hash",
    "file hash": "hash",
}

# Values that identify a record in the source system rather than a real entity.
SOURCE_IDENTIFIER_TYPES = {"other", "device", "fingerprint", "serial number"}
GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _entity_kind(artifact_type, value):
    kind = ARTIFACT_TYPE_TO_ENTITY.get(str(artifact_type or "").strip().lower())
    if kind is None:
        return None
    if kind == "hostname" and GUID_RE.match(str(value or "").strip()):
        # A GUID in a hostname field is an agent identifier, not a host name.
        return None
    return kind


def extract_entities(case):
    """Collect typed entities and source identifiers for one Case."""
    entities = {kind: [] for kind in ENTITY_PRIORITY}
    source_identifiers = []

    for alert in case.alerts.all():
        for artifact in alert.artifacts.all():
            value = str(getattr(artifact, "value", "") or "").strip()
            if not value:
                continue
            artifact_type = str(getattr(artifact, "type", "") or "")
            kind = _entity_kind(artifact_type, value)

            if kind is None:
                lowered = artifact_type.strip().lower()
                if lowered in SOURCE_IDENTIFIER_TYPES or GUID_RE.match(value):
                    entry = {"type": artifact_type or "identifier", "value": value}
                    if entry not in source_identifiers:
                        source_identifiers.append(entry)
                continue

            if value not in entities[kind]:
                entities[kind].append(value)

        unmapped = getattr(alert, "unmapped", None) or {}
        for key in ("trellix_agent_id", "trellix_detection_id", "trellix_trace_id", "qradar_offense_id"):
            value = unmapped.get(key)
            if value:
                entry = {"type": key, "value": str(value)}
                if entry not in source_identifiers:
                    source_identifiers.append(entry)

    return {"entities": entities, "source_identifiers": source_identifiers}


def primary_entity(extracted):
    """Highest-priority entity value, or an empty string."""
    entities = (extracted or {}).get("entities") or {}
    for kind in ENTITY_PRIORITY:
        values = entities.get(kind) or []
        if values:
            return {"kind": kind, "value": values[0]}
    return {"kind": "", "value": ""}


def entity_display(extracted):
    """Human-facing label, e.g. `THAONTP21 / SHB\\thaontp`."""
    entities = (extracted or {}).get("entities") or {}
    parts = []
    for kind in ("hostname", "username"):
        values = entities.get(kind) or []
        if values:
            parts.append(values[0])
    if parts:
        return " / ".join(parts)

    primary = primary_entity(extracted)
    return primary["value"]
