"""Entity signatures used to link Cases into clusters.

Extraction itself is not reimplemented here: triage already produces typed
entities from Alert and Artifact records, and having two extractors would let the
cluster view and the case view disagree about what an entity is.
"""

import hashlib

from apps.agentic.triage.entities import ENTITY_PRIORITY, extract_entities

# Entities that identify *who* and *where* carry more linking weight than a value
# that legitimately recurs across unrelated activity, such as a shared gateway IP.
ENTITY_WEIGHTS = {
    "hostname": 1.0,
    "username": 1.0,
    "hash": 0.9,
    "process": 0.5,
    "ip": 0.4,
}


def entity_pairs(extracted):
    """Flatten a triage extraction into a set of `kind:value` strings."""
    entities = (extracted or {}).get("entities") or {}
    pairs = set()
    for kind in ENTITY_PRIORITY:
        for value in entities.get(kind) or []:
            text = str(value).strip()
            if text:
                pairs.add(f"{kind}:{text.lower()}")
    return pairs


def case_tactics(case):
    """MITRE tactics attached to a Case, from its alerts and its triage result."""
    tactics = set()
    for alert in case.alerts.all():
        tactic = (getattr(alert, "tactic", "") or "").strip()
        if tactic:
            tactics.add(tactic.lower())

    triage = getattr(case, "triage_results", None)
    if triage is not None:
        latest = triage.all()[:1]
        for result in latest:
            for tactic in result.mitre_tactics or []:
                text = str(tactic).strip()
                if text:
                    tactics.add(text.lower())
    return tactics


def build_node(case):
    """Everything the scorer needs about one Case, read once."""
    extracted = extract_entities(case)
    return {
        "case": case,
        "extracted": extracted,
        "pairs": entity_pairs(extracted),
        "tactics": case_tactics(case),
        "timestamp": case.created_at,
    }


def merge_entity_sets(nodes):
    """Union the typed entity sets of several nodes, preserving kind grouping."""
    merged = {kind: [] for kind in ENTITY_PRIORITY}
    for node in nodes:
        entities = (node["extracted"] or {}).get("entities") or {}
        for kind in ENTITY_PRIORITY:
            for value in entities.get(kind) or []:
                text = str(value).strip()
                if text and text not in merged[kind]:
                    merged[kind].append(text)
    return {kind: sorted(values) for kind, values in merged.items() if values}


def fingerprint_for(primary_entities):
    """Stable hash over the sorted entity set.

    Identity of record for a cluster. Lookup still happens by entity overlap
    first, because a cluster that gains an entity must be extended rather than
    replaced by a second cluster carrying a new hash.
    """
    pairs = []
    for kind in sorted(primary_entities or {}):
        for value in sorted(primary_entities[kind] or []):
            pairs.append(f"{kind}:{str(value).strip().lower()}")
    digest = hashlib.sha256("|".join(sorted(pairs)).encode("utf-8"))
    return digest.hexdigest()


def entity_pairs_from_primary(primary_entities):
    pairs = set()
    for kind, values in (primary_entities or {}).items():
        for value in values or []:
            text = str(value).strip()
            if text:
                pairs.add(f"{kind}:{text.lower()}")
    return pairs


def cluster_title(primary_entities, case_count):
    """Human-facing label built from the highest-priority entities present."""
    for kind in ENTITY_PRIORITY:
        values = (primary_entities or {}).get(kind) or []
        if values:
            head = ", ".join(values[:3])
            suffix = "" if len(values) <= 3 else f" +{len(values) - 3}"
            return f"{head}{suffix} ({case_count} cases)"
    return f"Unlinked cluster ({case_count} cases)"
