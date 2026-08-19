"""Asset context resolution.

Every field is either sourced from a system of record or the literal string
`unknown`. Nothing is inferred from a hostname unless an explicit, configured
naming rule says so — and then the result is labelled as inferred, not as CMDB
truth.

The mock CMDB provider is deliberately treated as *not* authoritative: it
fabricates plausible asset profiles from a hash, and feeding that into a prompt
is how an ordinary workstation became a "production server" in an AI verdict.
"""

import logging
import re

logger = logging.getLogger(__name__)

UNKNOWN = "unknown"

SOURCE_CMDB = "cmdb"
SOURCE_DIRECTORY = "directory"
SOURCE_NAMING_RULE = "naming_rule"
SOURCE_OS_REPORTED = "os_reported"
SOURCE_NONE = "none"

SOURCE_LABELS = {
    SOURCE_CMDB: "CMDB: matched",
    SOURCE_DIRECTORY: "CMDB: no match — inferred from directory",
    SOURCE_NAMING_RULE: "CMDB: no match — inferred from naming rule",
    SOURCE_OS_REPORTED: "CMDB: no match — device type from OS reported by the agent",
    SOURCE_NONE: "Unknown",
}

# Providers that synthesise data rather than reporting it.
NON_AUTHORITATIVE_PROVIDERS = {"MockCMDBProvider", "Mock", "MockTIProvider"}

ASSET_FIELDS = (
    "device_type",
    "environment",
    "criticality",
    "owner",
    "business_service",
    "location",
    "network_zone",
    "os",
)


def empty_context():
    context = {field: UNKNOWN for field in ASSET_FIELDS}
    context.update({
        "cmdb_matched": False,
        "asset_context_source": SOURCE_NONE,
        "asset_context_source_label": SOURCE_LABELS[SOURCE_NONE],
        "provider": "",
    })
    return context


def _clean(value):
    text = str(value or "").strip()
    return text or UNKNOWN


def _from_cmdb(hostname):
    """Authoritative CMDB lookup. Mock providers are ignored on purpose."""
    from integrations.cmdb.service import lookup_artifact_context

    try:
        output = lookup_artifact_context("Hostname", hostname)
    except Exception:
        logger.warning("CMDB lookup failed for %s", hostname, exc_info=True)
        return None

    payload = output.model_dump() if hasattr(output, "model_dump") else (output or {})
    for result in payload.get("results") or []:
        provider = str(result.get("provider") or "")
        if provider in NON_AUTHORITATIVE_PROVIDERS:
            logger.debug("Ignoring non-authoritative CMDB provider %s for %s", provider, hostname)
            continue
        asset = result.get("asset") or {}
        business = result.get("business") or {}
        if not asset and not business:
            continue
        return {
            "device_type": _clean(asset.get("asset_type")),
            "environment": _clean(asset.get("environment")),
            "criticality": _clean(business.get("criticality") or business.get("business_criticality")),
            "owner": _clean(business.get("owner") or business.get("owner_team")),
            "business_service": _clean(business.get("service_name") or business.get("service_id")),
            "location": _clean(asset.get("location")),
            "network_zone": _clean(asset.get("network_zone")),
            "os": _clean(asset.get("os")),
            "cmdb_matched": True,
            "asset_context_source": SOURCE_CMDB,
            "asset_context_source_label": SOURCE_LABELS[SOURCE_CMDB],
            "provider": provider,
        }
    return None


def _device_type_from_os(os_text):
    """Windows Server vs client edition is the one reliable directory signal."""
    text = str(os_text or "").lower()
    if not text:
        return UNKNOWN
    if "server" in text:
        return "server"
    if any(token in text for token in ("windows 10", "windows 11", "windows 7", "windows 8")):
        return "workstation"
    if any(token in text for token in ("mac", "ubuntu desktop")):
        return "workstation"
    return UNKNOWN


def _from_directory(hostname):
    """AD computer object: OU plus operatingSystem.

    Returns None when LDAP is not configured, so the caller falls through to
    naming rules instead of inventing a value.
    """
    from apps.settings.runtime_config import get_ldap_config

    config = get_ldap_config()
    if not config.get("enabled"):
        return None

    try:
        from apps.accounts.ldap import fetch_computer_object
    except ImportError:
        logger.debug("No directory computer lookup available; skipping")
        return None

    try:
        record = fetch_computer_object(hostname)
    except Exception:
        logger.warning("Directory lookup failed for %s", hostname, exc_info=True)
        return None
    if not record:
        return None

    context = empty_context()
    context.update({
        "device_type": _device_type_from_os(record.get("operatingSystem")),
        "os": _clean(record.get("operatingSystem")),
        "owner": _clean(record.get("managedBy") or record.get("ou")),
        "location": _clean(record.get("location")),
        "cmdb_matched": False,
        "asset_context_source": SOURCE_DIRECTORY,
        "asset_context_source_label": SOURCE_LABELS[SOURCE_DIRECTORY],
    })
    return context


def _from_naming_rules(hostname):
    from apps.settings.runtime_config import get_asset_naming_rules

    name = str(hostname or "").strip()
    if not name:
        return None

    for rule in get_asset_naming_rules() or []:
        pattern = str((rule or {}).get("pattern") or "").strip()
        if not pattern:
            continue
        try:
            if not re.search(pattern, name, re.IGNORECASE):
                continue
        except re.error:
            logger.warning("Invalid asset naming rule pattern: %r", pattern)
            continue

        context = empty_context()
        context.update({
            "device_type": _clean(rule.get("device_type")),
            "environment": _clean(rule.get("environment")),
            "owner": _clean(rule.get("owner")),
            "criticality": _clean(rule.get("criticality")),
            "cmdb_matched": False,
            "asset_context_source": SOURCE_NAMING_RULE,
            "asset_context_source_label": SOURCE_LABELS[SOURCE_NAMING_RULE],
            "matched_rule": pattern,
        })
        return context
    return None


def resolve_asset_context(hostname, *, os_hint=""):
    """Resolve asset context through the documented fallback chain.

    CMDB → directory → configured naming rule → unknown. The source is always
    reported so a reader knows how much to trust the values.
    """
    if not str(hostname or "").strip():
        return empty_context()

    for resolver in (_from_cmdb, _from_directory, _from_naming_rules):
        try:
            context = resolver(hostname)
        except Exception:
            logger.exception("Asset resolver %s failed for %s", resolver.__name__, hostname)
            continue
        if context:
            if context.get("os") in (UNKNOWN, "") and os_hint:
                context["os"] = _clean(os_hint)
            if context.get("device_type") == UNKNOWN and os_hint:
                context["device_type"] = _device_type_from_os(os_hint)
            return context

    context = empty_context()
    if os_hint:
        context["os"] = _clean(os_hint)
        device_type = _device_type_from_os(os_hint)
        context["device_type"] = device_type
        if device_type != UNKNOWN:
            # Derived from the OS string the agent reported: deterministic, and
            # labelled so nobody mistakes it for a CMDB record.
            context["asset_context_source"] = SOURCE_OS_REPORTED
            context["asset_context_source_label"] = SOURCE_LABELS[SOURCE_OS_REPORTED]
    return context


ROLE_CLAIM_TERMS = (
    "server",
    "production",
    "prod",
    "workstation",
    "domain controller",
    "database",
    "máy chủ",
    "máy trạm",
)


def detect_unverified_asset_claim(text, asset_context):
    """Flag role language in the model's prose when no system of record backed it."""
    if (asset_context or {}).get("cmdb_matched"):
        return []
    lowered = str(text or "").lower()
    hits = sorted({term for term in ROLE_CLAIM_TERMS if term in lowered})
    if not hits:
        return []
    return [{
        "flag": "unverified_asset_claim",
        "terms": hits,
        "asset_context_source": (asset_context or {}).get("asset_context_source", SOURCE_NONE),
    }]
