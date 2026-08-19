"""Trellix EDR SaaS endpoints, verified against a live tenant.

The API is a three-level hierarchy: a threat groups affected hosts, and each
affected host carries the individual detections. Ingestion walks all three.

Host naming: the tenant is identified by a base domain such as
`soc.trellix.com`. The API lives on `api.<base>` and the console on `ui.<base>`.
`api_base_url` accepts either form; `api_host()` normalises it.
"""

from urllib.parse import urlparse

TOKEN_PATH = "/token"

THREATS_PATH = "/ft/api/v2/ft/threats"
THREAT_DETAIL_PATH = "/ft/api/v2/ft/threats/{threat_id}"
DETECTION_DETAIL_PATH = "/ft/api/v2/ft/threats/{threat_id}/detections/{detection_id}"
THREAT_AFFECTED_HOSTS_PATH = "/ft/api/v2/ft/threats/{threat_id}/affectedhosts"
THREAT_DETECTIONS_PATH = "/ft/api/v2/ft/threats/{threat_id}/detections"

SYSTEMS_PATH = "/ft/api/v2/ft/systems"

# Search APIs, gated by the soc.hts.* / soc.rts.* scopes. Not used by ingestion;
# they back the hunting surface and are unverified on this tenant.
REALTIME_SEARCH_PATH = "/active-response/api/v1/searches"  # TODO(verify)
HISTORICAL_SEARCH_PATH = "/historical-search/api/v1/searches"  # TODO(verify)
SEARCH_STATUS_PATH = "/historical-search/api/v1/searches/{search_id}/status"  # TODO(verify)
SEARCH_RESULTS_PATH = "/historical-search/api/v1/searches/{search_id}/results"  # TODO(verify)

# Containment, inert unless allow_containment is enabled. Unverified.
ISOLATE_HOST_PATH = "/remediation/api/v1/systems/{agent_id}/isolate"  # TODO(verify)
KILL_PROCESS_PATH = "/remediation/api/v1/systems/{agent_id}/processes/{process_id}/kill"  # TODO(verify)
QUARANTINE_FILE_PATH = "/remediation/api/v1/systems/{agent_id}/files/quarantine"  # TODO(verify)

CONSOLE_THREAT_URL = (
    "https://ui.{base}/monitoring/#/workspace/72,TOTAL_THREATS,{threat_id}"
    "?traceId={trace_id}&maGuid={ma_guid}&sha256={sha256}"
)

VERIFIED_PATHS = {
    "THREATS_PATH": THREATS_PATH,
    "THREAT_DETAIL_PATH": THREAT_DETAIL_PATH,
    "DETECTION_DETAIL_PATH": DETECTION_DETAIL_PATH,
    "THREAT_AFFECTED_HOSTS_PATH": THREAT_AFFECTED_HOSTS_PATH,
    "THREAT_DETECTIONS_PATH": THREAT_DETECTIONS_PATH,
}


def base_domain(api_base_url):
    """Strip scheme and any api./ui. prefix to get the tenant base domain."""
    raw = str(api_base_url or "").strip()
    if not raw:
        return ""
    host = urlparse(raw).hostname if "//" in raw else raw.split("/")[0]
    host = (host or "").strip().lower().rstrip(".")
    for prefix in ("api.", "ui."):
        if host.startswith(prefix):
            return host[len(prefix):]
    return host


def api_host(api_base_url):
    """Full API origin. Accepts soc.trellix.com or https://api.soc.trellix.com."""
    base = base_domain(api_base_url)
    return f"https://api.{base}" if base else ""


def console_url(api_base_url, *, threat_id, trace_id="", ma_guid="", sha256=""):
    base = base_domain(api_base_url)
    if not base:
        return ""
    return CONSOLE_THREAT_URL.format(
        base=base,
        threat_id=threat_id,
        trace_id=trace_id,
        ma_guid=ma_guid,
        sha256=sha256,
    )
