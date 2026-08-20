"""Trellix EDR SaaS endpoints, verified against a live tenant.

The API is a three-level hierarchy: a threat groups affected hosts, and each
affected host carries the individual detections. Ingestion walks all three.

Host naming: the tenant is identified by a base domain such as
`soc.trellix.com`. The API lives on `api.<base>` and the console on `ui.<base>`.
`api_base_url` accepts either form; `api_host()` normalises it.

There is a second, newer surface: the platform API under `/edr/v2`, which
lives on its own gateway (`platform_gateway_url`, for example
https://api.manage.trellix.com) and needs an `x-api-key` header. It is the
documented source for ingestion, since its alert records carry the user,
the command line and the process ancestry that the threat endpoints omit.
"""

from urllib.parse import urlparse

TOKEN_PATH = "/token"

THREATS_PATH = "/ft/api/v2/ft/threats"
THREAT_DETAIL_PATH = "/ft/api/v2/ft/threats/{threat_id}"
DETECTION_DETAIL_PATH = "/ft/api/v2/ft/threats/{threat_id}/detections/{detection_id}"
THREAT_AFFECTED_HOSTS_PATH = "/ft/api/v2/ft/threats/{threat_id}/affectedhosts"
THREAT_DETECTIONS_PATH = "/ft/api/v2/ft/threats/{threat_id}/detections"

SYSTEMS_PATH = "/ft/api/v2/ft/systems"

# Platform API, taken from the Trellix EDR Product Guide (2026-08-11), reachable
# on the platform gateway rather than the legacy host and requiring an x-api-key
# header in addition to the OAuth bearer token. Sending only the bearer token
# returns 403; sending an invalid key returns 401.
#
# These paths replace an earlier set of invented ones. They are documented but
# not yet exercised on the SHB tenant, because the x-api-key is not configured.
ALERTS_PATH = "/edr/v2/alerts"

REALTIME_SEARCH_PATH = "/edr/v2/searches/realtime"
REALTIME_SEARCH_RESULTS_PATH = "/edr/v2/searches/realtime/{search_id}/results"
HISTORICAL_SEARCH_PATH = "/edr/v2/searches/historical"
HISTORICAL_SEARCH_RESULTS_PATH = "/edr/v2/searches/historical/{search_id}/results"
# Both search families report progress through one queue-jobs resource.
SEARCH_STATUS_PATH = "/edr/v2/searches/queue-jobs/{job_id}"

INVESTIGATIONS_PATH = "/edr/v2/investigations"
INVESTIGATION_DETAIL_PATH = "/edr/v2/investigations/{investigation_id}"
INVESTIGATION_EVIDENCE_PATH = "/edr/v2/investigations/{investigation_id}/evidence"

# Containment, inert unless allow_containment is enabled.
REMEDIATION_HOST_PATH = "/edr/v2/remediation/host"
REMEDIATION_SEARCH_PATH = "/edr/v2/remediation/search"
REMEDIATION_THREAT_PATH = "/edr/v2/remediation/threat"
REMEDIATION_ACTIONS_PATH = "/edr/v2/remediation/actions"
REMEDIATION_HOST_INFO_PATH = "/edr/v2/remediation/host-info"
REMEDIATION_STATUS_PATH = "/edr/v2/remediation/queue-jobs/{job_id}"

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
