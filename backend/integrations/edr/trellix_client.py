"""Trellix EDR SaaS client.

Ingestion walks the real API hierarchy: threats → affected hosts → detections.
Every list endpoint pages with skip/items/total and takes a `from` epoch in
milliseconds as the lower time bound.

Containment is implemented but inert unless `allow_containment` is enabled, in
which case it still requires a Critical-risk playbook and human approval.
"""

import json
import logging
import time

import httpx

from integrations.edr import trellix_endpoints as endpoints
from integrations.edr.trellix_auth import get_access_token, invalidate_token

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_TRANSPORT_RETRIES = 3
DEFAULT_PAGE_SIZE = 50
MAX_PAGES = 200
SEARCH_POLL_INTERVAL_SECONDS = 2.0
SEARCH_MAX_POLL_SECONDS = 300

# Ingest only actionable severities by default; s0-s2 is mostly endpoint noise.
DEFAULT_SEVERITIES = ["s3", "s4", "s5"]
DEFAULT_SCORE_RANGE = [30]


class TrellixApiError(RuntimeError):
    def __init__(self, message, *, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class TrellixContainmentDisabled(RuntimeError):
    """Raised when a containment action is attempted while the flag is off."""


class ContainmentPlan(dict):
    """Dry-run description of a containment action that was not executed."""


class TrellixEdrClient:
    def __init__(self, config):
        self.config = config
        self.base_url = endpoints.api_host(config.get("api_base_url"))
        if not self.base_url:
            raise TrellixApiError(
                "Trellix API base URL is not configured. Use the tenant domain, e.g. soc.trellix.com."
            )

    # ------------------------------------------------------------------ HTTP

    def _headers(self):
        headers = {
            "Authorization": f"Bearer {get_access_token(self.config)}",
            "Accept": "application/json",
        }
        if self.config.get("tenant_id"):
            headers["x-tenant-id"] = self.config["tenant_id"]
        return headers

    def _request(self, method, path, *, params=None, json_body=None, retry_auth=True):
        url = f"{self.base_url}{path}"

        for attempt in range(1, MAX_TRANSPORT_RETRIES + 1):
            try:
                with httpx.Client(timeout=self.config.get("timeout_seconds", 60), trust_env=False) as client:
                    response = client.request(method, url, headers=self._headers(), params=params, json=json_body)
            except httpx.ConnectError as exc:
                raise TrellixApiError(
                    f"Cannot reach {url}: {exc}. Verify api_base_url is the tenant domain."
                ) from exc
            except httpx.HTTPError as exc:
                if attempt == MAX_TRANSPORT_RETRIES:
                    raise TrellixApiError(f"Trellix request failed: {type(exc).__name__}") from exc
                time.sleep(min(2 ** attempt, 8))
                continue

            if response.status_code == 401 and retry_auth:
                invalidate_token(self.config)
                return self._request(method, path, params=params, json_body=json_body, retry_auth=False)

            if response.status_code == 429:
                delay = _retry_after_seconds(response) or min(2 ** attempt, 8)
                if attempt < MAX_TRANSPORT_RETRIES:
                    time.sleep(delay)
                    continue

            if response.status_code in RETRYABLE_STATUS and attempt < MAX_TRANSPORT_RETRIES:
                time.sleep(min(2 ** attempt, 8))
                continue

            return self._handle_response(response, path)

        raise TrellixApiError("Trellix request failed after retries.")

    def _handle_response(self, response, path):
        if response.is_success:
            if not response.content:
                return {}
            try:
                return response.json()
            except ValueError as exc:
                raise TrellixApiError(
                    f"Trellix returned non-JSON content for {path} "
                    f"(content-type '{response.headers.get('content-type', 'unknown')}')."
                ) from exc

        if response.status_code in {401, 403}:
            raise TrellixApiError(
                f"Trellix rejected {path} with HTTP {response.status_code}: {response.text[:200]}. "
                "Check the tenant domain and that the credential carries the scope this endpoint needs.",
                status_code=response.status_code,
            )
        if response.status_code == 404:
            raise TrellixApiError(
                f"Trellix returned 404 for {path}. The endpoint may not exist on this tenant.",
                status_code=404,
            )
        raise TrellixApiError(
            f"Trellix returned HTTP {response.status_code} for {path}: {response.text[:200]}",
            status_code=response.status_code,
        )

    def _paginate(self, path, *, collection, params=None, page_size=None):
        """Walk a Trellix list endpoint.

        The API reports total/items/skipped; a page is the last one when
        skipped + items reaches total.
        """
        limit = page_size or min(self.config.get("max_rows", 1000), DEFAULT_PAGE_SIZE)
        skip = 0
        collected = []

        for _page in range(MAX_PAGES):
            query = dict(params or {})
            query.update({"limit": limit, "skip": skip})
            body = self._request("GET", path, params=query) or {}

            collected.extend(body.get(collection) or [])

            total = int(body.get("total") or 0)
            items = int(body.get("items") or 0)
            skipped = int(body.get("skipped") or 0)

            if items == 0 or skipped + items >= total:
                break
            skip = skipped + items
            if len(collected) >= self.config.get("max_rows", 1000):
                logger.info("Trellix pagination stopped at max_rows for %s", path)
                break

        return collected

    # --------------------------------------------------------------- Threats

    def list_threats(self, *, since_epoch_ms, severities=None, score_range=None, page_size=None):
        """Threats last detected at or after `since_epoch_ms`, newest first."""
        threat_filter = {
            "severities": severities or DEFAULT_SEVERITIES,
            "scoreRange": score_range or DEFAULT_SCORE_RANGE,
        }
        return self._paginate(
            endpoints.THREATS_PATH,
            collection="threats",
            params={
                "sort": "-lastDetected",
                "filter": json.dumps(threat_filter),
                "from": int(since_epoch_ms),
            },
            page_size=page_size,
        )

    def get_threat(self, threat_id):
        """Threat detail. Carries file hashes, the interpreter process and the
        score, none of which appear in the threat list."""
        return self._request("GET", endpoints.THREAT_DETAIL_PATH.format(threat_id=threat_id)) or {}

    def get_detection(self, threat_id, detection_id):
        return self._request(
            "GET",
            endpoints.DETECTION_DETAIL_PATH.format(threat_id=threat_id, detection_id=detection_id),
        ) or {}

    def list_affected_hosts(self, threat_id, *, since_epoch_ms, page_size=None):
        return self._paginate(
            endpoints.THREAT_AFFECTED_HOSTS_PATH.format(threat_id=threat_id),
            collection="affectedHosts",
            params={"sort": "-rank", "from": int(since_epoch_ms)},
            page_size=page_size,
        )

    def list_detections(self, threat_id, affected_host_id, *, since_epoch_ms, page_size=None):
        return self._paginate(
            endpoints.THREAT_DETECTIONS_PATH.format(threat_id=threat_id),
            collection="detections",
            params={
                "sort": "-rank",
                "from": int(since_epoch_ms),
                "filter": json.dumps({"affectedHostId": affected_host_id}),
            },
            page_size=page_size,
        )

    def console_url(self, *, threat_id, trace_id="", ma_guid="", sha256=""):
        return endpoints.console_url(
            self.config.get("api_base_url"),
            threat_id=threat_id,
            trace_id=trace_id,
            ma_guid=ma_guid,
            sha256=sha256,
        )

    # ----------------------------------------------------------------- Hosts

    def get_host(self, *, hostname=None, ip=None, agent_id=None):
        params = {}
        if agent_id:
            params["maGuid"] = agent_id
        if hostname:
            params["hostname"] = hostname
        if ip:
            params["ipAddress"] = ip
        if not params:
            raise ValueError("get_host requires hostname, ip or agent_id.")

        body = self._request("GET", endpoints.SYSTEMS_PATH, params=params) or {}
        systems = body.get("systems") or body.get("data") or []
        return systems[0] if systems else None

    # ---------------------------------------------------------------- Search

    def search_realtime(self, query, *, limit=None, host_ids=()):
        from integrations.edr.trellix_guard import guard_edr_search

        guarded = guard_edr_search(query, hours=1, limit=limit, host_ids=host_ids, config=self.config)
        guarded.raise_for_rejection()
        return self._run_search(
            endpoints.REALTIME_SEARCH_PATH,
            {"query": guarded.query, "limit": guarded.limit, "hostIds": list(guarded.host_ids)},
            mode="realtime",
            guarded=guarded,
        )

    def search_historical(self, query, *, hours=None, limit=None, host_ids=()):
        from integrations.edr.trellix_guard import guard_edr_search

        guarded = guard_edr_search(query, hours=hours, limit=limit, host_ids=host_ids, config=self.config)
        guarded.raise_for_rejection()
        return self._run_search(
            endpoints.HISTORICAL_SEARCH_PATH,
            {
                "query": guarded.query,
                "limit": guarded.limit,
                "hours": guarded.hours,
                "hostIds": list(guarded.host_ids),
            },
            mode="historical",
            guarded=guarded,
        )

    def _run_search(self, path, body, *, mode, guarded):
        from integrations.siem.audit import record_edr_search

        started = time.perf_counter()
        created = self._request("POST", path, json_body=body) or {}
        search_id = created.get("searchId") or created.get("id")

        rows = self._poll_search(search_id, limit=guarded.limit) if search_id else []

        record_edr_search(
            query=guarded.query,
            mode=mode,
            rewrites=guarded.rewrites,
            row_count=len(rows),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
        return rows

    def _poll_search(self, search_id, *, limit):
        deadline = time.monotonic() + SEARCH_MAX_POLL_SECONDS
        while True:
            status_body = self._request("GET", endpoints.SEARCH_STATUS_PATH.format(search_id=search_id)) or {}
            status = str(status_body.get("status", "")).upper()
            if status in {"COMPLETED", "FINISHED", "SUCCESS"}:
                break
            if status in {"FAILED", "ERROR", "CANCELED"}:
                raise TrellixApiError(f"Trellix search {search_id} ended with status {status}.")
            if time.monotonic() > deadline:
                raise TrellixApiError(f"Trellix search {search_id} did not complete within the timeout.")
            time.sleep(SEARCH_POLL_INTERVAL_SECONDS)

        results = self._request("GET", endpoints.SEARCH_RESULTS_PATH.format(search_id=search_id)) or {}
        rows = results.get("results") or results.get("items") or []
        return rows[:limit]

    # ----------------------------------------------------------- Containment

    def _require_containment(self, action, plan):
        if not self.config.get("allow_containment"):
            logger.warning("Trellix containment action %s requested while disabled", action)
            return ContainmentPlan({
                "executed": False,
                "action": action,
                "reason": "containment_disabled",
                "plan": plan,
                "detail": (
                    "Containment is disabled. Enable allow_containment, run the action through the "
                    "Critical-risk playbook, and obtain human approval before execution."
                ),
            })
        return None

    def isolate_host(self, agent_id, *, reason=""):
        blocked = self._require_containment("isolate_host", {"agent_id": agent_id, "reason": reason})
        if blocked is not None:
            return blocked
        return self._request(
            "POST",
            endpoints.ISOLATE_HOST_PATH.format(agent_id=agent_id),
            json_body={"reason": reason},
        )

    def kill_process(self, agent_id, process_id, *, reason=""):
        blocked = self._require_containment(
            "kill_process", {"agent_id": agent_id, "process_id": process_id, "reason": reason}
        )
        if blocked is not None:
            return blocked
        return self._request(
            "POST",
            endpoints.KILL_PROCESS_PATH.format(agent_id=agent_id, process_id=process_id),
            json_body={"reason": reason},
        )

    def quarantine_file(self, agent_id, file_hash, *, reason=""):
        blocked = self._require_containment(
            "quarantine_file", {"agent_id": agent_id, "file_hash": file_hash, "reason": reason}
        )
        if blocked is not None:
            return blocked
        return self._request(
            "POST",
            endpoints.QUARANTINE_FILE_PATH.format(agent_id=agent_id),
            json_body={"hash": file_hash, "reason": reason},
        )


def _retry_after_seconds(response):
    value = response.headers.get("Retry-After")
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def get_trellix_client():
    from apps.settings.runtime_config import get_trellix_config

    return TrellixEdrClient(get_trellix_config())
