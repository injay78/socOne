"""QRadar REST client.

The token issued to ASP carries read permission only, so every write path is
gated behind `allow_write` and raises while that flag is off. The gate lives in
the client, not in callers, so no skill can route around it.
"""

import logging
import time

import httpx

logger = logging.getLogger(__name__)

ARIEL_COMPLETED_STATES = {"COMPLETED"}
ARIEL_FAILED_STATES = {"ERROR", "CANCELED"}
SEARCH_POLL_INTERVAL_SECONDS = 2.0
RETRYABLE_STATUS = {500, 502, 503, 504}
MAX_TRANSPORT_RETRIES = 3


class QRadarApiError(RuntimeError):
    def __init__(self, message, *, status_code=None, qradar_code=None):
        super().__init__(message)
        self.status_code = status_code
        self.qradar_code = qradar_code


class QRadarWriteDisabled(RuntimeError):
    """Raised when a write operation is attempted on a read-only connection."""


class QRadarSearchTimeout(QRadarApiError):
    pass


class QRadarClient:
    def __init__(self, config):
        self.config = config
        self.base_url = (config.get("base_url") or "").rstrip("/")
        if not self.base_url:
            raise QRadarApiError("QRadar base URL is not configured.")
        if not config.get("api_token"):
            raise QRadarApiError("QRadar API token is not configured.")

    # ------------------------------------------------------------------ HTTP

    def _headers(self, extra=None):
        headers = {
            "SEC": self.config["api_token"],
            "Version": self.config.get("api_version") or "22.0",
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    def _verify(self):
        ca_bundle = (self.config.get("ca_bundle_path") or "").strip()
        if not self.config.get("verify_ssl"):
            return False
        return ca_bundle or True

    def _client(self, timeout):
        return httpx.Client(verify=self._verify(), timeout=timeout, trust_env=False)

    def _request(self, method, path, *, timeout=None, headers=None, params=None, data=None):
        url = f"{self.base_url}{path}"
        timeout = timeout or self.config.get("metadata_timeout_seconds", 30)
        last_error = None

        for attempt in range(1, MAX_TRANSPORT_RETRIES + 1):
            try:
                with self._client(timeout) as client:
                    response = client.request(
                        method,
                        url,
                        headers=self._headers(headers),
                        params=params,
                        data=data,
                    )
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == MAX_TRANSPORT_RETRIES:
                    raise QRadarApiError(f"QRadar request failed: {type(exc).__name__}") from exc
                time.sleep(min(2 ** attempt, 8))
                continue

            if response.status_code in RETRYABLE_STATUS and attempt < MAX_TRANSPORT_RETRIES:
                time.sleep(min(2 ** attempt, 8))
                continue
            return self._handle_response(response)

        raise QRadarApiError(f"QRadar request failed after retries: {last_error}")

    def _handle_response(self, response):
        if response.is_success:
            if not response.content:
                return None
            try:
                return response.json()
            except ValueError as exc:
                raise QRadarApiError(
                    f"QRadar returned non-JSON content type '{response.headers.get('content-type', 'unknown')}'."
                ) from exc

        qradar_code = None
        message = response.text[:300]
        try:
            body = response.json()
            qradar_code = body.get("code")
            message = body.get("message") or body.get("description") or message
        except ValueError:
            pass
        raise QRadarApiError(
            f"QRadar returned HTTP {response.status_code}: {message}",
            status_code=response.status_code,
            qradar_code=qradar_code,
        )

    # ---------------------------------------------------------------- Ariel

    def create_search(self, query_expression):
        payload = {"query_expression": query_expression}
        result = self._request(
            "POST",
            "/api/ariel/searches",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.config.get("metadata_timeout_seconds", 30),
        )
        search_id = (result or {}).get("search_id")
        if not search_id:
            raise QRadarApiError("QRadar did not return a search_id.")
        return search_id

    def get_search(self, search_id):
        return self._request("GET", f"/api/ariel/searches/{search_id}")

    def delete_search(self, search_id):
        """Cancel and remove a search. Allowed while read-only: it only frees
        resources this client itself created."""
        try:
            self._request("DELETE", f"/api/ariel/searches/{search_id}")
        except QRadarApiError:
            logger.warning("Failed to delete QRadar search %s", search_id, exc_info=True)

    def get_search_results(self, search_id, *, max_rows):
        return self._request(
            "GET",
            f"/api/ariel/searches/{search_id}/results",
            headers={"Range": f"items=0-{max(0, max_rows - 1)}"},
            timeout=self.config.get("search_timeout_seconds", 300),
        )

    def run_aql(self, guarded_query, *, max_rows=None):
        """Execute an already-guarded AQL statement and return its rows."""
        max_rows = max_rows or self.config.get("max_rows", 1000)
        deadline = time.monotonic() + self.config.get("search_timeout_seconds", 300)
        search_id = self.create_search(guarded_query)

        try:
            while True:
                status = (self.get_search(search_id) or {}).get("status", "")
                if status in ARIEL_COMPLETED_STATES:
                    break
                if status in ARIEL_FAILED_STATES:
                    raise QRadarApiError(f"QRadar search ended with status {status}.")
                if time.monotonic() > deadline:
                    raise QRadarSearchTimeout(
                        f"QRadar search {search_id} did not complete within the configured timeout."
                    )
                time.sleep(SEARCH_POLL_INTERVAL_SECONDS)

            results = self.get_search_results(search_id, max_rows=max_rows) or {}
        except Exception:
            self.delete_search(search_id)
            raise

        rows = results.get("events") or results.get("flows") or []
        return rows[:max_rows]

    # -------------------------------------------------------------- Offenses

    def list_offenses(self, *, filter_expression=None, fields=None, offset=0, limit=100):
        headers = {"Range": f"items={offset}-{max(offset, offset + limit - 1)}"}
        params = {}
        if filter_expression:
            params["filter"] = filter_expression
        if fields:
            params["fields"] = ",".join(fields)
        return self._request("GET", "/api/siem/offenses", headers=headers, params=params) or []

    def get_offense(self, offense_id):
        return self._request("GET", f"/api/siem/offenses/{offense_id}")

    def get_offense_notes(self, offense_id):
        return self._request("GET", f"/api/siem/offenses/{offense_id}/notes") or []

    def get_offense_source_addresses(self, address_ids):
        return self._batch_addresses("/api/siem/source_addresses", address_ids)

    def get_offense_local_destination_addresses(self, address_ids):
        return self._batch_addresses("/api/siem/local_destination_addresses", address_ids)

    def _batch_addresses(self, path, address_ids):
        ids = [str(item) for item in (address_ids or []) if item is not None]
        if not ids:
            return []
        expression = " or ".join(f"id={item}" for item in ids)
        return self._request("GET", path, params={"filter": expression}) or []

    def list_offense_types(self):
        return self._request("GET", "/api/siem/offense_types") or []

    def list_closing_reasons(self):
        return self._request("GET", "/api/siem/offense_closing_reasons") or []

    # -------------------------------------------------------- Reference data

    def get_reference_set(self, name):
        return self._request("GET", f"/api/reference_data/sets/{name}")

    def list_reference_sets(self):
        return self._request("GET", "/api/reference_data/sets") or []

    # ----------------------------------------------------------------- Write

    def _require_write(self, operation):
        if not self.config.get("allow_write"):
            raise QRadarWriteDisabled(
                f"QRadar write operation '{operation}' is disabled. "
                "The ASP token is read-only; enable allow_write only after QRadar grants write permission."
            )

    def close_offense(self, offense_id, closing_reason_id):
        self._require_write("close_offense")
        return self._request(
            "POST",
            f"/api/siem/offenses/{offense_id}",
            data={"status": "CLOSED", "closing_reason_id": closing_reason_id},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def add_offense_note(self, offense_id, note_text):
        self._require_write("add_offense_note")
        return self._request(
            "POST",
            f"/api/siem/offenses/{offense_id}/notes",
            data={"note_text": note_text},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def add_reference_set_value(self, name, value):
        self._require_write("add_reference_set_value")
        return self._request(
            "POST",
            f"/api/reference_data/sets/{name}",
            data={"value": value},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
