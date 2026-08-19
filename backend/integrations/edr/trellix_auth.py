"""OAuth2 client-credentials token handling for the Trellix EDR SaaS tenant.

The token is cached in Redis per tenant and refreshed shortly before expiry, so
a fleet of workers shares one token instead of minting one per request. A short
Redis lock keeps a refresh stampede from hitting IAM when many workers wake at
once.
"""

import logging
import time

import httpx
from django.core.cache import caches

from integrations.edr.trellix_endpoints import TOKEN_PATH

logger = logging.getLogger(__name__)

TOKEN_CACHE_KEY = "asp:trellix:token:{tenant}"
LOCK_CACHE_KEY = "asp:trellix:token-lock:{tenant}"
LOCK_TTL_SECONDS = 30
REFRESH_MARGIN_SECONDS = 60
LOCK_WAIT_SECONDS = 0.5
LOCK_MAX_WAIT_ROUNDS = 20


class TrellixAuthError(RuntimeError):
    pass


def _cache():
    return caches["default"]


def _tenant_key(config):
    return config.get("tenant_id") or config.get("client_id") or "default"


def _scopes(config):
    """Read scopes always; action scopes only when containment is enabled.

    While containment is off ASP does not even ask for the privilege.
    """
    scopes = list(config.get("read_scopes") or [])
    if config.get("allow_containment"):
        scopes.extend(config.get("action_scopes") or [])
    return " ".join(dict.fromkeys(scope for scope in scopes if scope))


def _request_token(config):
    token_url = (config.get("iam_token_url") or "").strip()
    if not token_url:
        raise TrellixAuthError("Trellix IAM token URL is not configured.")
    if not config.get("client_id") or not config.get("client_secret"):
        raise TrellixAuthError("Trellix client credentials are not configured.")

    if not token_url.rstrip("/").endswith(TOKEN_PATH.rstrip("/")):
        logger.debug("Trellix IAM token URL does not match the documented path %s", TOKEN_PATH)

    data = {"grant_type": "client_credentials"}
    scope = _scopes(config)
    if scope:
        data["scope"] = scope

    try:
        with httpx.Client(timeout=config.get("timeout_seconds", 60), trust_env=False) as client:
            response = client.post(
                token_url,
                data=data,
                auth=(config["client_id"], config["client_secret"]),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.HTTPError as exc:
        raise TrellixAuthError(f"Trellix IAM request failed: {type(exc).__name__}") from exc

    if not response.is_success:
        raise TrellixAuthError(f"Trellix IAM returned HTTP {response.status_code}: {response.text[:200]}")

    try:
        body = response.json()
    except ValueError as exc:
        raise TrellixAuthError("Trellix IAM returned a non-JSON response.") from exc

    token = body.get("access_token")
    if not token:
        raise TrellixAuthError("Trellix IAM response contained no access_token.")

    granted = str(body.get("scope") or "")
    missing = [item for item in (scope or "").split() if item and item not in granted.split()]
    if missing:
        # IAM issues a token with fewer scopes rather than failing, so an
        # endpoint later returns 403 for a reason that has nothing to do with
        # the endpoint. Surface it at the point it actually happens.
        logger.warning(
            "Trellix IAM granted fewer scopes than requested. Missing: %s. Granted: %s",
            " ".join(missing),
            granted,
        )

    expires_in = int(body.get("expires_in") or 3600)
    return token, expires_in


def token_claims(config):
    """Decode the IAM token payload for diagnostics: tenant id and granted scopes."""
    import base64
    import json

    token = get_access_token(config)
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        logger.warning("Could not decode the Trellix IAM token payload", exc_info=True)
        return {}


def _store(tenant, token, expires_in):
    ttl = max(30, expires_in - REFRESH_MARGIN_SECONDS)
    _cache().set(TOKEN_CACHE_KEY.format(tenant=tenant), token, ttl)


def get_access_token(config, *, force_refresh=False):
    tenant = _tenant_key(config)
    cache = _cache()
    cache_key = TOKEN_CACHE_KEY.format(tenant=tenant)

    if not force_refresh:
        cached = cache.get(cache_key)
        if cached:
            return cached

    lock_key = LOCK_CACHE_KEY.format(tenant=tenant)
    if cache.add(lock_key, "1", LOCK_TTL_SECONDS):
        try:
            token, expires_in = _request_token(config)
            _store(tenant, token, expires_in)
            return token
        finally:
            cache.delete(lock_key)

    # Another process is refreshing; wait briefly for it to publish the token.
    for _ in range(LOCK_MAX_WAIT_ROUNDS):
        time.sleep(LOCK_WAIT_SECONDS)
        cached = cache.get(cache_key)
        if cached:
            return cached

    token, expires_in = _request_token(config)
    _store(tenant, token, expires_in)
    return token


def invalidate_token(config):
    _cache().delete(TOKEN_CACHE_KEY.format(tenant=_tenant_key(config)))
