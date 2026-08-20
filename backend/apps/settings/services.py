import logging

import httpx
from pycti import OpenCTIApiClient

logger = logging.getLogger(__name__)


def _config_test_client_timeout():
    from django.conf import settings

    return max(1.0, settings.CONFIG_TEST_TIMEOUT_SECONDS - 2)


def _chat_completions_url(base_url):
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"


def _redact(value, secrets):
    redacted = str(value)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def test_llm_provider(config):
    api_key = (config.get("api_key") or "").strip()
    base_url = (config.get("base_url") or "").strip()
    model = (config.get("model") or "").strip()
    proxy = (config.get("proxy") or "").strip()

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        "temperature": 0,
        "max_tokens": 8,
        "stream": False,
    }
    client_kwargs = {"trust_env": False, "timeout": _config_test_client_timeout()}
    if proxy:
        client_kwargs["proxy"] = proxy
    try:
        with httpx.Client(**client_kwargs) as client:
            response = client.post(_chat_completions_url(base_url), headers=headers, json=payload)
        if response.is_success:
            try:
                data = response.json()
            except ValueError:
                return {
                    "success": False,
                    "detail": (
                        "LLM provider returned HTTP "
                        f"{response.status_code} with non-JSON content type "
                        f"'{response.headers.get('content-type', 'unknown')}'. "
                        "The endpoint must answer a non-streaming Chat Completions request with JSON."
                    ),
                    "response_preview": _redact(response.text, [api_key])[:500],
                }
            content = ""
            choices = data.get("choices") if isinstance(data, dict) else None
            if choices and isinstance(choices, list):
                message = (choices[0] or {}).get("message") or {}
                content = str(message.get("content") or "")
            return {
                "success": True,
                "detail": "LLM provider responded successfully.",
                "response_preview": content[:200],
            }

        return {
            "success": False,
            "detail": f"LLM provider test failed with HTTP {response.status_code}.",
            "response_preview": _redact(response.text, [api_key])[:500],
        }
    except httpx.HTTPError as exc:
        logger.exception("LLM provider test failed")
        return {
            "success": False,
            "detail": f"LLM provider test failed due to a connection error: {type(exc).__name__}.",
            "response_preview": "",
        }
    except Exception as exc:
        logger.exception("LLM provider test failed")
        return {
            "success": False,
            "detail": f"LLM provider test failed while reading the response: {type(exc).__name__}.",
            "response_preview": "",
        }


def test_alienvault_otx_config(config):
    api_key = (config.get("api_key") or "").strip()
    base_url = (config.get("base_url") or "").strip().rstrip("/")
    proxy = (config.get("proxy") or "").strip()

    if not api_key:
        return {
            "success": False,
            "detail": "AlienVault OTX API key is not configured.",
            "response_preview": "",
        }

    headers = {
        "accept": "application/json",
        "X-OTX-API-KEY": api_key,
    }
    client_kwargs = {"trust_env": False}
    if proxy:
        client_kwargs["proxy"] = proxy
    try:
        with httpx.Client(**client_kwargs) as client:
            response = client.get(f"{base_url}/user/me", headers=headers)
        if response.is_success:
            return {
                "success": True,
                "detail": "AlienVault OTX authentication succeeded.",
                "response_preview": response.text[:500],
            }
        return {
            "success": False,
            "detail": f"AlienVault OTX test failed with HTTP {response.status_code}.",
            "response_preview": _redact(response.text, [api_key])[:500],
        }
    except Exception:
        logger.exception("AlienVault OTX configuration test failed")
        return {
            "success": False,
            "detail": "AlienVault OTX test failed due to a connection error.",
            "response_preview": "",
        }


def test_virustotal_config(config):
    api_keys = [str(key).strip() for key in (config.get("api_keys") or []) if str(key).strip()]
    base_url = (config.get("base_url") or "").strip().rstrip("/")
    proxy = (config.get("proxy") or "").strip()
    timeout = config.get("timeout_seconds") or 20

    if not api_keys:
        return {
            "success": False,
            "detail": "VirusTotal API keys are not configured.",
            "response_preview": "",
        }

    client_kwargs = {"trust_env": False, "timeout": timeout}
    if proxy:
        client_kwargs["proxy"] = proxy

    failures = []
    try:
        with httpx.Client(**client_kwargs) as client:
            for index, api_key in enumerate(api_keys):
                headers = {"accept": "application/json", "x-apikey": api_key}
                response = client.get(f"{base_url}/ip_addresses/8.8.8.8", headers=headers)
                if response.is_success:
                    detail = f"VirusTotal authentication succeeded with key #{index + 1} of {len(api_keys)}."
                    if failures:
                        detail += f" Failed keys: {', '.join(failures)}."
                    return {
                        "success": True,
                        "detail": detail,
                        "response_preview": _redact(response.text, api_keys)[:500],
                    }
                failures.append(f"#{index + 1} (HTTP {response.status_code})")
        return {
            "success": False,
            "detail": f"All VirusTotal keys failed: {', '.join(failures)}.",
            "response_preview": "",
        }
    except Exception:
        logger.exception("VirusTotal configuration test failed")
        return {
            "success": False,
            "detail": "VirusTotal test failed due to a connection error.",
            "response_preview": "",
        }


def test_opencti_config(config):
    token = (config.get("token") or "").strip()
    url = (config.get("url") or "").strip().rstrip("/")
    proxy = (config.get("proxy") or "").strip()
    ssl_verify = bool(config.get("ssl_verify"))

    if not url:
        return {
            "success": False,
            "detail": "OpenCTI URL is not configured.",
            "response_preview": "",
        }
    if not token:
        return {
            "success": False,
            "detail": "OpenCTI API token is not configured.",
            "response_preview": "",
        }

    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        client = OpenCTIApiClient(
            url,
            token,
            log_level="error",
            ssl_verify=ssl_verify,
            proxies=proxies,
            perform_health_check=True,
            provider="AspOpenCTITest/1.0",
        )
        indicators = client.indicator.list(first=1)
        observables = client.stix_cyber_observable.list(first=1)
        preview = {
            "indicator_sample_count": len(indicators or []),
            "observable_sample_count": len(observables or []),
        }
        if indicators:
            preview["indicator_sample"] = {
                "id": indicators[0].get("id"),
                "name": indicators[0].get("name"),
                "entity_type": indicators[0].get("entity_type"),
            }
        if observables:
            preview["observable_sample"] = {
                "id": observables[0].get("id"),
                "value": observables[0].get("observable_value") or observables[0].get("value"),
                "entity_type": observables[0].get("entity_type"),
            }
        return {
            "success": True,
            "detail": "OpenCTI responded successfully.",
            "response_preview": str(preview)[:500],
        }
    except Exception:
        logger.exception("OpenCTI configuration test failed")
        return {
            "success": False,
            "detail": "OpenCTI test failed due to a connection error.",
            "response_preview": "",
        }


def test_splunk_config(config):
    import splunklib.client

    password = config.get("password") or ""
    try:
        service = splunklib.client.connect(
            host=config.get("host"),
            port=config.get("port"),
            username=config.get("username"),
            password=password,
            scheme=config.get("scheme") or "https",
            verify=bool(config.get("verify")),
        )
        info = service.info
        return {
            "success": True,
            "detail": "Splunk responded successfully.",
            "response_preview": str({key: info.get(key) for key in ("serverName", "version", "guid")})[:500],
        }
    except Exception:
        logger.exception("Splunk configuration test failed")
        return {
            "success": False,
            "detail": "Splunk test failed due to a connection error.",
            "response_preview": "",
        }


def test_elk_config(config):
    from elasticsearch import Elasticsearch

    api_key = config.get("api_key") or ""
    try:
        client = Elasticsearch(
            (config.get("host") or "").rstrip("/"),
            api_key=api_key,
            verify_certs=bool(config.get("verify_certs")),
        )
        info = client.info()
        return {
            "success": True,
            "detail": "ELK responded successfully.",
            "response_preview": str({
                "cluster_name": info.get("cluster_name"),
                "version": (info.get("version") or {}).get("number") if isinstance(info.get("version"), dict) else "",
            })[:500],
        }
    except Exception:
        logger.exception("ELK configuration test failed")
        return {
            "success": False,
            "detail": "ELK test failed due to a connection error.",
            "response_preview": "",
        }


def test_qradar_config(config):
    base_url = (config.get("base_url") or "").strip().rstrip("/")
    api_token = (config.get("api_token") or "").strip()

    if not base_url:
        return {"success": False, "detail": "QRadar base URL is not configured.", "response_preview": ""}
    if not api_token:
        return {"success": False, "detail": "QRadar API token is not configured.", "response_preview": ""}

    verify = config.get("ca_bundle_path") or bool(config.get("verify_ssl", True))
    headers = {
        "SEC": api_token,
        "Version": config.get("api_version") or "22.0",
        "Accept": "application/json",
    }
    try:
        with httpx.Client(verify=verify, timeout=_config_test_client_timeout(), trust_env=False) as client:
            response = client.get(f"{base_url}/api/system/about", headers=headers)
            if response.status_code == 403:
                # /api/system/about needs the ADMIN capability, which a
                # deliberately read-only service account does not have. Fall back
                # to the capability ASP actually depends on, so a correct
                # read-only token is not reported as rejected.
                response = client.get(
                    f"{base_url}/api/siem/offenses",
                    headers={**headers, "Range": "items=0-0"},
                )
        if response.is_success:
            try:
                body = response.json()
            except ValueError:
                return {
                    "success": False,
                    "detail": "QRadar returned a non-JSON response. Check the base URL path.",
                    "response_preview": _redact(response.text, [api_token])[:500],
                }
            # The fallback probe returns a list of offences rather than the
            # system description, so the release name is not always available.
            release = body.get("release_name", "unknown") if isinstance(body, dict) else ""
            detail = (
                f"QRadar responded successfully (release {release})."
                if release
                else "QRadar responded successfully. The token can read offences but is not an admin token."
            )
            return {
                "success": True,
                "detail": detail,
                "response_preview": _redact(str(body), [api_token])[:200],
            }
        if response.status_code in {401, 403}:
            return {
                "success": False,
                "detail": "QRadar rejected the API token. Verify the token and its read permissions.",
                "response_preview": _redact(response.text, [api_token])[:500],
            }
        return {
            "success": False,
            "detail": f"QRadar test failed with HTTP {response.status_code}.",
            "response_preview": _redact(response.text, [api_token])[:500],
        }
    except httpx.HTTPError as exc:
        logger.exception("QRadar configuration test failed")
        return {
            "success": False,
            "detail": f"QRadar test failed due to a connection error: {type(exc).__name__}.",
            "response_preview": "",
        }


def test_trellix_config(config):
    token_url = (config.get("iam_token_url") or "").strip()
    api_base_url = (config.get("api_base_url") or "").strip().rstrip("/")
    client_id = (config.get("client_id") or "").strip()
    client_secret = (config.get("client_secret") or "").strip()

    if not token_url or not api_base_url:
        return {"success": False, "detail": "Trellix IAM token URL and API base URL are required.", "response_preview": ""}
    if not client_id or not client_secret:
        return {"success": False, "detail": "Trellix client credentials are not configured.", "response_preview": ""}

    scopes = list(config.get("read_scopes") or [])
    if config.get("allow_containment"):
        scopes.extend(config.get("action_scopes") or [])
    data = {"grant_type": "client_credentials"}
    scope = " ".join(dict.fromkeys(item for item in scopes if item))
    if scope:
        data["scope"] = scope

    try:
        with httpx.Client(timeout=_config_test_client_timeout(), trust_env=False) as client:
            response = client.post(
                token_url,
                data=data,
                auth=(client_id, client_secret),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
    except httpx.HTTPError as exc:
        logger.exception("Trellix configuration test failed")
        return {
            "success": False,
            "detail": f"Trellix IAM test failed due to a connection error: {type(exc).__name__}.",
            "response_preview": "",
        }

    if not response.is_success:
        return {
            "success": False,
            "detail": f"Trellix IAM rejected the credentials with HTTP {response.status_code}.",
            "response_preview": _redact(response.text, [client_secret])[:500],
        }

    try:
        body = response.json()
    except ValueError:
        return {
            "success": False,
            "detail": "Trellix IAM returned a non-JSON response.",
            "response_preview": _redact(response.text, [client_secret])[:500],
        }

    token = body.get("access_token")
    if not token:
        return {
            "success": False,
            "detail": "Trellix IAM response contained no access_token.",
            "response_preview": _redact(str(body), [client_secret])[:200],
        }

    # The IAM response echoes the requested scopes; the token itself carries what
    # was actually granted. Compare against the token or a denied scope looks fine
    # here and fails later as an unexplained 403.
    claims = _decode_jwt_payload(body.get("access_token"))
    granted = str(claims.get("scope") or body.get("scope") or scope)
    missing = [item for item in scope.split() if item and item not in granted.split()]

    detail = f"Trellix IAM issued a token (expires in {body.get('expires_in', 'unknown')}s)."
    if missing:
        detail += f" Requested but NOT granted: {' '.join(missing)}."

    preview = f"granted scopes: {granted}"
    if claims.get("tenant_id"):
        preview += f" | tenant_id: {claims['tenant_id']}"

    return {
        "success": True,
        "detail": detail,
        "response_preview": preview[:300],
    }


def _decode_jwt_payload(token):
    import base64
    import json

    parts = str(token or "").split(".")
    if len(parts) != 3:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}
