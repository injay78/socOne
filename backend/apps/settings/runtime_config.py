from functools import lru_cache


@lru_cache(maxsize=1)
def get_llm_configs():
    from .models import LLMProviderConfig

    def _models(provider):
        candidates = [provider.model] + [str(m).strip() for m in (provider.fallback_models or [])]
        seen = []
        for candidate in candidates:
            if candidate and candidate not in seen:
                seen.append(candidate)
        return seen

    return [
        {
            "name": provider.name,
            "api_key": provider.api_key,
            "base_url": provider.base_url.rstrip("/"),
            "model": provider.model,
            "models": _models(provider),
            "proxy": provider.proxy,
            "tags": provider.tags or [],
            "supports_json_mode": provider.supports_json_mode,
            "supports_tool_calling": provider.supports_tool_calling,
            "context_window_tokens": provider.context_window_tokens,
            "max_output_tokens": provider.max_output_tokens,
            "request_timeout_seconds": provider.request_timeout_seconds,
            "max_retries": provider.max_retries,
        }
        for provider in LLMProviderConfig.objects.filter(enabled=True).order_by("priority", "name", "created_at")
    ]


@lru_cache(maxsize=1)
def get_otx_config():
    from .models import ThreatIntelAlienVaultOTXConfig

    config = ThreatIntelAlienVaultOTXConfig.get_current()
    return {
        "enabled": config.enabled,
        "api_key": config.api_key,
        "base_url": config.base_url.rstrip("/"),
        "proxy": config.proxy,
    }


@lru_cache(maxsize=1)
def get_opencti_config():
    from .models import ThreatIntelOpenCTIConfig

    config = ThreatIntelOpenCTIConfig.get_current()
    return {
        "enabled": config.enabled,
        "url": config.url.rstrip("/"),
        "token": config.token,
        "ssl_verify": config.ssl_verify,
        "proxy": config.proxy,
    }


@lru_cache(maxsize=1)
def get_virustotal_config():
    from .models import ThreatIntelVirusTotalConfig

    config = ThreatIntelVirusTotalConfig.get_current()
    return {
        "enabled": config.enabled,
        "api_keys": [key for key in (config.api_keys or []) if str(key).strip()],
        "base_url": config.base_url.rstrip("/"),
        "proxy": config.proxy,
        "timeout_seconds": config.timeout_seconds,
        "requests_per_minute_per_key": config.requests_per_minute_per_key,
    }


@lru_cache(maxsize=1)
def get_playbook_automation_config():
    from .models import PlaybookAutomationConfig, PlaybookAutomationRule

    config = PlaybookAutomationConfig.get_current()
    return {
        "enabled": config.enabled,
        "max_auto_runs_per_case": config.max_auto_runs_per_case,
        "rules": [
            {
                "name": rule.name,
                "keywords": [str(k).strip().lower() for k in (rule.keywords or []) if str(k).strip()],
                "min_severity": rule.min_severity,
                "playbook_name": rule.playbook_name,
                "priority": rule.priority,
                "fallback": rule.fallback,
            }
            for rule in PlaybookAutomationRule.objects.filter(enabled=True).order_by("priority", "name")
        ],
    }


@lru_cache(maxsize=1)
def get_splunk_config():
    from .models import SiemSplunkConfig

    config = SiemSplunkConfig.get_current()
    return {
        "host": config.host,
        "port": config.port,
        "username": config.username,
        "password": config.password,
        "scheme": config.scheme,
        "verify": config.verify,
    }


@lru_cache(maxsize=1)
def get_elk_config():
    from .models import SiemElkConfig

    config = SiemElkConfig.get_current()
    return {
        "host": config.host.rstrip("/"),
        "api_key": config.api_key,
        "verify_certs": config.verify_certs,
        "process_alert_from_index_enabled": config.process_alert_from_index_enabled,
        "action_index": config.action_index,
        "action_poll_interval_seconds": config.action_poll_interval_seconds,
        "action_size": config.action_size,
    }


@lru_cache(maxsize=1)
def get_ldap_config():
    from .models import LdapConfig

    config = LdapConfig.get_current()
    return {
        "enabled": config.enabled,
        "server_uri": config.server_uri,
        "domain": config.domain,
        "bind_dn": config.bind_dn,
        "bind_password": config.bind_password,
        "user_search_base_dn": config.user_search_base_dn,
        "user_login_attr": config.user_login_attr,
    }


@lru_cache(maxsize=1)
def get_qradar_config():
    from .models import SiemQRadarConfig

    config = SiemQRadarConfig.get_current()
    return {
        "enabled": config.enabled,
        "base_url": config.base_url.rstrip("/"),
        "api_token": config.api_token,
        "api_version": config.api_version,
        "verify_ssl": config.verify_ssl,
        "ca_bundle_path": config.ca_bundle_path,
        "search_timeout_seconds": config.search_timeout_seconds,
        "metadata_timeout_seconds": config.metadata_timeout_seconds,
        "max_rows": config.max_rows,
        "default_window_minutes": config.default_window_minutes,
        "max_window_hours": config.max_window_hours,
        "max_concurrent_searches": config.max_concurrent_searches,
        "allow_write": config.allow_write,
        "poll_enabled": config.poll_enabled,
        "poll_interval_seconds": config.poll_interval_seconds,
    }


@lru_cache(maxsize=1)
def get_trellix_config():
    from .models import EdrTrellixConfig

    config = EdrTrellixConfig.get_current()
    return {
        "enabled": config.enabled,
        "iam_token_url": config.iam_token_url,
        "api_base_url": config.api_base_url.rstrip("/"),
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "tenant_id": config.tenant_id,
        "read_scopes": config.read_scopes or [],
        "action_scopes": config.action_scopes or [],
        "timeout_seconds": config.timeout_seconds,
        "rate_limit_per_minute": config.rate_limit_per_minute,
        "max_rows": config.max_rows,
        "max_window_hours": config.max_window_hours,
        "threat_severities": config.threat_severities or ["s3", "s4", "s5"],
        "threat_score_min": config.threat_score_min,
        "ingest_lookback_days": config.ingest_lookback_days,
        "allow_containment": config.allow_containment,
        "poll_enabled": config.poll_enabled,
        "poll_interval_seconds": config.poll_interval_seconds,
    }


@lru_cache(maxsize=1)
def get_mcp_configs():
    from .models import McpServerConfig

    return [
        {
            "name": server.name,
            "transport": server.transport,
            "url_or_command": server.url_or_command,
            "auth_header": server.auth_header,
            "token": server.token,
            "timeout_seconds": server.timeout_seconds,
            "allowed_tools": server.allowed_tools or [],
            "enabled": server.enabled,
        }
        for server in McpServerConfig.objects.all().order_by("name")
    ]


@lru_cache(maxsize=1)
def get_ioc_config():
    from .models import IocVerificationConfig

    config = IocVerificationConfig.get_current()
    return {
        "enabled": config.enabled,
        "internal_sources_only": config.internal_sources_only,
        "reputable_domains": config.reputable_domains or [],
        "internal_networks": config.internal_networks or [],
        "internal_domains": config.internal_domains or [],
        "max_web_results": config.max_web_results,
        "rate_limit_per_minute": config.rate_limit_per_minute,
        "ttl_ip_hours": config.ttl_ip_hours,
        "ttl_domain_hours": config.ttl_domain_hours,
        "ttl_url_hours": config.ttl_url_hours,
        "ttl_hash_hours": config.ttl_hash_hours,
        "ttl_email_hours": config.ttl_email_hours,
    }


@lru_cache(maxsize=1)
def get_telegram_config():
    from .models import TelegramNotificationConfig

    config = TelegramNotificationConfig.get_current()
    return {
        "enabled": config.enabled,
        "bot_token": config.bot_token,
        "asp_base_url": config.asp_base_url,
        "retry_limit": config.retry_limit,
        "rate_limit_per_minute": config.rate_limit_per_minute,
        "aggregation_window_seconds": config.aggregation_window_seconds,
        "aggregation_threshold": config.aggregation_threshold,
        "quiet_hours_start": config.quiet_hours_start,
        "quiet_hours_end": config.quiet_hours_end,
    }


@lru_cache(maxsize=1)
def get_branding_config():
    from .models import BrandingConfig

    config = BrandingConfig.get_current()

    def _url(field):
        try:
            return field.url if field else ""
        except Exception:
            return ""

    return {
        "product_name": config.product_name,
        "product_short_name": config.product_short_name,
        "logo_full": _url(config.logo_full),
        "logo_compact": _url(config.logo_compact),
        "logo_mark": _url(config.logo_mark),
        "logo_dark": _url(config.logo_dark),
        "favicon": _url(config.favicon),
        "login_background": _url(config.login_background),
        "primary_color": config.primary_color,
        "accent_color": config.accent_color,
    }


@lru_cache(maxsize=1)
def get_runtime_config():
    from .models import RuntimeConfig

    config = RuntimeConfig.get_current()
    return {
        "prompt_language": config.prompt_language,
        "stream_maxlen": config.stream_maxlen,
        "dashboard_refresh_interval_seconds": config.dashboard_refresh_interval_seconds,
        "anonymization_enabled": config.anonymization_enabled,
        "anonymization_fields": config.anonymization_fields or [],
        "asset_naming_rules": config.asset_naming_rules or [],
        "correlation_window_hours": config.correlation_window_hours,
    }


def get_prompt_language():
    return get_runtime_config()["prompt_language"]


def get_correlation_window_hours():
    return get_runtime_config()["correlation_window_hours"]


def get_asset_naming_rules():
    return get_runtime_config()["asset_naming_rules"]


def get_anonymization_settings():
    config = get_runtime_config()
    return {
        "enabled": config["anonymization_enabled"],
        "fields": config["anonymization_fields"],
    }


def get_stream_maxlen():
    try:
        return get_runtime_config()["stream_maxlen"]
    except Exception as exc:
        if exc.__class__.__name__ == "DatabaseOperationForbidden":
            return 10000
        raise


def get_dashboard_refresh_interval_seconds():
    return get_runtime_config()["dashboard_refresh_interval_seconds"]


def invalidate(group=None):
    if group in {None, "llm"}:
        get_llm_configs.cache_clear()
    if group in {None, "threat_intel", "otx"}:
        get_otx_config.cache_clear()
    if group in {None, "threat_intel", "opencti"}:
        get_opencti_config.cache_clear()
    if group in {None, "threat_intel", "virustotal"}:
        get_virustotal_config.cache_clear()
    if group in {None, "playbook_automation"}:
        get_playbook_automation_config.cache_clear()
    if group in {None, "siem", "splunk"}:
        get_splunk_config.cache_clear()
    if group in {None, "siem", "elk"}:
        get_elk_config.cache_clear()
    if group in {None, "siem", "qradar"}:
        get_qradar_config.cache_clear()
    if group in {None, "edr", "trellix"}:
        get_trellix_config.cache_clear()
    if group in {None, "notifications", "telegram"}:
        get_telegram_config.cache_clear()
    if group in {None, "mcp"}:
        get_mcp_configs.cache_clear()
    if group in {None, "ioc"}:
        get_ioc_config.cache_clear()
    if group in {None, "branding"}:
        get_branding_config.cache_clear()
    if group in {None, "ldap"}:
        get_ldap_config.cache_clear()
    if group in {None, "runtime"}:
        get_runtime_config.cache_clear()
