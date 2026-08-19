import uuid

from django.core.validators import RegexValidator
from django.db import models


class LLMProviderConfig(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    base_url = models.URLField(max_length=500)
    model = models.CharField(max_length=200)
    fallback_models = models.JSONField(default=list, blank=True, help_text="Các model dự phòng thử lần lượt khi model chính lỗi/hết quota (fallback models tried in order when the primary fails)")
    api_key = models.TextField(blank=True, default="")
    proxy = models.CharField(max_length=500, blank=True, default="")
    tags = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=100)
    supports_json_mode = models.BooleanField(default=False)
    supports_tool_calling = models.BooleanField(default=False)
    context_window_tokens = models.PositiveIntegerField(default=32768)
    max_output_tokens = models.PositiveIntegerField(default=4096)
    request_timeout_seconds = models.PositiveIntegerField(default=120)
    max_retries = models.PositiveSmallIntegerField(default=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_llm_provider_configs"
        ordering = ["priority", "name", "created_at"]

    def __str__(self):
        return self.name


class ThreatIntelAlienVaultOTXConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    api_key = models.TextField(blank=True, default="")
    base_url = models.URLField(max_length=500, default="https://otx.alienvault.com/api/v1")
    proxy = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_ti_alienvault_otx_config"

    def __str__(self):
        return "AlienVault OTX"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class ThreatIntelOpenCTIConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    url = models.URLField(max_length=500, default="http://localhost:8080")
    token = models.TextField(blank=True, default="")
    ssl_verify = models.BooleanField(default=False)
    proxy = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_ti_opencti_config"

    def __str__(self):
        return "OpenCTI"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class ThreatIntelVirusTotalConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    api_keys = models.JSONField(default=list, blank=True, help_text="Danh sách API key, xoay vòng theo từng request (list of API keys rotated per request)")
    base_url = models.URLField(max_length=500, default="https://www.virustotal.com/api/v3")
    proxy = models.CharField(max_length=500, blank=True, default="")
    timeout_seconds = models.PositiveIntegerField(default=20)
    requests_per_minute_per_key = models.PositiveIntegerField(default=4, help_text="Trần request/phút cho mỗi key (per-key request ceiling, VT free tier = 4)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_ti_virustotal_config"

    def __str__(self):
        return "VirusTotal"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class SiemSplunkConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    host = models.CharField(max_length=255, blank=True, default="")
    port = models.PositiveIntegerField(default=8089)
    username = models.CharField(max_length=255, blank=True, default="")
    password = models.TextField(blank=True, default="")
    scheme = models.CharField(max_length=10, default="https")
    verify = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_siem_splunk_config"

    def __str__(self):
        return "Splunk"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class SiemElkConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    host = models.URLField(max_length=500, blank=True, default="")
    api_key = models.TextField(blank=True, default="")
    verify_certs = models.BooleanField(default=False)
    process_alert_from_index_enabled = models.BooleanField(default=False)
    action_index = models.CharField(max_length=255, blank=True, default="siem-alert")
    action_poll_interval_seconds = models.PositiveIntegerField(default=60)
    action_size = models.PositiveIntegerField(default=1000)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_siem_elk_config"

    def __str__(self):
        return "ELK"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class SiemQRadarConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    base_url = models.URLField(max_length=500, blank=True, default="")
    api_token = models.TextField(blank=True, default="")
    api_version = models.CharField(max_length=20, blank=True, default="22.0")
    verify_ssl = models.BooleanField(default=True)
    ca_bundle_path = models.CharField(max_length=500, blank=True, default="")
    search_timeout_seconds = models.PositiveIntegerField(default=300)
    metadata_timeout_seconds = models.PositiveIntegerField(default=30)
    max_rows = models.PositiveIntegerField(default=1000)
    default_window_minutes = models.PositiveIntegerField(default=60)
    max_window_hours = models.PositiveIntegerField(default=24)
    max_concurrent_searches = models.PositiveSmallIntegerField(default=2)
    allow_write = models.BooleanField(default=False)
    poll_enabled = models.BooleanField(default=False)
    poll_interval_seconds = models.PositiveIntegerField(default=60)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_siem_qradar_config"

    def __str__(self):
        return "QRadar"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class EdrTrellixConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    iam_token_url = models.URLField(max_length=500, blank=True, default="")
    api_base_url = models.URLField(max_length=500, blank=True, default="")
    client_id = models.CharField(max_length=255, blank=True, default="")
    client_secret = models.TextField(blank=True, default="")
    tenant_id = models.CharField(max_length=255, blank=True, default="")
    read_scopes = models.JSONField(default=list, blank=True)
    action_scopes = models.JSONField(default=list, blank=True)
    timeout_seconds = models.PositiveIntegerField(default=60)
    rate_limit_per_minute = models.PositiveIntegerField(default=120)
    max_rows = models.PositiveIntegerField(default=1000)
    max_window_hours = models.PositiveIntegerField(default=24)
    threat_severities = models.JSONField(
        default=list,
        blank=True,
        help_text="Trellix severity codes to ingest. Empty means s3, s4 and s5.",
    )
    threat_score_min = models.PositiveIntegerField(default=30)
    ingest_lookback_days = models.PositiveIntegerField(default=7)
    allow_containment = models.BooleanField(default=False)
    poll_enabled = models.BooleanField(default=False)
    poll_interval_seconds = models.PositiveIntegerField(default=60)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_edr_trellix_config"

    def __str__(self):
        return "Trellix EDR"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class TelegramNotificationConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    bot_token = models.TextField(blank=True, default="")
    asp_base_url = models.URLField(max_length=500, blank=True, default="")
    retry_limit = models.PositiveSmallIntegerField(default=3)
    rate_limit_per_minute = models.PositiveIntegerField(default=20)
    aggregation_window_seconds = models.PositiveIntegerField(default=300)
    aggregation_threshold = models.PositiveIntegerField(default=3)
    quiet_hours_start = models.PositiveSmallIntegerField(null=True, blank=True)
    quiet_hours_end = models.PositiveSmallIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_telegram_notification_config"

    def __str__(self):
        return "Telegram"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class McpServerConfig(models.Model):
    class Transport(models.TextChoices):
        HTTP = "http", "Streamable HTTP"
        STDIO = "stdio", "stdio"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    transport = models.CharField(max_length=10, choices=Transport, default=Transport.HTTP)
    url_or_command = models.CharField(max_length=1000, blank=True, default="")
    auth_header = models.CharField(max_length=100, blank=True, default="")
    token = models.TextField(blank=True, default="")
    timeout_seconds = models.PositiveIntegerField(default=30)
    allowed_tools = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_mcp_servers"
        ordering = ["name"]

    def __str__(self):
        return self.name


class IocVerificationConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=True)
    internal_sources_only = models.BooleanField(
        default=False,
        help_text="Skip web MCP lookups entirely and rely on OTX/OpenCTI.",
    )
    reputable_domains = models.JSONField(default=list, blank=True)
    internal_networks = models.JSONField(default=list, blank=True)
    internal_domains = models.JSONField(default=list, blank=True)
    max_web_results = models.PositiveIntegerField(default=8)
    rate_limit_per_minute = models.PositiveIntegerField(default=30)
    ttl_ip_hours = models.PositiveIntegerField(default=24)
    ttl_domain_hours = models.PositiveIntegerField(default=72)
    ttl_url_hours = models.PositiveIntegerField(default=72)
    ttl_hash_hours = models.PositiveIntegerField(default=720)
    ttl_email_hours = models.PositiveIntegerField(default=168)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_ioc_verification_config"

    def __str__(self):
        return "IOC Verification"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class PlaybookAutomationConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    max_auto_runs_per_case = models.PositiveIntegerField(default=3, help_text="Trần số playbook tự chạy cho một case (ceiling of auto-started playbooks per case)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_playbook_automation_config"

    def __str__(self):
        return "Playbook Automation"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class PlaybookAutomationRule(models.Model):
    """Maps incoming cases to the SOC playbook that should run automatically.

    Keyword matching is deterministic and case-insensitive over the case title
    plus alert rule names; an empty keyword list matches every case (catch-all
    rules should carry the lowest priority).
    """

    class MinSeverity(models.TextChoices):
        ANY = "", "Any"
        LOW = "Low"
        MEDIUM = "Medium"
        HIGH = "High"
        CRITICAL = "Critical"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    enabled = models.BooleanField(default=True)
    keywords = models.JSONField(default=list, blank=True, help_text="Chuỗi con khớp không phân biệt hoa thường trên title + rule name (case-insensitive substrings)")
    min_severity = models.CharField(max_length=20, choices=MinSeverity, blank=True, default="")
    playbook_name = models.CharField(max_length=255, help_text="NAME của playbook sẽ chạy (playbook NAME to launch)")
    priority = models.PositiveIntegerField(default=100)
    fallback = models.BooleanField(default=False, help_text="Chỉ chạy khi chưa có playbook nào khác trên case (runs only when no other playbook exists on the case)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_playbook_automation_rules"
        ordering = ["priority", "name"]

    def __str__(self):
        return self.name


class BrandingConfig(models.Model):
    """Product identity, configurable per deployment.

    The release template ships neutral defaults; a customer's identity is
    loaded at deployment time through a fixture, never committed here.
    """

    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    product_name = models.CharField(max_length=120, default="SOC Platform")
    product_short_name = models.CharField(max_length=40, default="SOC")
    logo_full = models.FileField(upload_to="branding/", blank=True, null=True)
    logo_compact = models.FileField(upload_to="branding/", blank=True, null=True)
    logo_mark = models.FileField(upload_to="branding/", blank=True, null=True)
    logo_dark = models.FileField(
        upload_to="branding/",
        blank=True,
        null=True,
        help_text="Light-text variant for dark surfaces such as the sidebar.",
    )
    favicon = models.FileField(upload_to="branding/", blank=True, null=True)
    login_background = models.FileField(upload_to="branding/", blank=True, null=True)
    primary_color = models.CharField(max_length=9, default="#1677ff")
    accent_color = models.CharField(max_length=9, default="#1677ff")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_branding_config"

    def __str__(self):
        return self.product_name

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class LdapConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    enabled = models.BooleanField(default=False)
    server_uri = models.CharField(max_length=500, blank=True, default="")
    domain = models.CharField(max_length=255, blank=True, default="")
    bind_dn = models.CharField(max_length=500, blank=True, default="")
    bind_password = models.TextField(blank=True, default="")
    user_search_base_dn = models.CharField(max_length=500, blank=True, default="")
    user_login_attr = models.CharField(max_length=100, default="uid")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_ldap_config"

    def __str__(self):
        return "LDAP"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class RuntimeConfig(models.Model):
    singleton_id = models.PositiveSmallIntegerField(default=1, unique=True, editable=False)
    prompt_language = models.CharField(max_length=10, default="en")
    stream_maxlen = models.PositiveIntegerField(default=10000)
    dashboard_refresh_interval_seconds = models.PositiveIntegerField(default=300)
    anonymization_enabled = models.BooleanField(default=False)
    anonymization_fields = models.JSONField(default=list, blank=True)
    correlation_window_hours = models.PositiveIntegerField(
        default=24,
        help_text=(
            "An alert joins an open Case with the same correlation key when that Case "
            "was active within this many hours."
        ),
    )
    asset_naming_rules = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "Ordered fallback rules mapping a hostname pattern to a device type, "
            'e.g. [{"pattern": "^SRV-", "device_type": "server", "owner": "Infra"}].'
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_runtime_config"

    def __str__(self):
        return "Runtime"

    @classmethod
    def get_current(cls):
        instance, _ = cls.objects.get_or_create(singleton_id=1)
        return instance


class CustomVariable(models.Model):
    class ValueType(models.TextChoices):
        STRING = "string", "String"
        INTEGER = "integer", "Integer"
        FLOAT = "float", "Float"
        BOOLEAN = "boolean", "Boolean"
        LIST = "list", "List"
        DICTIONARY = "dictionary", "Dictionary"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(
        max_length=128,
        unique=True,
        validators=[
            RegexValidator(
                regex=r"^[A-Z][A-Z0-9_]{0,127}$",
                message="Key must start with an uppercase letter and contain only uppercase letters, numbers, and underscores.",
            )
        ],
    )
    value_type = models.CharField(max_length=16, choices=ValueType.choices)
    value = models.JSONField()
    is_secret = models.BooleanField(default=False)
    description = models.TextField(blank=True, default="")
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "setting_custom_variables"
        ordering = ["key"]

    def __str__(self):
        return self.key
