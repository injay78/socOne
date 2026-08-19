from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.common.models import BaseModel


class AgenticJobStatus(models.TextChoices):
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCESS = "Success"
    FAILED = "Failed"


class CaseAnalysisJob(BaseModel):
    case = models.ForeignKey(
        "cases.Case",
        on_delete=models.CASCADE,
        related_name="agentic_analysis_jobs",
    )
    status = models.CharField(
        max_length=20,
        choices=AgenticJobStatus,
        default=AgenticJobStatus.PENDING,
        db_index=True,
    )
    trigger = models.CharField(max_length=100, blank=True, default="")
    scheduled_at = models.DateTimeField(default=timezone.now, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    queue_message_id = models.CharField(max_length=255, blank=True, default="")
    error = models.TextField(blank=True, default="")
    result_json = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "agentic_case_analysis_jobs"
        ordering = ["scheduled_at", "created_at"]

    def __str__(self):
        return f"{self.case.case_id or self.case_id} {self.status}"


class LlmCallRecord(BaseModel):
    prompt_id = models.CharField(max_length=200, blank=True, default="", db_index=True)
    prompt_version = models.CharField(max_length=50, blank=True, default="")
    prompt_hash = models.CharField(max_length=64, blank=True, default="")
    provider_name = models.CharField(max_length=100, blank=True, default="")
    model_name = models.CharField(max_length=200, blank=True, default="")
    attempts = models.PositiveSmallIntegerField(default=0)
    success = models.BooleanField(default=False, db_index=True)
    error = models.TextField(blank=True, default="")
    tokens_in = models.PositiveIntegerField(null=True, blank=True)
    tokens_out = models.PositiveIntegerField(null=True, blank=True)
    latency_ms = models.PositiveIntegerField(default=0)
    trimmed_tiers = models.JSONField(default=list, blank=True)
    raw_response = models.TextField(blank=True, default="")
    source_type = models.CharField(max_length=100, blank=True, default="")
    source_id = models.CharField(max_length=64, blank=True, default="")
    case = models.ForeignKey(
        "cases.Case",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="llm_call_records",
    )

    class Meta:
        db_table = "agentic_llm_call_records"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.prompt_id} {self.model_name} {'ok' if self.success else 'failed'}"


class TriageVerdict(models.TextChoices):
    TRUE_POSITIVE = "true_positive", "True Positive"
    FALSE_POSITIVE = "false_positive", "False Positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive", "Benign True Positive"
    NEEDS_MORE_INFO = "needs_more_info", "Needs More Info"


class FalsePositiveClass(models.TextChoices):
    SUPPRESSED = "suppressed", "Already suppressed"
    VERIFIED_LEGITIMATE = "verified_legitimate", "Verified legitimate activity"
    RULE_MISCONFIGURATION = "rule_misconfiguration", "Rule misconfiguration"
    OTHER = "other", "Other"


class SuppressionMatchType(models.TextChoices):
    RULE = "rule", "Rule name"
    ENTITY = "entity", "Artifact value"
    SUBNET = "subnet", "IP subnet"
    USER = "user", "Username"


class TriageSuppression(BaseModel):
    match_type = models.CharField(max_length=20, choices=SuppressionMatchType, db_index=True)
    pattern = models.CharField(max_length=500)
    reason = models.TextField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="triage_suppressions",
    )
    expires_at = models.DateTimeField(
        help_text="Mandatory. A suppression without an end date is not allowed.",
    )
    enabled = models.BooleanField(default=True, db_index=True)

    class Meta:
        db_table = "agentic_triage_suppressions"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.match_type}:{self.pattern}"

    @property
    def is_active(self):
        return self.enabled and self.expires_at > timezone.now()


class TriageResult(BaseModel):
    case = models.ForeignKey(
        "cases.Case",
        on_delete=models.CASCADE,
        related_name="triage_results",
    )
    verdict = models.CharField(max_length=30, choices=TriageVerdict, db_index=True)
    false_positive_class = models.CharField(
        max_length=30, choices=FalsePositiveClass, blank=True, default=""
    )
    severity_ai = models.CharField(max_length=20, blank=True, default="")
    impact_ai = models.CharField(max_length=20, blank=True, default="")
    priority_ai = models.CharField(max_length=20, blank=True, default="")
    confidence = models.FloatField(default=0.0)
    needs_human = models.BooleanField(default=False, db_index=True)
    mitre_tactics = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    kill_chain_phase = models.CharField(max_length=100, blank=True, default="")
    evidence = models.JSONField(default=list, blank=True)
    recommended_actions = models.JSONField(default=list, blank=True)
    reasoning_vi = models.TextField(blank=True, default="")
    reasoning_en = models.TextField(blank=True, default="")
    prompt_family = models.CharField(max_length=50, blank=True, default="")
    context_tiers = models.JSONField(default=dict, blank=True)
    facts = models.JSONField(
        default=dict,
        blank=True,
        help_text="Deterministic facts rendered from database records, never generated by the model.",
    )
    entities = models.JSONField(default=dict, blank=True)
    asset_context = models.JSONField(default=dict, blank=True)
    missing_context = models.JSONField(
        default=list,
        blank=True,
        help_text="Required fields still absent after enrichment, with what was tried and why it failed.",
    )
    quality_flags = models.JSONField(default=list, blank=True)
    error = models.TextField(blank=True, default="")
    suppressed_by = models.ForeignKey(
        TriageSuppression,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="triage_results",
    )
    llm_call = models.ForeignKey(
        "agentic.LlmCallRecord",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="triage_results",
    )
    human_verdict = models.CharField(max_length=30, choices=TriageVerdict, blank=True, default="")
    human_verdict_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="triage_overrides",
    )
    human_verdict_at = models.DateTimeField(null=True, blank=True)
    human_verdict_note = models.TextField(blank=True, default="")

    class Meta:
        db_table = "agentic_triage_results"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["case", "-created_at"], name="triage_case_created_idx"),
        ]

    def __str__(self):
        return f"{self.case_id} {self.verdict}"

    @property
    def effective_verdict(self):
        return self.human_verdict or self.verdict

    @property
    def ai_was_overridden(self):
        return bool(self.human_verdict) and self.human_verdict != self.verdict


class IocVerdict(models.TextChoices):
    MALICIOUS = "malicious", "Malicious"
    SUSPICIOUS = "suspicious", "Suspicious"
    BENIGN = "benign", "Benign"
    UNKNOWN = "unknown", "Unknown"


class IocVerification(BaseModel):
    indicator_type = models.CharField(max_length=20, db_index=True)
    indicator_value = models.CharField(max_length=1000, db_index=True)
    verdict = models.CharField(
        max_length=20, choices=IocVerdict, default=IocVerdict.UNKNOWN, db_index=True
    )
    confidence = models.FloatField(default=0.0)
    is_internal = models.BooleanField(default=False)
    first_seen = models.CharField(max_length=64, blank=True, default="")
    last_seen = models.CharField(max_length=64, blank=True, default="")
    categories = models.JSONField(default=list, blank=True)
    associated_actors = models.JSONField(default=list, blank=True)
    associated_campaigns = models.JSONField(default=list, blank=True)
    references = models.JSONField(default=list, blank=True)
    notes_vi = models.TextField(blank=True, default="")
    notes_en = models.TextField(blank=True, default="")
    sources_used = models.JSONField(default=list, blank=True)
    injection_flags = models.JSONField(default=list, blank=True)
    rejected_references = models.JSONField(default=list, blank=True)
    error = models.TextField(blank=True, default="")
    expires_at = models.DateTimeField(db_index=True)
    llm_call = models.ForeignKey(
        "agentic.LlmCallRecord",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="ioc_verifications",
    )

    class Meta:
        db_table = "agentic_ioc_verifications"
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["indicator_type", "indicator_value"],
                name="ioc_verification_unique_indicator",
            ),
        ]
        indexes = [
            models.Index(fields=["verdict", "-created_at"], name="ioc_verdict_created_idx"),
        ]

    def __str__(self):
        return f"{self.indicator_type}:{self.indicator_value} {self.verdict}"

    @property
    def is_fresh(self):
        return self.expires_at > timezone.now()
