from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.common.models import BaseModel
from apps.common.readable_ids import save_with_readable_id


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


class ClusterStatus(models.TextChoices):
    OPEN = "open", "Open"
    MERGED = "merged", "Merged"
    CLOSED = "closed", "Closed"


class IncidentCluster(BaseModel):
    """An N-way, machine-generated grouping of Cases and Alerts sharing entities.

    Deliberately not a Case and not a CaseRelationship. A Case already collapses
    alerts sharing a correlation_uid, so making it a container of Cases too would
    give one model two grouping semantics, and every existing list view, metric
    and SLA rule would start counting containers as ordinary Cases.
    CaseRelationship is a pairwise, analyst-curated link; machine-generated edges
    would pollute it, and a pairwise row cannot hold cluster identity, score or
    lifecycle.
    """

    cluster_id = models.CharField(
        max_length=32,
        unique=True,
        editable=False,
        db_index=True,
        blank=True,
        default="",
        help_text="Record ID e.g. cluster_000001",
    )
    title = models.CharField(max_length=500, blank=True, default="")
    primary_entities = models.JSONField(
        default=dict,
        blank=True,
        help_text="Typed entity sets defining this cluster, from triage entity extraction.",
    )
    window_start = models.DateTimeField(db_index=True)
    window_end = models.DateTimeField(db_index=True)
    link_score = models.FloatField(default=0.0)
    status = models.CharField(
        max_length=20, choices=ClusterStatus, default=ClusterStatus.OPEN, db_index=True
    )
    case_count = models.PositiveIntegerField(default=0)
    alert_count = models.PositiveIntegerField(default=0)
    fingerprint = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="Hash over the sorted primary entity set. A re-run updates the cluster carrying this fingerprint instead of creating a second one.",
    )
    merged_into = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="merged_from"
    )
    lifecycle_events = models.JSONField(
        default=list,
        blank=True,
        help_text="Append-only merge and split events, so a cluster is never silently replaced.",
    )

    class Meta:
        db_table = "agentic_incident_clusters"
        ordering = ["-window_end", "-created_at"]
        indexes = [
            models.Index(fields=["status", "-window_end"], name="cluster_status_window_idx"),
        ]

    def __str__(self):
        return f"{self.cluster_id or self.id} {self.title}"

    def save(self, *args, **kwargs):
        return save_with_readable_id(self, "cluster_id", "cluster", *args, **kwargs)


class IncidentClusterMember(BaseModel):
    cluster = models.ForeignKey(
        IncidentCluster, on_delete=models.CASCADE, related_name="members"
    )
    case = models.ForeignKey(
        "cases.Case",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="cluster_memberships",
    )
    alert = models.ForeignKey(
        "alerts.Alert",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="cluster_memberships",
    )
    joined_at = models.DateTimeField(default=timezone.now, db_index=True)
    contribution_score = models.FloatField(default=0.0)

    class Meta:
        db_table = "agentic_incident_cluster_members"
        ordering = ["joined_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["cluster", "case"],
                condition=models.Q(case__isnull=False),
                name="cluster_member_unique_case",
            ),
            models.UniqueConstraint(
                fields=["cluster", "alert"],
                condition=models.Q(alert__isnull=False),
                name="cluster_member_unique_alert",
            ),
        ]

    def __str__(self):
        return f"{self.cluster_id} -> {self.case_id or self.alert_id}"


class HuntMode(models.TextChoices):
    ADVISORY = "advisory", "Advisory"
    AUTO = "auto", "Auto"


class HuntPlanStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    GENERATING = "generating", "Generating"
    READY = "ready", "Ready"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    BUDGET_EXHAUSTED = "budget_exhausted", "Budget Exhausted"


class HuntPlan(BaseModel):
    cluster = models.ForeignKey(
        IncidentCluster, on_delete=models.CASCADE, related_name="hunt_plans"
    )
    status = models.CharField(
        max_length=20, choices=HuntPlanStatus, default=HuntPlanStatus.PENDING, db_index=True
    )
    mode = models.CharField(
        max_length=20,
        choices=HuntMode,
        default=HuntMode.ADVISORY,
        db_index=True,
        help_text="advisory generates queries without running them. auto executes them read-only behind the SIEM and EDR guards.",
    )
    hypotheses_count = models.PositiveIntegerField(default=0)
    llm_call = models.ForeignKey(
        "agentic.LlmCallRecord",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="hunt_plans",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="hunt_plans",
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    stop_reason = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Why the plan stopped early, for example which budget ceiling was reached.",
    )
    budget_snapshot = models.JSONField(
        default=dict,
        blank=True,
        help_text="Ceilings in force when the plan ran, so a later config change does not rewrite history.",
    )
    error = models.TextField(blank=True, default="")

    class Meta:
        db_table = "agentic_hunt_plans"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["cluster", "-created_at"], name="hunt_plan_cluster_idx"),
        ]

    def __str__(self):
        return f"{self.cluster_id} {self.mode} {self.status}"


class HuntHypothesisStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    CONFIRMED = "confirmed", "Confirmed"
    REFUTED = "refuted", "Refuted"
    INCONCLUSIVE = "inconclusive", "Inconclusive"


class HuntHypothesis(BaseModel):
    plan = models.ForeignKey(HuntPlan, on_delete=models.CASCADE, related_name="hypotheses")
    statement = models.TextField(blank=True, default="")
    mitre_technique = models.CharField(max_length=50, blank=True, default="", db_index=True)
    rationale = models.TextField(blank=True, default="")
    status = models.CharField(
        max_length=20,
        choices=HuntHypothesisStatus,
        default=HuntHypothesisStatus.PENDING,
        db_index=True,
    )
    position = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = "agentic_hunt_hypotheses"
        ordering = ["plan", "position"]

    def __str__(self):
        return f"{self.mitre_technique or 'hypothesis'} {self.status}"


class HuntQueryTarget(models.TextChoices):
    QRADAR = "qradar", "QRadar"
    TRELLIX = "trellix", "Trellix"


class HuntQueryStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    REJECTED = "rejected", "Rejected by guard"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"
    SKIPPED = "skipped", "Skipped"


class HuntQuery(BaseModel):
    hypothesis = models.ForeignKey(
        HuntHypothesis, on_delete=models.CASCADE, related_name="queries"
    )
    target = models.CharField(max_length=20, choices=HuntQueryTarget, db_index=True)
    query_text = models.TextField(blank=True, default="")
    purpose = models.TextField(blank=True, default="")
    expected_evidence = models.TextField(
        blank=True, default="", help_text="How to read a positive result."
    )
    negative_interpretation = models.TextField(
        blank=True, default="", help_text="What an empty result does and does not prove."
    )
    status = models.CharField(
        max_length=20, choices=HuntQueryStatus, default=HuntQueryStatus.PENDING, db_index=True
    )
    row_count = models.PositiveIntegerField(null=True, blank=True)
    sample_rows = models.JSONField(default=list, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    guard_rejection_reason = models.TextField(
        blank=True,
        default="",
        help_text="Why the read-only guard refused this query. A rejected query is surfaced, never silently skipped.",
    )
    executed_at = models.DateTimeField(null=True, blank=True)
    executed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="hunt_queries",
    )
    error = models.TextField(blank=True, default="")
    position = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = "agentic_hunt_queries"
        ordering = ["hypothesis", "position"]

    def __str__(self):
        return f"{self.target} {self.status}"


class HuntConclusion(models.TextChoices):
    CONFIRMED = "confirmed", "Confirmed"
    REFUTED = "refuted", "Refuted"
    INCONCLUSIVE = "inconclusive", "Inconclusive"


class HuntFinding(BaseModel):
    hypothesis = models.ForeignKey(
        HuntHypothesis, on_delete=models.CASCADE, related_name="findings"
    )
    conclusion = models.CharField(
        max_length=20,
        choices=HuntConclusion,
        default=HuntConclusion.INCONCLUSIVE,
        db_index=True,
    )
    summary = models.TextField(blank=True, default="")
    evidence = models.JSONField(
        default=list,
        blank=True,
        help_text="References to real records. Evidence the model only describes is not accepted.",
    )
    llm_call = models.ForeignKey(
        "agentic.LlmCallRecord",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="hunt_findings",
    )

    class Meta:
        db_table = "agentic_hunt_findings"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.hypothesis_id} {self.conclusion}"
