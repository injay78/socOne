from django.core.exceptions import ValidationError
from django.db import models

from apps.common.models import BaseModel
from apps.common.readable_ids import save_with_readable_id


class KnowledgeSource(models.TextChoices):
    MANUAL = "Manual"
    CASE = "Case"
    TRIAGE = "Triage"
    HUMAN_OVERRIDE = "HumanOverride", "Human Override"
    HUNT = "Hunt"


# Sources that describe a specific case. Manual knowledge is the only kind that
# stands on its own.
CASE_DERIVED_SOURCES = {
    KnowledgeSource.CASE,
    KnowledgeSource.TRIAGE,
    KnowledgeSource.HUMAN_OVERRIDE,
    KnowledgeSource.HUNT,
}


class KnowledgeKind(models.TextChoices):
    """What a record teaches, which decides how it is retrieved and weighted."""

    FALSE_POSITIVE = "false_positive", "False Positive Context"
    BUSINESS_BEHAVIOUR = "business_behaviour", "Business Behaviour"
    ASSET_CRITICALITY = "asset_criticality", "Asset Criticality"
    IDENTITY_CRITICALITY = "identity_criticality", "Identity Criticality"
    HUNT_FINDING = "hunt_finding", "Hunt Finding"
    DETECTION_LOGIC = "detection_logic", "Detection Logic"
    OTHER = "other", "Other"


class Knowledge(BaseModel):
    knowledge_id = models.CharField(max_length=32, unique=True, editable=False, db_index=True, blank=True, default="", help_text="Record ID e.g. knowledge_000001 (记录 ID e.g. knowledge_000001)")
    title = models.CharField(max_length=500, blank=True, default="", help_text="Knowledge title (知识标题)")
    body = models.TextField(blank=True, default="", help_text="Knowledge content (知识内容)")
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Knowledge expiration time; empty means permanently valid (知识过期时间，空表示永久有效)")
    source = models.CharField(max_length=20, choices=KnowledgeSource, blank=True, default="", help_text="Knowledge source (知识来源)")
    kind = models.CharField(
        max_length=32,
        choices=KnowledgeKind,
        default=KnowledgeKind.OTHER,
        db_index=True,
        help_text="What this record teaches, which decides how it is retrieved and weighted.",
    )
    tags = models.JSONField(default=list, blank=True, help_text="Knowledge tags (知识标签)")
    entities = models.JSONField(
        default=dict,
        blank=True,
        help_text="Typed entities this record applies to, in the triage extraction shape. Retrieval matches these before it falls back to text.",
    )
    fingerprint = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        help_text="Hash over kind and entities. Capturing the same lesson twice updates the existing record instead of adding a duplicate.",
    )
    confidence = models.FloatField(
        default=0.0,
        help_text="How much to trust this record. Human-written and human-corrected knowledge outranks anything a model inferred.",
    )
    hit_count = models.PositiveIntegerField(
        default=0,
        help_text="How often this record was retrieved into an investigation, used to rank the useful above the merely recent.",
    )
    last_used_at = models.DateTimeField(null=True, blank=True, db_index=True)
    case = models.ForeignKey(
        "cases.Case",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="extracted_knowledge",
        help_text="Case this Knowledge was extracted from; empty for manual Knowledge (知识提取来源 Case, 手动知识为空)",
    )

    class Meta:
        db_table = "knowledge"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["created_at", "source"], name="knowledge_created_src_idx"),
            models.Index(fields=["kind", "-hit_count"], name="knowledge_kind_hits_idx"),
        ]

    def save(self, *args, **kwargs):
        return save_with_readable_id(self, "knowledge_id", "knowledge", *args, **kwargs)

    def clean(self):
        super().clean()
        if self.source in CASE_DERIVED_SOURCES and self.case_id is None:
            raise ValidationError({"case": "Case-derived knowledge requires a case."})
        if self.source == KnowledgeSource.MANUAL and self.case_id is not None:
            raise ValidationError({"case": "Manual knowledge cannot be linked to a case."})

    def __str__(self):
        return self.title or str(self.id)
