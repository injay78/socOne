from pydantic import BaseModel, ConfigDict, Field


class AffectedAsset(BaseModel):
    asset_type: str
    asset_value: str


class EvidenceFinding(BaseModel):
    title: str
    finding_type: str
    subject: str
    evidence: str
    conclusion: str


class AttackChainStep(BaseModel):
    attack_stage: str
    description: str


class TimelineEvent(BaseModel):
    timestamp: str
    attack_behavior: str
    evidence_field: str


class IndicatorOfCompromise(BaseModel):
    indicator_type: str
    value: str
    context: str


class Remediation(BaseModel):
    action_type: str
    description: str
    priority: str


class InvestigationReport(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    verdict: str = Field(
        description="true_positive, benign_true_positive, false_positive or needs_more_info"
    )
    false_positive_class: str = Field(
        default="",
        description=(
            "Required when verdict is false_positive: suppressed, verified_legitimate, "
            "rule_misconfiguration or other"
        ),
    )
    severity: str
    impact: str
    priority: str
    confidence: str = Field(description="Unknown, Low, Medium or High")
    confidence_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Numeric confidence from 0 to 1. Drives the human-review threshold.",
    )
    digest: str
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    evidence_findings: list[EvidenceFinding] = Field(default_factory=list)
    attack_chain: list[AttackChainStep] = Field(default_factory=list)
    attack_timeline: list[TimelineEvent] = Field(default_factory=list)
    ioc_indicators: list[IndicatorOfCompromise] = Field(default_factory=list)
    remediations: list[Remediation] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)


class KnowledgeSearchKeywords(BaseModel):
    keywords: list[str] = Field(default_factory=list)


class AnalysisRecord(BaseModel):
    trigger: str
    source_type: str = ""
    source_id: str = ""
    profile_version: str
    generated_at: str
    knowledge_keywords: list[str] = Field(default_factory=list)
    knowledge_records: list[dict] = Field(default_factory=list)
    report: InvestigationReport
