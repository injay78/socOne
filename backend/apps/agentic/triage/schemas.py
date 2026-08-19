from pydantic import BaseModel, ConfigDict, Field


class TriageEvidence(BaseModel):
    """One piece of evidence backing the verdict.

    `reference` must point at a real record already in ASP. Items whose
    reference cannot be resolved are rejected before the result is stored, so
    the model cannot invent supporting facts.
    """

    kind: str = Field(description="log, enrichment, intel, cmdb or history")
    source: str = Field(description="Where the evidence came from")
    summary: str = Field(description="What the evidence shows")
    reference: str = Field(default="", description="Readable id of the referenced record, e.g. alert_000123")


class TriageAction(BaseModel):
    category: str = Field(description="investigate, contain or close")
    description: str


class TriageOutput(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    verdict: str = Field(description="true_positive, false_positive, benign_true_positive or needs_more_info")
    false_positive_class: str = Field(
        default="",
        description="Required when verdict is false_positive: suppressed, verified_legitimate, rule_misconfiguration or other",
    )
    severity: str = Field(description="Informational, Low, Medium, High or Critical")
    impact: str = Field(description="Unknown, Low, Medium, High or Critical")
    priority: str = Field(description="Unknown, Low, Medium, High or Critical")
    confidence: float = Field(ge=0.0, le=1.0, description="0 to 1")
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_phase: str = Field(default="")
    evidence: list[TriageEvidence] = Field(default_factory=list)
    recommended_actions: list[TriageAction] = Field(default_factory=list)
    reasoning_vi: str = Field(default="", description="Rendered rationale in Vietnamese")
    reasoning_en: str = Field(default="", description="Rendered rationale in English")
