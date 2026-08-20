from pydantic import BaseModel, ConfigDict, Field


class HuntQueryOutput(BaseModel):
    """One concrete query a Tier 3 analyst could run against a real system.

    `negative_interpretation` is mandatory in spirit: a hunting query whose empty
    result cannot be interpreted wastes an analyst's shift.
    """

    model_config = ConfigDict(use_enum_values=True)

    target: str = Field(description="qradar or trellix")
    query_text: str = Field(default="")
    purpose: str = Field(default="")
    expected_evidence: str = Field(default="", description="How to read a positive result.")
    negative_interpretation: str = Field(
        default="", description="What an empty result does and does not prove."
    )


class HuntHypothesisOutput(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    statement: str = Field(default="")
    mitre_technique: str = Field(default="", description="ATT&CK technique id such as T1078.")
    rationale: str = Field(default="")
    queries: list[HuntQueryOutput] = Field(default_factory=list)


class HuntPlanOutput(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    summary: str = Field(default="")
    hypotheses: list[HuntHypothesisOutput] = Field(default_factory=list)


class HuntEvidenceRef(BaseModel):
    """A pointer to a record that exists in this database.

    References are validated after generation; anything the model invented is
    dropped, and a conclusion left without evidence cannot be `confirmed`.
    """

    kind: str = Field(default="", description="hunt_query, case or alert")
    reference: str = Field(default="", description="Record identifier")
    note: str = Field(default="")


class HuntFindingOutput(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    conclusion: str = Field(description="confirmed, refuted or inconclusive")
    summary: str = Field(default="")
    evidence: list[HuntEvidenceRef] = Field(default_factory=list)


class HuntRefinementOutput(BaseModel):
    """Follow-up queries proposed after a round of results was inconclusive.

    Returning no queries is a valid and often correct answer: it says the
    hypothesis cannot be settled with the telemetry available, which is more
    useful than another speculative query.
    """

    model_config = ConfigDict(use_enum_values=True)

    rationale: str = Field(default="", description="Why these follow-ups, or why none are worth running.")
    queries: list[HuntQueryOutput] = Field(default_factory=list)
