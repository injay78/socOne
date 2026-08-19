from pydantic import BaseModel, ConfigDict, Field


class IocReference(BaseModel):
    """A citation the model selected from the retrieved candidate set.

    `url` must appear in the candidates gathered during this run. Anything else
    is rejected at validation time.
    """

    url: str
    title: str = ""
    published_at: str = ""
    quote: str = ""


class IocVerdictOutput(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    verdict: str = Field(description="malicious, suspicious, benign or unknown")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    first_seen: str = Field(default="")
    last_seen: str = Field(default="")
    categories: list[str] = Field(default_factory=list)
    associated_actors: list[str] = Field(default_factory=list)
    associated_campaigns: list[str] = Field(default_factory=list)
    references: list[IocReference] = Field(default_factory=list)
    notes_vi: str = Field(default="")
    notes_en: str = Field(default="")
