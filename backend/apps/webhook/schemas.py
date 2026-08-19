from typing import Any

from pydantic import BaseModel, Field


class SplunkPayload(BaseModel):
    search_name: str
    result: dict[str, Any]
    sid: str | None = None
    app: str | None = None
    owner: str | None = None
    results_link: str | None = None


class KibanaRule(BaseModel):
    name: str


class KibanaContext(BaseModel):
    hits: list[Any]


class KibanaPayload(BaseModel):
    rule: KibanaRule
    context: KibanaContext


class WebhookResult(BaseModel):
    status: str = "success"
    stream: str
    sent: int = 0
    skipped: int = 0
    message_ids: list[str] = Field(default_factory=list)


class QRadarPayload(BaseModel):
    """Payload posted by a QRadar Custom Action or forwarding rule.

    Accepts either a bare offence object or an envelope carrying one, so the
    same endpoint works with the shapes QRadar deployments emit in practice.
    """

    offense: dict[str, Any] | None = None
    offense_id: int | str | None = None

    model_config = {"extra": "allow"}

    def resolved_offense(self) -> dict[str, Any]:
        if self.offense:
            return self.offense
        extra = {
            key: value
            for key, value in (self.__pydantic_extra__ or {}).items()
            if key not in {"offense", "offense_id"}
        }
        if self.offense_id is not None:
            extra.setdefault("id", self.offense_id)
        if not extra.get("id"):
            raise ValueError("QRadar webhook payload must contain an offence id.")
        return extra
