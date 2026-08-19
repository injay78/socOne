import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from apps.settings.runtime_config import get_prompt_language
from integrations.llm.structured import StructuredCall, StructuredOutputError, invoke_structured

logger = logging.getLogger(__name__)

INVESTIGATION_SYSTEM_PROMPT = "investigation.system"
INVESTIGATION_KNOWLEDGE_KEYWORD_PROMPT = "investigation.knowledge_keywords"
KNOWLEDGE_EXTRACTION_PROMPT = "knowledge_extraction.system"

ANALYSIS_SYSTEM_PROMPT_PATH = ("investigation", "System")
KNOWLEDGE_KEYWORD_PROMPT_PATH = ("investigation", "KnowledgeKeywords")
KNOWLEDGE_EXTRACTION_PROMPT_PATH = ("knowledge_extraction", "System")


@dataclass(frozen=True)
class PromptSpec:
    directory: str
    name: str


PROMPT_CATALOG = {
    INVESTIGATION_SYSTEM_PROMPT: PromptSpec(*ANALYSIS_SYSTEM_PROMPT_PATH),
    INVESTIGATION_KNOWLEDGE_KEYWORD_PROMPT: PromptSpec(*KNOWLEDGE_KEYWORD_PROMPT_PATH),
    KNOWLEDGE_EXTRACTION_PROMPT: PromptSpec(*KNOWLEDGE_EXTRACTION_PROMPT_PATH),
}


def _prompt_file_path(spec, *, language=None):
    prompt_language = language or get_prompt_language()
    filename = f"{spec.name}_{prompt_language}.md"
    return Path(settings.BASE_DIR) / "data" / "playbooks" / spec.directory / filename


def _prompt_spec(prompt_id):
    try:
        return PROMPT_CATALOG[prompt_id]
    except KeyError:
        raise KeyError(f"Unknown agentic prompt id: {prompt_id}") from None


def read_prompt(prompt_id, *, language=None):
    spec = _prompt_spec(prompt_id)
    return _prompt_file_path(spec, language=language).read_text(encoding="utf-8")


STRUCTURED_OUTPUT_MODEL_TAG = "structured_output"
RAW_RESPONSE_MAX_LENGTH = 20000


def prompt_fingerprint(prompt_id, *, language=None):
    text = read_prompt(prompt_id, language=language)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _record_call(*, prompt_id, call, source=None, case=None, trimmed_tiers=None, error=""):
    from apps.agentic.models import LlmCallRecord
    from apps.agentic.services.playbooks import _sanitize_visible_text

    source_type, source_id = "", ""
    if source is not None:
        source_type = source._meta.model_name if hasattr(source, "_meta") else type(source).__name__
        source_id = str(getattr(source, "pk", ""))

    try:
        LlmCallRecord.objects.create(
            prompt_id=prompt_id,
            prompt_version=get_prompt_language(),
            prompt_hash=prompt_fingerprint(prompt_id),
            provider_name=getattr(call, "provider_name", ""),
            model_name=getattr(call, "model_name", ""),
            attempts=getattr(call, "attempts", 0),
            success=getattr(call, "success", False),
            error=error[:2000],
            tokens_in=getattr(call, "tokens_in", None),
            tokens_out=getattr(call, "tokens_out", None),
            latency_ms=getattr(call, "latency_ms", 0),
            trimmed_tiers=trimmed_tiers or [],
            raw_response=_sanitize_visible_text(
                getattr(call, "raw_response", ""),
                max_length=RAW_RESPONSE_MAX_LENGTH,
            ),
            source_type=source_type,
            source_id=source_id,
            case=case,
        )
    except Exception:
        logger.exception("Failed to persist LLM call record for prompt %s", prompt_id)


def invoke_structured_llm(
    *,
    prompt_id,
    payload,
    output_schema,
    model_tag=STRUCTURED_OUTPUT_MODEL_TAG,
    source=None,
    case=None,
    trimmed_tiers=None,
):
    try:
        instance, call = invoke_structured(
            system_prompt=read_prompt(prompt_id),
            payload=payload,
            output_schema=output_schema,
            model_tag=model_tag,
        )
    except StructuredOutputError as exc:
        _record_call(
            prompt_id=prompt_id,
            call=StructuredCall(
                provider_name="",
                model_name="",
                attempts=exc.attempts,
                latency_ms=0,
                tokens_in=None,
                tokens_out=None,
                raw_response=exc.raw_response,
                success=False,
            ),
            source=source,
            case=case,
            trimmed_tiers=trimmed_tiers,
            error=str(exc),
        )
        raise

    _record_call(
        prompt_id=prompt_id,
        call=call,
        source=source,
        case=case,
        trimmed_tiers=trimmed_tiers,
    )
    return instance
