import json
import logging
import time
from dataclasses import dataclass

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import ValidationError

from integrations.llm.anonymization import build_anonymizer
from integrations.llm.extraction import JsonExtractionError, extract_json_object
from integrations.llm.llmapi import LLMAPI

logger = logging.getLogger(__name__)

SCHEMA_INSTRUCTION = (
    "Respond with a single JSON object that validates against this JSON Schema.\n"
    "Return only the JSON object: no prose before or after it, no code fence, no explanation.\n"
    "Every field described as required must be present.\n\n"
    "JSON Schema:\n{schema}"
)

REPAIR_INSTRUCTION = (
    "The previous response could not be used: {error}\n"
    "Return the corrected JSON object only."
)


class StructuredOutputError(RuntimeError):
    """Raised when the model never produced a schema-valid object."""

    def __init__(self, message, *, attempts, raw_response=""):
        super().__init__(message)
        self.attempts = attempts
        self.raw_response = raw_response


@dataclass
class StructuredCall:
    provider_name: str
    model_name: str
    attempts: int
    latency_ms: int
    tokens_in: int | None
    tokens_out: int | None
    raw_response: str
    success: bool
    error: str = ""


def structured_output_limits(model_tag=None):
    """Input budget of the provider a structured call will resolve to."""
    api = LLMAPI(temperature=0.0)
    provider = api.select_config(tag=model_tag) if model_tag else api.select_config()
    return {
        "context_window_tokens": provider.get("context_window_tokens") or 32768,
        "max_output_tokens": provider.get("max_output_tokens") or 4096,
    }


def _schema_text(output_schema):
    return json.dumps(output_schema.model_json_schema(), ensure_ascii=False, indent=2)


def _content_as_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        return "".join(parts)
    return str(content or "")


def _usage(response):
    usage = getattr(response, "usage_metadata", None) or {}
    return usage.get("input_tokens"), usage.get("output_tokens")


def invoke_structured(*, system_prompt, payload, output_schema, model_tag=None, config=None):
    """Obtain a schema-valid object from an OpenAI-compatible endpoint.

    Deliberately avoids tool calling and provider-side schema enforcement:
    the schema is described in the prompt, JSON mode is opt-in per provider,
    and every response goes through extraction, repair and validation.
    """
    api = LLMAPI(temperature=0.0)
    provider = api.select_config(tag=model_tag) if model_tag else api.select_config()

    anonymizer = build_anonymizer()
    if anonymizer is not None:
        payload = anonymizer.anonymize(payload)

    extra_kwargs = {}
    if provider.get("supports_json_mode"):
        extra_kwargs["model_kwargs"] = {"response_format": {"type": "json_object"}}

    model = api.get_model(tag=model_tag, **extra_kwargs)

    system_content = f"{system_prompt}\n\n{SCHEMA_INSTRUCTION.format(schema=_schema_text(output_schema))}"
    messages = [
        SystemMessage(content=system_content),
        HumanMessage(content=json.dumps(payload, ensure_ascii=False, default=str)),
    ]

    max_attempts = max(1, int(provider.get("max_retries", 2)) + 1)
    started = time.perf_counter()
    raw_text = ""
    tokens_in = tokens_out = None
    last_error = ""

    for attempt in range(1, max_attempts + 1):
        response = model.invoke(messages)
        raw_text = _content_as_text(response.content)
        attempt_in, attempt_out = _usage(response)
        tokens_in = attempt_in if attempt_in is not None else tokens_in
        tokens_out = attempt_out if attempt_out is not None else tokens_out

        try:
            data = extract_json_object(raw_text)
            if anonymizer is not None:
                data = anonymizer.rehydrate(data)
            instance = output_schema.model_validate(data)
        except (JsonExtractionError, ValidationError) as exc:
            last_error = str(exc)
            logger.warning(
                "Structured LLM attempt %s/%s rejected: %s",
                attempt,
                max_attempts,
                last_error,
            )
            if attempt == max_attempts:
                break
            messages = [
                *messages,
                response,
                HumanMessage(content=REPAIR_INSTRUCTION.format(error=last_error)),
            ]
            continue

        return instance, StructuredCall(
            provider_name=provider.get("name", ""),
            model_name=provider.get("model", ""),
            attempts=attempt,
            latency_ms=int((time.perf_counter() - started) * 1000),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            raw_response=raw_text,
            success=True,
        )

    raise StructuredOutputError(
        f"LLM did not return a schema-valid object after {max_attempts} attempts: {last_error}",
        attempts=max_attempts,
        raw_response=raw_text,
    )
