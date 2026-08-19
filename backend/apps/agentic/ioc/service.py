"""IOC verification: structured sources plus web MCP, synthesised with citations.

This is the only skill whose traffic leaves the organisation, so the rules
here are stricter than elsewhere: the indicator itself is never contacted,
internal indicators never leave, and a malicious verdict without a retrieved
source is downgraded to unknown.
"""

import logging
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from django.conf import settings
from django.core.cache import caches
from django.db import transaction
from django.utils import timezone

from apps.agentic.analysis.prompts import STRUCTURED_OUTPUT_MODEL_TAG
from apps.agentic.ioc.injection import wrap_untrusted
from apps.agentic.ioc.normalize import (
    HASH_TYPES,
    IOC_DOMAIN,
    IOC_EMAIL,
    IOC_IP,
    IOC_UNKNOWN,
    IOC_URL,
    classify,
    is_internal,
)
from apps.agentic.ioc.schemas import IocVerdictOutput
from apps.agentic.models import IocVerdict, IocVerification, LlmCallRecord
from apps.settings.runtime_config import get_prompt_language
from integrations.llm.structured import StructuredOutputError, invoke_structured
from integrations.mcp.client import McpError, get_clients

logger = logging.getLogger(__name__)

PROMPT_DIRECTORY = "ioc_verify"
PROMPT_NAME = "System"
RATE_LIMIT_CACHE_KEY = "asp:ioc:ratelimit:{minute}"
EVIDENCE_REQUIRED_VERDICTS = {IocVerdict.MALICIOUS, IocVerdict.SUSPICIOUS}
SEARCH_TOOL_HINTS = ("search", "web_search", "brave_web_search", "tavily_search", "fetch_search")


def _config():
    from apps.settings.runtime_config import get_ioc_config

    return get_ioc_config()


def prompt_path(language=None):
    language = language or get_prompt_language()
    return Path(settings.CUSTOM_DIR) / "data" / "playbooks" / PROMPT_DIRECTORY / f"{PROMPT_NAME}_{language}.md"


def read_prompt():
    for language in (get_prompt_language(), "en"):
        path = prompt_path(language)
        if path.exists():
            return path.read_text(encoding="utf-8")
    raise FileNotFoundError(f"IOC verification prompt not found: {prompt_path('en')}")


def ttl_for(indicator_type, config):
    if indicator_type in HASH_TYPES:
        return config["ttl_hash_hours"]
    return {
        IOC_IP: config["ttl_ip_hours"],
        IOC_DOMAIN: config["ttl_domain_hours"],
        IOC_URL: config["ttl_url_hours"],
        IOC_EMAIL: config["ttl_email_hours"],
    }.get(indicator_type, config["ttl_domain_hours"])


def _rate_limit_ok(config):
    cache = caches["default"]
    key = RATE_LIMIT_CACHE_KEY.format(minute=int(timezone.now().timestamp() // 60))
    try:
        current = cache.get_or_set(key, 0, 120)
        count = cache.incr(key)
    except ValueError:
        cache.set(key, 1, 120)
        count = 1
    del current
    return count <= config["rate_limit_per_minute"]


# ------------------------------------------------------------------ sourcing

def collect_structured_intel(indicator_type, value):
    """OTX and OpenCTI through the existing threat intel service."""
    from integrations.threat_intel.service import query_indicator

    artifact_type = {
        IOC_IP: "IP Address",
        IOC_DOMAIN: "Domain",
        IOC_URL: "URL",
        IOC_EMAIL: "Email",
    }.get(indicator_type, "Hash")

    try:
        output = query_indicator(value, artifact_type=artifact_type)
    except Exception:
        logger.warning("Structured intel lookup failed for %s", value, exc_info=True)
        return []

    payload = output.model_dump() if hasattr(output, "model_dump") else output
    return (payload or {}).get("results") or []


def _search_tool_for(client):
    for tool in client.allowed_tools:
        if any(hint in tool.lower() for hint in SEARCH_TOOL_HINTS):
            return tool
    return next(iter(sorted(client.allowed_tools)), None)


def collect_web_evidence(indicator_type, value, config):
    """Query MCP servers about the indicator.

    The indicator is only ever a search term. ASP never resolves it, never
    fetches it, and never opens a connection towards attacker infrastructure.
    """
    blocks = []
    queries = [
        f"{value} malicious indicator analysis",
        f"{value} threat intelligence report",
    ]

    for client in get_clients():
        tool = _search_tool_for(client)
        if not tool:
            continue
        for query in queries:
            if len(blocks) >= config["max_web_results"]:
                break
            try:
                results = client.call_tool(tool, {"query": query})
            except McpError as exc:
                logger.warning("MCP server %s failed: %s", client.name, exc)
                break
            for item in results:
                blocks.append({"source": client.name, "content": item})
                if len(blocks) >= config["max_web_results"]:
                    break
    return blocks


URL_PATTERN_CHARS = ("http://", "https://")


def extract_candidate_urls(blocks, structured_results):
    """Every URL the model is permitted to cite."""
    import re

    candidates = []
    url_re = re.compile(r"https?://[^\s\"'<>)\]]+")

    for block in blocks:
        for match in url_re.findall(str(block.get("content") or "")):
            cleaned = match.rstrip(".,;")
            if cleaned not in candidates:
                candidates.append(cleaned)

    for item in structured_results or []:
        for key in ("reference", "url", "permalink", "link"):
            value = (item or {}).get(key) if isinstance(item, dict) else None
            if isinstance(value, str) and value.startswith(URL_PATTERN_CHARS) and value not in candidates:
                candidates.append(value)

    return candidates


def _domain_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def validate_references(references, candidates, config):
    """Reject citations the model did not actually retrieve."""
    allowed = set(candidates)
    reputable = {str(item).strip().lower() for item in (config.get("reputable_domains") or []) if str(item).strip()}

    kept, rejected = [], []
    for reference in references:
        payload = reference.model_dump() if hasattr(reference, "model_dump") else dict(reference)
        url = str(payload.get("url") or "").strip()
        if not url or url not in allowed:
            rejected.append(payload)
            continue
        domain = _domain_of(url)
        payload["reputable"] = bool(reputable) and any(
            domain == item or domain.endswith(f".{item}") for item in reputable
        )
        kept.append(payload)
    return kept, rejected


# ----------------------------------------------------------------- interface

def get_cached(indicator_type, value):
    record = IocVerification.objects.filter(
        indicator_type=indicator_type, indicator_value=value
    ).first()
    if record and record.is_fresh:
        return record
    return None


@transaction.atomic
def _store(indicator_type, value, *, ttl_hours, **fields):
    expires_at = timezone.now() + timedelta(hours=ttl_hours)
    record, _created = IocVerification.objects.update_or_create(
        indicator_type=indicator_type,
        indicator_value=value,
        defaults={"expires_at": expires_at, **fields},
    )
    return record


def verify_indicator(raw_value, *, artifact_type=None, force=False):
    """Verify one indicator. Always returns an IocVerification record."""
    config = _config()
    indicator_type, value = classify(raw_value)

    if indicator_type == IOC_UNKNOWN or not value:
        return _store(
            IOC_UNKNOWN,
            str(raw_value or "")[:1000],
            ttl_hours=1,
            verdict=IocVerdict.UNKNOWN,
            confidence=0.0,
            error="Indicator type could not be determined.",
            notes_en="The value is not a recognisable indicator.",
            notes_vi="Giá trị không phải là một chỉ dấu hợp lệ.",
        )

    internal = is_internal(
        indicator_type,
        value,
        internal_networks=config["internal_networks"],
        internal_domains=config["internal_domains"],
    )
    if internal:
        # Internal indicators never leave the organisation, cached or not.
        return _store(
            indicator_type,
            value,
            ttl_hours=ttl_for(indicator_type, config),
            verdict=IocVerdict.UNKNOWN,
            confidence=0.0,
            is_internal=True,
            sources_used=["internal-scope-check"],
            notes_en="Internal indicator. No external lookup was performed.",
            notes_vi="Chỉ dấu nội bộ. Không thực hiện tra cứu ra bên ngoài.",
        )

    if not force:
        cached = get_cached(indicator_type, value)
        if cached is not None:
            return cached

    if not config["enabled"]:
        return _store(
            indicator_type,
            value,
            ttl_hours=1,
            verdict=IocVerdict.UNKNOWN,
            error="IOC verification is disabled.",
        )

    if not _rate_limit_ok(config):
        logger.warning("IOC verification rate limit reached; skipping %s", value)
        return _store(
            indicator_type,
            value,
            ttl_hours=1,
            verdict=IocVerdict.UNKNOWN,
            error="Rate limit reached for IOC verification.",
        )

    structured_results = collect_structured_intel(indicator_type, value)
    sources_used = ["threat_intel"] if structured_results else []

    blocks = []
    if not config["internal_sources_only"]:
        blocks = collect_web_evidence(indicator_type, value, config)
        sources_used.extend(sorted({block["source"] for block in blocks}))

    if not structured_results and not blocks:
        # With no structured intelligence and no retrieved content there is
        # nothing to synthesise: the verdict is unknown by definition, so the
        # model call would only burn tokens.
        logger.info("No sources available for %s:%s; skipping LLM synthesis", indicator_type, value)
        return _store(
            indicator_type,
            value,
            ttl_hours=ttl_for(indicator_type, config),
            verdict=IocVerdict.UNKNOWN,
            confidence=0.0,
            sources_used=[],
            notes_en="No threat intelligence provider or web source returned anything for this indicator.",
            notes_vi="Không có nguồn threat intel hay nguồn web nào trả về dữ liệu cho chỉ dấu này.",
        )

    untrusted_text, injection_flags = wrap_untrusted(blocks)
    candidates = extract_candidate_urls(blocks, structured_results)

    payload = {
        "indicator": {"type": indicator_type, "value": value},
        "structured_intelligence": structured_results,
        "candidate_references": candidates,
        "retrieved_web_content": untrusted_text,
    }

    try:
        output, call = invoke_structured(
            system_prompt=read_prompt(),
            payload=payload,
            output_schema=IocVerdictOutput,
            model_tag=STRUCTURED_OUTPUT_MODEL_TAG,
        )
    except StructuredOutputError as exc:
        return _store(
            indicator_type,
            value,
            ttl_hours=1,
            verdict=IocVerdict.UNKNOWN,
            error=str(exc)[:2000],
            sources_used=sources_used,
            injection_flags=injection_flags,
        )
    except FileNotFoundError as exc:
        return _store(
            indicator_type, value, ttl_hours=1, verdict=IocVerdict.UNKNOWN, error=str(exc)[:500]
        )

    record = _record_call(call, indicator_type, value)
    kept, rejected = validate_references(output.references, candidates, config)

    verdict = output.verdict if output.verdict in {choice.value for choice in IocVerdict} else IocVerdict.UNKNOWN
    error = ""
    if verdict in EVIDENCE_REQUIRED_VERDICTS and not kept:
        # No retrievable source means no accusation.
        verdict = IocVerdict.UNKNOWN
        error = "Verdict downgraded to unknown: no retrievable reference supported it."

    return _store(
        indicator_type,
        value,
        ttl_hours=ttl_for(indicator_type, config),
        verdict=verdict,
        confidence=max(0.0, min(1.0, float(output.confidence or 0.0))),
        first_seen=output.first_seen,
        last_seen=output.last_seen,
        categories=output.categories,
        associated_actors=output.associated_actors,
        associated_campaigns=output.associated_campaigns,
        references=kept,
        rejected_references=rejected,
        notes_vi=output.notes_vi,
        notes_en=output.notes_en,
        sources_used=sources_used,
        injection_flags=injection_flags,
        error=error,
        llm_call=record,
    )


def _record_call(call, indicator_type, value):
    from apps.agentic.services.playbooks import _sanitize_visible_text

    try:
        return LlmCallRecord.objects.create(
            prompt_id="ioc.verify",
            prompt_version=get_prompt_language(),
            provider_name=call.provider_name,
            model_name=call.model_name,
            attempts=call.attempts,
            success=call.success,
            tokens_in=call.tokens_in,
            tokens_out=call.tokens_out,
            latency_ms=call.latency_ms,
            raw_response=_sanitize_visible_text(call.raw_response, max_length=20000),
            source_type=indicator_type,
            source_id=value[:64],
        )
    except Exception:
        logger.exception("Failed to persist IOC verification LLM call record")
        return None


def verify_bulk(values, *, force=False):
    return [verify_indicator(value, force=force) for value in values or []]


def verify_for_case(case, *, limit=10):
    """Enrichment step used by triage: verify the indicators on a Case."""
    seen = []
    records = []
    for alert in case.alerts.all():
        for artifact in alert.artifacts.all():
            value = str(getattr(artifact, "value", "") or "").strip()
            if not value or value in seen:
                continue
            indicator_type, normalised = classify(value)
            if indicator_type == IOC_UNKNOWN:
                continue
            seen.append(value)
            records.append(verify_indicator(normalised))
            if len(records) >= limit:
                return records
    return records
