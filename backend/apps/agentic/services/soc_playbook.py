"""Shared runner for markdown-driven SOC analysis playbooks.

Every SOC playbook in custom/playbooks/soc_*.py is a thin wrapper around one of
the two entry points here: run_case_playbook analyses the whole case against a
markdown procedure, run_ioc_playbook applies the procedure per matching
artifact. The markdown itself is the system prompt; the LLM answer must be a
JSON object (schema described inside the prompt, per the self-hosted-LLM rule),
extracted and repaired before anything trusts it.
"""

import json
import logging

from django.db import transaction
from langchain_core.messages import HumanMessage, SystemMessage

from apps.agentic.analysis.profiles import serialize_case_for_investigation
from apps.enrichments.models import Enrichment, EnrichmentProvider, EnrichmentType
from apps.settings.runtime_config import get_prompt_language
from integrations.llm.extraction import JsonExtractionError, extract_json_object
from integrations.llm.llmapi import LLMAPI
from integrations.threat_intel.service import query_indicator

logger = logging.getLogger(__name__)

MAX_PAYLOAD_CHARS = 60_000
MAX_ENRICHMENT_DATA_CHARS = 2_000
MAX_TI_ARTIFACTS = 10
MAX_IOC_ARTIFACTS = 5
TI_SUPPORTED_TYPES = ("IP Address", "Hostname", "URL String", "Hash")


def run_case_playbook(playbook, *, enrich_ti=True):
    """Analyse the whole case with the playbook's markdown procedure."""
    case = playbook.case
    if case is None:
        raise ValueError(f"{playbook.NAME} requires a linked case.")

    if enrich_ti:
        playbook.add_run_message("Collecting threat intelligence for case artifacts...")
        stats = ensure_threat_intel(case)
        playbook.add_run_message(
            f"Threat intel ready: {stats['enriched']} enriched, {stats['skipped']} skipped."
        )

    payload = {
        "case": serialize_case_for_investigation(case),
        "enrichments": _collect_enrichments(case),
        "user_input": playbook.user_input,
    }
    playbook.add_run_message("Running LLM analysis...")
    parsed = _invoke(playbook, payload)

    status = str(parsed.get("Status") or parsed.get("status") or "").strip()
    confidence = parsed.get("Confidence") or parsed.get("confidence_score") or parsed.get("confidence")
    _store_case_report(case, playbook, parsed)
    playbook.add_run_message("Report stored as case enrichment.")
    return f"{playbook.NAME}: Status={status or 'n/a'}, Confidence={confidence if confidence is not None else 'n/a'}"


def run_ioc_playbook(playbook, *, artifact_types, enrich_ti=True):
    """Apply the playbook's markdown procedure to each matching artifact."""
    case = playbook.case
    if case is None:
        raise ValueError(f"{playbook.NAME} requires a linked case.")

    artifacts = [
        artifact
        for artifact in _unique_artifacts(case)
        if str(artifact.type) in artifact_types and artifact.value
    ][:MAX_IOC_ARTIFACTS]
    if not artifacts:
        return f"{playbook.NAME}: no matching artifacts on this case."

    summaries = []
    for artifact in artifacts:
        playbook.add_run_message(f"Analysing {artifact.type}: {artifact.value[:120]}")
        if enrich_ti:
            _enrich_artifact(artifact)
        payload = {
            "indicator": artifact.value,
            "indicator_type": str(artifact.type),
            "enrichments": [
                _compact_enrichment(item)
                for item in artifact.enrichments.order_by("-created_at")[:8]
            ],
            "case_context": {
                "case_id": case.case_id,
                "title": case.title,
                "severity": str(case.severity),
            },
            "user_input": playbook.user_input,
        }
        try:
            parsed = _invoke(playbook, payload)
        except Exception:
            logger.exception("SOC IOC playbook failed for artifact %s", artifact.artifact_id)
            summaries.append(f"{artifact.value[:60]}: failed")
            continue
        status = str(parsed.get("Status") or parsed.get("status") or "unknown").strip()
        _store_artifact_report(case, artifact, playbook, parsed)
        summaries.append(f"{artifact.value[:60]}: {status}")

    return f"{playbook.NAME}: " + "; ".join(summaries)


def ensure_threat_intel(case):
    """Upsert TI enrichment for the case's lookup-able artifacts (bounded)."""
    stats = {"enriched": 0, "skipped": 0}
    candidates = [
        artifact
        for artifact in _unique_artifacts(case)
        if str(artifact.type) in TI_SUPPORTED_TYPES and artifact.value
    ][:MAX_TI_ARTIFACTS]
    for artifact in candidates:
        try:
            if _enrich_artifact(artifact):
                stats["enriched"] += 1
            else:
                stats["skipped"] += 1
        except Exception:
            logger.exception("TI enrichment failed for artifact %s", artifact.artifact_id)
            stats["skipped"] += 1
    return stats


def _enrich_artifact(artifact):
    output = query_indicator(artifact.value, artifact_type=artifact.type)
    wrote = False
    for result in output.results:
        if result.error:
            continue
        _upsert_ti_enrichment(artifact, result)
        wrote = True
    return wrote


@transaction.atomic
def _upsert_ti_enrichment(artifact, result):
    uid = f"ti:{result.provider}:{artifact.artifact_id}"
    enrichment = (
        Enrichment.objects.select_for_update()
        .filter(artifact=artifact, provider=result.provider, type=EnrichmentType.THREAT_INTELLIGENCE, uid=uid)
        .first()
    )
    if enrichment is None:
        enrichment = Enrichment(
            artifact=artifact,
            provider=result.provider,
            type=EnrichmentType.THREAT_INTELLIGENCE,
            uid=uid,
        )
    malicious_text = "malicious" if result.is_malicious else "not malicious"
    enrichment.name = "Threat Intelligence"
    enrichment.value = artifact.value
    enrichment.desc = f"{result.provider} assessed indicator as {malicious_text} with {result.risk_level or 'unknown'} risk."
    enrichment.data = result.model_dump()
    enrichment.full_clean()
    enrichment.save()
    return enrichment


def _unique_artifacts(case):
    artifacts = {}
    for alert in case.alerts.prefetch_related("artifacts"):
        for artifact in alert.artifacts.all():
            artifacts[artifact.id] = artifact
    return list(artifacts.values())


def _collect_enrichments(case, limit=40):
    """Compact snapshot of everything already enriched on this case."""
    rows = Enrichment.objects.filter(alert__case=case) | Enrichment.objects.filter(case=case)
    artifact_rows = Enrichment.objects.filter(artifact__alerts__case=case)
    combined = (rows | artifact_rows).distinct().order_by("-created_at")[:limit]
    return [_compact_enrichment(item) for item in combined]


def _compact_enrichment(item):
    data = item.data if isinstance(item.data, dict) else {}
    dumped = json.dumps(data, ensure_ascii=False)
    if len(dumped) > MAX_ENRICHMENT_DATA_CHARS:
        dumped = dumped[:MAX_ENRICHMENT_DATA_CHARS] + "...[TRUNCATED]"
        data = {"_truncated": dumped}
    return {
        "provider": str(item.provider),
        "type": str(item.type),
        "value": item.value,
        "desc": item.desc,
        "data": data,
    }


def _read_system_prompt(playbook):
    languages = []
    try:
        configured = get_prompt_language()
    except Exception:
        configured = ""
    for lang in (configured, "vi", "en"):
        if lang and lang not in languages:
            languages.append(lang)
    last_error = None
    for lang in languages:
        try:
            return playbook.read_prompt("System", language=lang)
        except FileNotFoundError as exc:
            last_error = exc
    raise last_error


MODEL_TAG = "structured_output"
CHARS_PER_TOKEN = 2  # conservative for Vietnamese text
PROMPT_ALLOWANCE_TOKENS = 1_000


def _invoke(playbook, payload):
    system_prompt = _read_system_prompt(playbook)

    api = LLMAPI(temperature=0.0)
    provider = api.select_config(tag=MODEL_TAG)
    extra_kwargs = {}
    if provider.get("supports_json_mode"):
        extra_kwargs["model_kwargs"] = {"response_format": {"type": "json_object"}}
    model = api.get_model(tag=MODEL_TAG, **extra_kwargs)

    context_window = provider.get("context_window_tokens") or 32_768
    max_output = provider.get("max_output_tokens") or 4_096
    available_tokens = max(2_000, context_window - max_output - PROMPT_ALLOWANCE_TOKENS)
    payload_budget = max(8_000, available_tokens * CHARS_PER_TOKEN - len(system_prompt))
    body = _budgeted_json(payload, min(MAX_PAYLOAD_CHARS, payload_budget))

    messages = [SystemMessage(content=system_prompt), HumanMessage(content=body)]
    attempts = max(1, int(provider.get("max_retries", 2)) + 1)
    last_error = None
    for attempt in range(attempts):
        result = model.invoke(messages)
        text = _content_as_text(result.content)
        try:
            return extract_json_object(text)
        except JsonExtractionError as exc:
            last_error = exc
            messages = messages + [
                result,
                HumanMessage(content=(
                    "Kết quả trước không phải JSON hợp lệ "
                    f"({exc}). Trả về DUY NHẤT một JSON object đúng schema mô tả trong system prompt, "
                    "không suy nghĩ dài dòng, không thêm văn bản ngoài JSON."
                )),
            ]
    raise last_error


def _budgeted_json(payload, budget):
    body = json.dumps(payload, ensure_ascii=False, default=str)
    if len(body) <= budget:
        return body
    trimmed = _strip_heavy_keys(payload, {"raw_data", "raw_detection", "raw_threat", "raw"})
    body = json.dumps(trimmed, ensure_ascii=False, default=str)
    if len(body) <= budget:
        return body
    return body[:budget] + '... [TRUNCATED]"}'


def _strip_heavy_keys(value, keys):
    if isinstance(value, dict):
        return {k: _strip_heavy_keys(v, keys) for k, v in value.items() if k not in keys}
    if isinstance(value, list):
        return [_strip_heavy_keys(item, keys) for item in value]
    return value


def _content_as_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text", item)))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)


@transaction.atomic
def _store_case_report(case, playbook, parsed):
    uid = f"soc-playbook:{playbook.prompt_slug()}:{case.case_id}"
    _upsert_report(
        uid=uid,
        defaults={"case": case},
        name=playbook.NAME,
        value=case.case_id,
        parsed=parsed,
    )


@transaction.atomic
def _store_artifact_report(case, artifact, playbook, parsed):
    uid = f"soc-playbook:{playbook.prompt_slug()}:{artifact.artifact_id}"
    _upsert_report(
        uid=uid,
        defaults={"case": case, "artifact": artifact},
        name=playbook.NAME,
        value=artifact.value,
        parsed=parsed,
    )


def _upsert_report(*, uid, defaults, name, value, parsed):
    enrichment = (
        Enrichment.objects.select_for_update()
        .filter(uid=uid, provider=EnrichmentProvider.ASP, type=EnrichmentType.OBSERVATION)
        .first()
    )
    if enrichment is None:
        enrichment = Enrichment(
            uid=uid,
            provider=EnrichmentProvider.ASP,
            type=EnrichmentType.OBSERVATION,
            **defaults,
        )
    status = str(parsed.get("Status") or parsed.get("status") or "").strip()
    confidence = parsed.get("Confidence") or parsed.get("confidence_score") or parsed.get("confidence")
    enrichment.name = name
    enrichment.value = str(value)[:500]
    enrichment.desc = f"{name}: Status={status or 'n/a'}, Confidence={confidence if confidence is not None else 'n/a'}"
    enrichment.data = parsed
    enrichment.full_clean()
    enrichment.save()
    return enrichment
