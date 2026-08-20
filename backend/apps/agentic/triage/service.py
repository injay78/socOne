"""AI triage: deterministic pre-checks, one structured LLM call, stored verdict."""

import logging
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.agentic.analysis.prompts import STRUCTURED_OUTPUT_MODEL_TAG
from apps.agentic.analysis.profiles import serialize_case_for_investigation
from apps.agentic.models import (
    FalsePositiveClass,
    LlmCallRecord,
    TriageResult,
    TriageVerdict,
)
from apps.agentic.triage.asset import detect_unverified_asset_claim
from apps.agentic.triage.completeness import ensure_context
from apps.agentic.triage.context import (
    build_history_context,
    build_identity_context,
    build_ioc_verification_context,
    build_threat_intel_context,
    has_minimum_context,
)
from apps.agentic.triage.entities import extract_entities
from apps.agentic.triage.facts import build_facts
from apps.agentic.triage.schemas import TriageOutput
from apps.agentic.triage.suppression import find_matching_suppression
from apps.settings.runtime_config import get_prompt_language
from integrations.llm.budget import PayloadTier, apply_budget
from integrations.llm.structured import (
    StructuredOutputError,
    invoke_structured,
    structured_output_limits,
)

logger = logging.getLogger(__name__)

PROMPT_DIRECTORY = "ai_triage"
DEFAULT_FAMILY = "system"
DEFAULT_CONFIDENCE_THRESHOLD = 0.6

FAMILY_KEYWORDS = {
    "auth": ("login", "logon", "authentication", "brute", "credential", "password", "mfa"),
    "malware": ("malware", "ransom", "trojan", "virus", "payload", "shadow copy", "vssadmin"),
    "network": ("network", "port scan", "beacon", "c2", "dns", "proxy", "firewall", "traffic"),
    "data_exfil": ("exfil", "upload", "dlp", "data transfer", "large download"),
    "insider": ("insider", "privilege", "policy change", "unauthorized access", "after hours"),
}

VALID_VERDICTS = {choice.value for choice in TriageVerdict}
VALID_FP_CLASSES = {choice.value for choice in FalsePositiveClass}


class TriageSkipped(Exception):
    """Raised when triage deliberately did not run an LLM call."""


def prompt_path(family, *, language=None):
    language = language or get_prompt_language()
    return Path(settings.CUSTOM_DIR) / "data" / "playbooks" / PROMPT_DIRECTORY / f"{family}_{language}.md"


def read_triage_prompt(family):
    """Family prompt when present, otherwise the system prompt.

    Falls back across language too, so a missing translation degrades to the
    English prompt instead of failing the whole triage.
    """
    for candidate_family in (family, DEFAULT_FAMILY):
        for language in (get_prompt_language(), "en"):
            path = prompt_path(candidate_family, language=language)
            if path.exists():
                return path.read_text(encoding="utf-8"), candidate_family
    raise FileNotFoundError(
        f"No triage prompt found. Expected {prompt_path(DEFAULT_FAMILY, language='en')}"
    )


def select_family(case_payload):
    haystack = " ".join(
        [
            str(case_payload.get("title") or ""),
            str(case_payload.get("description") or ""),
            *[str((alert or {}).get("rule_name") or "") for alert in case_payload.get("alerts") or []],
        ]
    ).lower()

    for family, keywords in FAMILY_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            return family
    return DEFAULT_FAMILY


def confidence_threshold():
    return getattr(settings, "TRIAGE_CONFIDENCE_THRESHOLD", DEFAULT_CONFIDENCE_THRESHOLD)


def _known_references(case):
    """Readable ids the model is allowed to cite."""
    references = {case.case_id}
    for alert in case.alerts.all():
        references.add(alert.alert_id)
        for artifact in alert.artifacts.all():
            references.add(artifact.artifact_id)
    return {reference for reference in references if reference}


def validate_evidence(evidence_items, allowed_references):
    """Drop fabricated citations and report what was removed.

    An evidence item may omit a reference, but a reference that does not
    resolve to a real record is a hallucination and is rejected.
    """
    kept, rejected = [], []
    for item in evidence_items:
        payload = item.model_dump() if hasattr(item, "model_dump") else dict(item)
        reference = str(payload.get("reference") or "").strip()
        if reference and reference not in allowed_references:
            rejected.append(payload)
            continue
        kept.append(payload)
    return kept, rejected


def build_payload(case, *, asset_context=None, facts=None, missing=None):
    case_payload = serialize_case_for_investigation(case)
    tiers = [
        PayloadTier("case", 0, {k: v for k, v in case_payload.items() if k != "alerts"}, truncatable=False),
        # Asset context is a structured block with an explicit cmdb_matched flag,
        # never a free-form dump the model can read a role into.
        PayloadTier("asset_context", 1, asset_context or {}, truncatable=False),
        PayloadTier("verified_facts", 2, facts or {}, truncatable=False),
        PayloadTier("missing_context", 3, missing or [], truncatable=False),
        PayloadTier("alerts", 4, case_payload.get("alerts") or []),
        PayloadTier("threat_intel", 5, build_threat_intel_context(case_payload)),
        PayloadTier("identity", 6, build_identity_context(case_payload)),
        PayloadTier("ioc_verification", 7, build_ioc_verification_context(case)),
        PayloadTier("history", 8, build_history_context(case)),
    ]
    limits = structured_output_limits(STRUCTURED_OUTPUT_MODEL_TAG)
    budget = apply_budget(
        tiers,
        context_window_tokens=limits["context_window_tokens"],
        max_output_tokens=limits["max_output_tokens"],
    )
    payload = dict(budget.payload)
    payload["case"] = {**payload.get("case", {}), "alerts": payload.get("alerts", [])}
    payload.pop("alerts", None)
    return case_payload, payload, budget.trimmed_tiers


@transaction.atomic
def _store(case, **fields):
    result = TriageResult.objects.create(case=case, **fields)
    _mirror_to_case(case, result)
    transaction.on_commit(lambda: _notify(result))
    return result


def _notify(result):
    """Queue notifications after the result is committed.

    Notification problems must never roll back or block a triage verdict, so
    this runs on_commit and swallows its own failures.
    """
    from apps.notifications.service import emit_triage_result

    try:
        emit_triage_result(result)
    except Exception:
        logger.exception("Failed to queue triage notification for %s", result.case_id)


def _mirror_to_case(case, result):
    """Keep the existing Case.*_ai fields as the compatibility surface."""
    updates = {}
    if result.verdict != TriageVerdict.NEEDS_MORE_INFO:
        if result.severity_ai:
            updates["severity_ai"] = result.severity_ai
        if result.impact_ai:
            updates["impact_ai"] = result.impact_ai
        if result.priority_ai:
            updates["priority_ai"] = result.priority_ai
    if updates:
        for field, value in updates.items():
            setattr(case, field, value)
        case.save(update_fields=[*updates.keys(), "updated_at"])


def run_case_triage(case, *, trigger="analysis"):
    """Run the single AI assessment for a Case.

    Kept as the public entry point used by the API and the UI, but it no longer
    makes its own model call: the investigation report is the one AI output, and
    this returns the assessment derived from it.
    """
    from apps.agentic.analysis.analysis import run_case_analysis
    from apps.agentic.models import TriageResult

    run_case_analysis(case=case, trigger=trigger)
    result = TriageResult.objects.filter(case=case).order_by("-created_at").first()
    if result is None:
        raise RuntimeError(f"No assessment was stored for case {case.case_id}")
    return result


def _record_llm_call(case, call, family, trimmed):
    from apps.agentic.services.playbooks import _sanitize_visible_text

    try:
        return LlmCallRecord.objects.create(
            prompt_id=f"triage.{family}",
            prompt_version=get_prompt_language(),
            provider_name=call.provider_name,
            model_name=call.model_name,
            attempts=call.attempts,
            success=call.success,
            tokens_in=call.tokens_in,
            tokens_out=call.tokens_out,
            latency_ms=call.latency_ms,
            trimmed_tiers=trimmed,
            raw_response=_sanitize_visible_text(call.raw_response, max_length=20000),
            source_type="case",
            source_id=str(case.pk),
            case=case,
        )
    except Exception:
        logger.exception("Failed to persist triage LLM call record for %s", case.case_id)
        return None


def _store_model_output(case, output, record, family, trimmed, trigger, *, common=None, attempts=None):
    verdict = output.verdict if output.verdict in VALID_VERDICTS else TriageVerdict.NEEDS_MORE_INFO
    fp_class = output.false_positive_class if output.false_positive_class in VALID_FP_CLASSES else ""

    error = ""
    if verdict == TriageVerdict.FALSE_POSITIVE and not fp_class:
        # A false positive without a stated class is not actionable feedback.
        fp_class = FalsePositiveClass.OTHER
        error = "Model returned false_positive without a valid class; defaulted to other."

    kept_evidence, rejected_evidence = validate_evidence(output.evidence, _known_references(case))
    if rejected_evidence:
        logger.warning(
            "Dropped %d fabricated evidence reference(s) on case %s",
            len(rejected_evidence),
            case.case_id,
        )

    confidence = max(0.0, min(1.0, float(output.confidence or 0.0)))
    needs_human = confidence < confidence_threshold() or verdict == TriageVerdict.NEEDS_MORE_INFO

    common = common or {}
    # Post-check: role language with no system of record behind it.
    quality_flags = detect_unverified_asset_claim(
        f"{output.reasoning_vi}\n{output.reasoning_en}",
        common.get("asset_context"),
    )
    if rejected_evidence:
        quality_flags.append({"flag": "rejected_evidence", "count": len(rejected_evidence)})
    if quality_flags:
        logger.warning("Triage quality flags on case %s: %s", case.case_id, quality_flags)

    return _store(
        case,
        verdict=verdict,
        false_positive_class=fp_class,
        severity_ai=output.severity or "",
        impact_ai=output.impact or "",
        priority_ai=output.priority or "",
        confidence=confidence,
        needs_human=needs_human,
        mitre_tactics=output.mitre_tactics,
        mitre_techniques=output.mitre_techniques,
        kill_chain_phase=output.kill_chain_phase,
        evidence=kept_evidence,
        recommended_actions=[action.model_dump() for action in output.recommended_actions],
        reasoning_vi=output.reasoning_vi,
        reasoning_en=output.reasoning_en,
        prompt_family=family,
        llm_call=record,
        error=error,
        quality_flags=quality_flags,
        context_tiers={
            "trimmed": trimmed,
            "trigger": trigger,
            "rejected_evidence": len(rejected_evidence),
            "attempts": attempts or [],
        },
        **common,
    )


@transaction.atomic
def apply_human_verdict(result, *, verdict, user, note=""):
    if verdict not in VALID_VERDICTS:
        raise ValueError(f"Unknown triage verdict: {verdict}")

    locked = TriageResult.objects.select_for_update().get(pk=result.pk)
    locked.human_verdict = verdict
    locked.human_verdict_by = user if getattr(user, "is_authenticated", False) else None
    locked.human_verdict_at = timezone.now()
    locked.human_verdict_note = note or ""
    locked.save(update_fields=[
        "human_verdict",
        "human_verdict_by",
        "human_verdict_at",
        "human_verdict_note",
        "updated_at",
    ])

    # A human correcting the model is the most valuable lesson the platform
    # ever sees, so it is captured at a higher confidence than any AI verdict.
    from apps.agentic.triage.assessment import _learn
    from apps.knowledge.models import KnowledgeSource

    transaction.on_commit(lambda: _learn(locked, source=KnowledgeSource.HUMAN_OVERRIDE))
    return locked
