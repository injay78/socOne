"""Guardrails around the single investigation call.

The investigation report is the one AI output for a Case. This module supplies
the deterministic context it is built on and records the assessment, so there is
no second model call producing an overlapping verdict.

`TriageResult` remains the storage record: it already carries the human
override, quality flags and verified facts that the audit work in S7 depends on.
"""

import logging

from django.db import transaction

from apps.agentic.models import FalsePositiveClass, TriageResult, TriageVerdict
from apps.agentic.triage.asset import detect_unverified_asset_claim
from apps.agentic.triage.completeness import ensure_context
from apps.agentic.triage.entities import extract_entities
from apps.agentic.triage.facts import build_facts
from apps.agentic.triage.suppression import find_matching_suppression

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_THRESHOLD = 0.6
VALID_VERDICTS = {choice.value for choice in TriageVerdict}
VALID_FP_CLASSES = {choice.value for choice in FalsePositiveClass}

# The report's textual confidence maps to a score when the model omits the
# numeric field, so the review threshold always has something to work with.
CONFIDENCE_TEXT_TO_SCORE = {
    "high": 0.9,
    "medium": 0.6,
    "low": 0.3,
    "unknown": 0.0,
}

VERDICT_ALIASES = {
    "true positive": TriageVerdict.TRUE_POSITIVE,
    "true_positive": TriageVerdict.TRUE_POSITIVE,
    "suspicious": TriageVerdict.NEEDS_MORE_INFO,
    "benign": TriageVerdict.BENIGN_TRUE_POSITIVE,
    "benign true positive": TriageVerdict.BENIGN_TRUE_POSITIVE,
    "benign_true_positive": TriageVerdict.BENIGN_TRUE_POSITIVE,
    "false positive": TriageVerdict.FALSE_POSITIVE,
    "false_positive": TriageVerdict.FALSE_POSITIVE,
    "insufficient data": TriageVerdict.NEEDS_MORE_INFO,
    "needs_more_info": TriageVerdict.NEEDS_MORE_INFO,
}


class _Suppressed:
    def __init__(self, report, record):
        self.report = report
        self.record = record


def confidence_threshold():
    from django.conf import settings

    return getattr(settings, "TRIAGE_CONFIDENCE_THRESHOLD", DEFAULT_CONFIDENCE_THRESHOLD)


def build_deterministic_context(case, case_payload):
    """Asset context, verified facts and remaining gaps, all before the model."""
    asset_context, missing, attempts = ensure_context(case)
    extracted = extract_entities(case)
    facts = build_facts(case, asset_context=asset_context, extracted_entities=extracted)
    return {
        "asset_context": asset_context,
        "facts": facts,
        "missing": missing,
        "attempts": attempts,
        "entities": extracted,
        "case_payload": case_payload,
    }


def normalise_verdict(raw):
    text = str(raw or "").strip().lower()
    if text in VALID_VERDICTS:
        return text
    return VERDICT_ALIASES.get(text, TriageVerdict.NEEDS_MORE_INFO)


def confidence_score(report):
    try:
        score = float(getattr(report, "confidence_score", 0.0) or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    if score > 0:
        return max(0.0, min(1.0, score))
    return CONFIDENCE_TEXT_TO_SCORE.get(str(getattr(report, "confidence", "")).strip().lower(), 0.0)


def _known_references(case):
    references = {case.case_id}
    for alert in case.alerts.all():
        references.add(alert.alert_id)
        for artifact in alert.artifacts.all():
            references.add(artifact.artifact_id)
    return {reference for reference in references if reference}


def _evidence_from_report(report, case):
    """Map investigation findings onto the evidence shape, dropping bad citations."""
    allowed = _known_references(case)
    kept, rejected = [], []
    for finding in getattr(report, "evidence_findings", []) or []:
        payload = finding.model_dump() if hasattr(finding, "model_dump") else dict(finding)
        reference = str(payload.get("subject") or "").strip()
        item = {
            "kind": payload.get("finding_type", "log"),
            "source": payload.get("subject", ""),
            "summary": f"{payload.get('title', '')}: {payload.get('evidence', '')}".strip(": "),
            "conclusion": payload.get("conclusion", ""),
            "reference": reference if reference in allowed else "",
        }
        if reference and reference not in allowed and reference.startswith(("case_", "alert_", "artifact_")):
            rejected.append(payload)
            continue
        kept.append(item)
    return kept, rejected


def _actions_from_report(report):
    actions = []
    for remediation in getattr(report, "remediations", []) or []:
        payload = remediation.model_dump() if hasattr(remediation, "model_dump") else dict(remediation)
        actions.append({
            "category": _action_category(payload.get("action_type", "")),
            "description": payload.get("description", ""),
            "priority": payload.get("priority", ""),
        })
    return actions


def _action_category(action_type):
    text = str(action_type or "").lower()
    if any(token in text for token in ("contain", "isolate", "block", "quarantine", "disable")):
        return "contain"
    if any(token in text for token in ("close", "monitor", "no action")):
        return "close"
    return "investigate"


def store_assessment(*, case, report, deterministic, trigger, trimmed_tiers=None, llm_call=None):
    """Persist the single AI assessment derived from the investigation report."""
    verdict = normalise_verdict(getattr(report, "verdict", ""))
    score = confidence_score(report)

    fp_class = str(getattr(report, "false_positive_class", "") or "").strip().lower()
    error = ""
    if verdict == TriageVerdict.FALSE_POSITIVE and fp_class not in VALID_FP_CLASSES:
        fp_class = FalsePositiveClass.OTHER
        error = "Report returned false_positive without a valid class; defaulted to other."
    elif fp_class not in VALID_FP_CLASSES:
        fp_class = ""

    evidence, rejected = _evidence_from_report(report, case)
    quality_flags = detect_unverified_asset_claim(
        getattr(report, "digest", ""), deterministic.get("asset_context")
    )
    if rejected:
        quality_flags.append({"flag": "rejected_evidence", "count": len(rejected)})
    if quality_flags:
        logger.warning("Assessment quality flags on case %s: %s", case.case_id, quality_flags)

    needs_human = score < confidence_threshold() or verdict == TriageVerdict.NEEDS_MORE_INFO

    result = TriageResult.objects.create(
        case=case,
        verdict=verdict,
        false_positive_class=fp_class,
        severity_ai=getattr(report, "severity", "") or "",
        impact_ai=getattr(report, "impact", "") or "",
        priority_ai=getattr(report, "priority", "") or "",
        confidence=score,
        needs_human=needs_human,
        mitre_tactics=[step.get("attack_stage", "") for step in _dump_list(report, "attack_chain")],
        mitre_techniques=_techniques(report),
        kill_chain_phase=_kill_chain(report),
        evidence=evidence,
        recommended_actions=_actions_from_report(report),
        reasoning_vi=getattr(report, "digest", "") or "",
        reasoning_en="",
        prompt_family="investigation",
        facts=deterministic.get("facts") or {},
        entities=deterministic.get("entities") or {},
        asset_context=deterministic.get("asset_context") or {},
        missing_context=deterministic.get("missing") or [],
        quality_flags=quality_flags,
        error=error,
        llm_call=llm_call,
        context_tiers={
            "trimmed": trimmed_tiers or [],
            "trigger": trigger,
            "attempts": deterministic.get("attempts") or [],
            "attack_chain": _dump_list(report, "attack_chain"),
            "attack_timeline": _dump_list(report, "attack_timeline"),
            "ioc_indicators": _dump_list(report, "ioc_indicators"),
            "affected_assets": _dump_list(report, "affected_assets"),
            "unknowns": list(getattr(report, "unknowns", []) or []),
        },
    )
    transaction.on_commit(lambda: _notify(result))
    transaction.on_commit(lambda: _learn(result))
    return result


def _learn(result, *, source=None):
    """Turn a settled verdict into retrievable knowledge.

    Swallowed like notifications: a knowledge problem must never roll back or
    block a triage verdict.
    """
    from apps.knowledge.curation import capture_from_triage
    from apps.knowledge.models import KnowledgeSource

    try:
        capture_from_triage(result, source=source or KnowledgeSource.TRIAGE)
    except Exception:
        logger.exception("Failed to capture knowledge for case %s", result.case_id)


def _notify(result):
    """Queue Telegram/inbox notifications once the assessment is committed.

    Failures are swallowed: a notification problem must never roll back or
    block the triage verdict.
    """
    from apps.notifications.service import emit_triage_result

    try:
        emit_triage_result(result)
    except Exception:
        logger.exception("Failed to queue triage notification for case %s", result.case_id)


def _dump_list(report, field):
    items = getattr(report, field, []) or []
    return [item.model_dump() if hasattr(item, "model_dump") else dict(item) for item in items]


def _techniques(report):
    values = []
    for step in _dump_list(report, "attack_chain"):
        stage = str(step.get("attack_stage") or "")
        if stage and stage not in values:
            values.append(stage)
    return values


def _kill_chain(report):
    chain = _dump_list(report, "attack_chain")
    return str(chain[-1].get("attack_stage") or "") if chain else ""


def suppressed_assessment(case, deterministic, *, trigger):
    """Short-circuit a suppressed Case without spending an LLM call."""
    suppression = find_matching_suppression(deterministic.get("case_payload") or {})
    if suppression is None:
        return None

    from apps.agentic.analysis.schemas import AnalysisRecord, InvestigationReport

    logger.info("Case %s suppressed by %s", case.case_id, suppression)
    digest = (
        f"Case bị chặn bởi suppression rule {suppression.match_type}:{suppression.pattern}. "
        f"{suppression.reason}"
    )
    report = InvestigationReport(
        verdict=TriageVerdict.FALSE_POSITIVE,
        false_positive_class=FalsePositiveClass.SUPPRESSED,
        severity="Low",
        impact="Low",
        priority="Low",
        confidence="High",
        confidence_score=1.0,
        digest=digest,
    )

    TriageResult.objects.create(
        case=case,
        verdict=TriageVerdict.FALSE_POSITIVE,
        false_positive_class=FalsePositiveClass.SUPPRESSED,
        confidence=1.0,
        needs_human=False,
        suppressed_by=suppression,
        reasoning_vi=digest,
        prompt_family="suppression",
        facts=deterministic.get("facts") or {},
        entities=deterministic.get("entities") or {},
        asset_context=deterministic.get("asset_context") or {},
        missing_context=deterministic.get("missing") or [],
        context_tiers={"trigger": trigger, "attempts": deterministic.get("attempts") or []},
    )

    record = AnalysisRecord(
        trigger=trigger,
        profile_version="suppressed",
        generated_at="",
        report=report,
    )
    return _Suppressed(report, record.model_dump())
