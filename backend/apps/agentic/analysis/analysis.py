from dataclasses import dataclass
from typing import Any

from django.utils import timezone

from apps.agentic.analysis.knowledge import build_knowledge_context
from apps.agentic.analysis.profiles import AI_PROFILE_VERSION, serialize_case_for_investigation
from apps.agentic.analysis.prompts import (
    INVESTIGATION_SYSTEM_PROMPT,
    STRUCTURED_OUTPUT_MODEL_TAG,
    invoke_structured_llm,
)
from apps.agentic.analysis.schemas import AnalysisRecord, InvestigationReport
from apps.agentic.services.cases import save_case_analysis_record
from integrations.llm.budget import PayloadTier, apply_budget
from integrations.llm.structured import structured_output_limits


@dataclass(frozen=True)
class CaseAnalysisRequest:
    case: Any
    trigger: str
    user_input: str = ""
    source: Any = None


@dataclass(frozen=True)
class AnalysisResult:
    report: InvestigationReport
    analysis_record: dict


def generate_investigation_report(analysis_input, *, case=None, source=None, trimmed_tiers=None):
    return invoke_structured_llm(
        prompt_id=INVESTIGATION_SYSTEM_PROMPT,
        payload=analysis_input,
        output_schema=InvestigationReport,
        case=case,
        source=source,
        trimmed_tiers=trimmed_tiers,
    )


def _source_identity(source):
    if source is None:
        return "", ""
    model_name = source._meta.model_name if hasattr(source, "_meta") else type(source).__name__
    return model_name, str(getattr(source, "pk", ""))


@dataclass(frozen=True)
class CaseAnalysisRunner:
    def run(self, request: CaseAnalysisRequest):
        from apps.agentic.triage.assessment import (
            build_deterministic_context,
            store_assessment,
            suppressed_assessment,
        )

        case_payload = serialize_case_for_investigation(request.case)
        knowledge_context = build_knowledge_context(case_payload)

        # Deterministic context and guardrails run before the model, so the
        # report is built on verified facts rather than on inference.
        deterministic = build_deterministic_context(request.case, case_payload)
        suppressed = suppressed_assessment(request.case, deterministic, trigger=request.trigger)
        if suppressed is not None:
            return AnalysisResult(report=suppressed.report, analysis_record=suppressed.record)

        analysis_input, trimmed_tiers = self._build_analysis_input(
            case_payload=case_payload,
            knowledge_context=knowledge_context,
            user_input=request.user_input,
            deterministic=deterministic,
        )

        report = generate_investigation_report(
            analysis_input,
            case=request.case,
            source=request.source,
            trimmed_tiers=trimmed_tiers,
        )
        record = self._build_analysis_record(
            request=request,
            knowledge_context=knowledge_context,
            report=report,
        )
        save_case_analysis_record(case=request.case, record=record)
        store_assessment(
            case=request.case,
            report=report,
            deterministic=deterministic,
            trigger=request.trigger,
            trimmed_tiers=trimmed_tiers,
        )
        return AnalysisResult(report=report, analysis_record=record.model_dump())

    def _build_analysis_input(self, *, case_payload, knowledge_context, user_input, deterministic=None):
        knowledge_payload = knowledge_context.as_payload()
        case_core = {key: value for key, value in case_payload.items() if key != "alerts"}
        deterministic = deterministic or {}
        tiers = [
            PayloadTier("case_core", 0, case_core, truncatable=False),
            PayloadTier("asset_context", 1, deterministic.get("asset_context") or {}, truncatable=False),
            PayloadTier("verified_facts", 2, deterministic.get("facts") or {}, truncatable=False),
            PayloadTier("missing_context", 3, deterministic.get("missing") or [], truncatable=False),
            PayloadTier("alerts", 4, case_payload.get("alerts") or []),
            PayloadTier("knowledge_records", 5, knowledge_payload.get("records") or []),
        ]
        limits = structured_output_limits(STRUCTURED_OUTPUT_MODEL_TAG)
        budget = apply_budget(
            tiers,
            context_window_tokens=limits["context_window_tokens"],
            max_output_tokens=limits["max_output_tokens"],
        )

        analysis_input = {
            "case": {**budget.payload.get("case_core", {}), "alerts": budget.payload.get("alerts", [])},
            "knowledge": {**knowledge_payload, "records": budget.payload.get("knowledge_records", [])},
            "asset_context": budget.payload.get("asset_context", {}),
            "verified_facts": budget.payload.get("verified_facts", {}),
            "missing_context": budget.payload.get("missing_context", []),
            "discussions": [],
        }
        if user_input:
            analysis_input["user_input"] = user_input
        return analysis_input, budget.trimmed_tiers

    def _build_analysis_record(self, *, request, knowledge_context, report):
        source_type, source_id = _source_identity(request.source)
        return AnalysisRecord(
            trigger=request.trigger,
            source_type=source_type,
            source_id=source_id,
            profile_version=AI_PROFILE_VERSION,
            generated_at=timezone.now().isoformat(),
            knowledge_keywords=knowledge_context.keywords,
            knowledge_records=knowledge_context.records,
            report=report,
        )


def run_case_analysis(*, case, trigger, user_input="", source=None):
    request = CaseAnalysisRequest(
        case=case,
        trigger=trigger,
        user_input=user_input,
        source=source,
    )
    return CaseAnalysisRunner().run(request)
