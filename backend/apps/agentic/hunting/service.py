"""Hunt plan generation and guarded execution.

Two things are load-bearing here. First, nothing reaches QRadar or Trellix unless
the plan is in `auto` mode *and* the runtime master switch allows it: this is a
production bank SIEM and hunting is the one feature capable of degrading it.
Second, a query the guard refuses is recorded and shown with its reason, never
silently skipped, so an analyst never reads an empty plan as an all-clear.
"""

import logging
import time
from contextlib import contextmanager

from django.core.cache import caches
from django.db import transaction
from django.utils import timezone

from apps.agentic.hunting.prompts import (
    FINDING_PROMPT_NAME,
    PLAN_PROMPT_NAME,
    REFINE_PROMPT_NAME,
    build_finding_payload,
    build_plan_payload,
    build_refine_payload,
    read_prompt,
)
from apps.agentic.hunting.schemas import (
    HuntFindingOutput,
    HuntPlanOutput,
    HuntRefinementOutput,
)
from apps.agentic.models import (
    HuntConclusion,
    HuntFinding,
    HuntHypothesis,
    HuntHypothesisStatus,
    HuntMode,
    HuntPlan,
    HuntPlanStatus,
    HuntQuery,
    HuntQueryStatus,
    HuntQueryTarget,
    LlmCallRecord,
)
from apps.agentic.services.playbooks import _sanitize_visible_text
from apps.settings.runtime_config import get_hunting_config
from integrations.llm.structured import StructuredOutputError, invoke_structured
from integrations.siem import audit as siem_audit
from integrations.siem.aql_guard import guard_aql_with_config

logger = logging.getLogger(__name__)

PLAN_RATE_CACHE_KEY = "asp:hunt:plans:{hour}"
SEARCH_SLOT_CACHE_KEY = "asp:hunt:search-slot:{index}"
SEARCH_SLOT_TTL_SECONDS = 600


class HuntBudgetExceeded(RuntimeError):
    pass


def _cache():
    return caches["default"]


def _record_llm_call(prompt_id, call, *, source_type, source_id):
    return LlmCallRecord.objects.create(
        prompt_id=prompt_id,
        provider_name=call.provider_name,
        model_name=call.model_name,
        attempts=call.attempts,
        success=call.success,
        error=call.error or "",
        tokens_in=call.tokens_in,
        tokens_out=call.tokens_out,
        latency_ms=call.latency_ms,
        raw_response=call.raw_response or "",
        source_type=source_type,
        source_id=str(source_id),
    )


def _check_plan_rate_limit(config):
    key = PLAN_RATE_CACHE_KEY.format(hour=timezone.now().strftime("%Y%m%d%H"))
    cache = _cache()
    cache.add(key, 0, 3700)
    try:
        used = cache.incr(key)
    except ValueError:
        cache.set(key, 1, 3700)
        used = 1
    if used > config["max_plans_per_hour"]:
        raise HuntBudgetExceeded(
            f"Hunt plan ceiling reached: {config['max_plans_per_hour']} plans per hour."
        )


@contextmanager
def _search_slot(config):
    """Cap concurrent SIEM searches across every running plan."""
    cache = _cache()
    acquired = None
    for index in range(max(1, config["max_concurrent_searches"])):
        key = SEARCH_SLOT_CACHE_KEY.format(index=index)
        if cache.add(key, "1", SEARCH_SLOT_TTL_SECONDS):
            acquired = key
            break
    if acquired is None:
        raise HuntBudgetExceeded(
            f"All {config['max_concurrent_searches']} concurrent search slot(s) are busy."
        )
    try:
        yield
    finally:
        cache.delete(acquired)


def resolve_mode(requested_mode, config):
    """Fold the requested mode against the runtime master switch.

    Returns (mode, reason). Asking for `auto` while it is disabled yields an
    advisory plan and a reason the analyst can see, rather than a silent refusal.
    """
    requested = requested_mode or config["default_mode"]
    if requested == HuntMode.AUTO and not config["allow_auto_mode"]:
        return HuntMode.ADVISORY, "auto mode is disabled in runtime configuration"
    if requested not in {HuntMode.ADVISORY, HuntMode.AUTO}:
        return HuntMode.ADVISORY, f"unknown mode {requested!r}"
    return requested, ""


@transaction.atomic
def _persist_plan(plan, output, config):
    """Write hypotheses and queries, enforcing the per-plan query ceiling."""
    max_queries = config["max_queries_per_plan"]
    written_queries = 0
    dropped = 0

    for position, hypothesis_out in enumerate(output.hypotheses or []):
        hypothesis = HuntHypothesis.objects.create(
            plan=plan,
            statement=(hypothesis_out.statement or "").strip(),
            mitre_technique=(hypothesis_out.mitre_technique or "").strip()[:50],
            rationale=(hypothesis_out.rationale or "").strip(),
            position=position,
        )
        for query_position, query_out in enumerate(hypothesis_out.queries or []):
            if written_queries >= max_queries:
                dropped += 1
                continue
            target = (query_out.target or "").strip().lower()
            if target not in {HuntQueryTarget.QRADAR, HuntQueryTarget.TRELLIX}:
                dropped += 1
                continue
            HuntQuery.objects.create(
                hypothesis=hypothesis,
                target=target,
                query_text=(query_out.query_text or "").strip(),
                purpose=(query_out.purpose or "").strip(),
                expected_evidence=(query_out.expected_evidence or "").strip(),
                negative_interpretation=(query_out.negative_interpretation or "").strip(),
                position=query_position,
            )
            written_queries += 1

    plan.hypotheses_count = plan.hypotheses.count()
    if dropped:
        plan.stop_reason = (
            f"{dropped} generated quer(y/ies) dropped at the per-plan ceiling of {max_queries}."
        )
    return written_queries, dropped


def generate_plan(cluster, *, mode=None, user=None):
    config = get_hunting_config()
    if not config["enabled"]:
        raise HuntBudgetExceeded("Threat hunting is disabled in runtime configuration.")

    _check_plan_rate_limit(config)
    effective_mode, mode_reason = resolve_mode(mode, config)

    plan = HuntPlan.objects.create(
        cluster=cluster,
        status=HuntPlanStatus.GENERATING,
        mode=effective_mode,
        created_by=user if getattr(user, "is_authenticated", False) else None,
        started_at=timezone.now(),
        budget_snapshot=dict(config),
        stop_reason=mode_reason,
    )

    payload = build_plan_payload(
        cluster,
        max_window_hours=config["max_window_hours"],
        max_rows=config["max_rows"],
    )

    try:
        output, call = invoke_structured(
            system_prompt=read_prompt(PLAN_PROMPT_NAME),
            payload=payload,
            output_schema=HuntPlanOutput,
        )
    except Exception as exc:  # noqa: BLE001
        # Not only StructuredOutputError: provider-side failures such as a 400 for
        # an unsupported model, an auth error or a timeout surface as vendor
        # exceptions. A hunt plan is an optional enrichment, so a failed LLM call
        # is recorded on the plan and never propagated to the caller.
        plan.status = HuntPlanStatus.FAILED
        plan.error = f"{type(exc).__name__}: {exc}"[:2000]
        plan.completed_at = timezone.now()
        plan.save()
        logger.warning("Hunt plan generation failed for %s: %s", cluster.cluster_id, exc)
        return plan

    plan.llm_call = _record_llm_call(
        "hunting.plan", call, source_type="hunt_plan", source_id=plan.id
    )
    _persist_plan(plan, output, config)
    plan.status = HuntPlanStatus.READY
    plan.save()

    if effective_mode == HuntMode.AUTO:
        run_plan(plan, user=user)
    else:
        plan.completed_at = timezone.now()
        plan.save(update_fields=["completed_at", "updated_at"])

    return plan


SAMPLE_VALUE_MAX_LENGTH = 500


def _scrub_rows(rows, limit):
    """Trim and scrub sample rows with the playbook secret scrubber."""
    scrubbed = []
    for row in list(rows or [])[:limit]:
        if isinstance(row, dict):
            scrubbed.append(
                {
                    key: _sanitize_visible_text(value, max_length=SAMPLE_VALUE_MAX_LENGTH)
                    for key, value in row.items()
                }
            )
        else:
            scrubbed.append(_sanitize_visible_text(row, max_length=SAMPLE_VALUE_MAX_LENGTH))
    return scrubbed


def _execute_qradar(query, config):
    from integrations.siem.qradar_client import QRadarClient
    from apps.settings.runtime_config import get_qradar_config

    guard = guard_aql_with_config(query.query_text)
    if not guard.allowed:
        siem_audit.record_blocked_query(
            target="qradar", query=query.query_text, reason=guard.reason, detail=guard.detail
        )
        return None, guard

    client = QRadarClient(get_qradar_config())
    started = time.perf_counter()
    rows = client.run_aql(guard.query, max_rows=config["max_rows"]) or []
    duration_ms = int((time.perf_counter() - started) * 1000)
    siem_audit.record_aql_execution(
        query=guard.query,
        rewrites=guard.rewrites,
        row_count=len(rows),
        duration_ms=duration_ms,
    )
    return {"rows": rows, "duration_ms": duration_ms, "query": guard.query}, guard


def _execute_trellix(query, config):
    from integrations.edr.trellix_client import get_trellix_client
    from integrations.edr.trellix_guard import EdrQueryRejected

    client = get_trellix_client()
    started = time.perf_counter()
    try:
        rows = client.search_historical(
            query.query_text,
            hours=config["max_window_hours"],
            limit=config["max_rows"],
        ) or []
    except EdrQueryRejected as exc:
        siem_audit.record_blocked_query(
            target="trellix",
            query=query.query_text,
            reason=getattr(exc, "reason", "rejected"),
            detail=str(exc),
        )
        return None, exc
    duration_ms = int((time.perf_counter() - started) * 1000)
    siem_audit.record_edr_search(
        query=query.query_text,
        mode="historical",
        row_count=len(rows),
        duration_ms=duration_ms,
    )
    return {"rows": rows, "duration_ms": duration_ms, "query": query.query_text}, None


def execute_query(query, *, user=None):
    """Run one query read-only behind its guard. Never raises for a rejection."""
    config = get_hunting_config()
    if not config["allow_auto_mode"]:
        query.status = HuntQueryStatus.SKIPPED
        query.guard_rejection_reason = "Execution is disabled in runtime configuration."
        query.save()
        return query

    query.status = HuntQueryStatus.RUNNING
    query.executed_by = user if getattr(user, "is_authenticated", False) else None
    query.save(update_fields=["status", "executed_by", "updated_at"])

    try:
        with _search_slot(config):
            if query.target == HuntQueryTarget.QRADAR:
                result, guard = _execute_qradar(query, config)
                rejection = None if result else f"{guard.reason}: {guard.detail}"
            else:
                result, rejection_exc = _execute_trellix(query, config)
                rejection = None if result else str(rejection_exc)
    except HuntBudgetExceeded as exc:
        query.status = HuntQueryStatus.SKIPPED
        query.error = str(exc)
        query.save()
        return query
    except Exception as exc:  # noqa: BLE001 - a failed hunt query must not kill the plan
        query.status = HuntQueryStatus.FAILED
        query.error = f"{type(exc).__name__}: {exc}"[:2000]
        query.executed_at = timezone.now()
        query.save()
        logger.warning("Hunt query %s failed: %s", query.id, exc)
        return query

    if result is None:
        query.status = HuntQueryStatus.REJECTED
        query.guard_rejection_reason = rejection or "Rejected by the read-only guard."
        query.executed_at = timezone.now()
        query.save()
        return query

    rows = result["rows"]
    query.status = HuntQueryStatus.SUCCEEDED
    query.row_count = len(rows)
    query.sample_rows = _scrub_rows(rows, config["sample_row_limit"])
    query.duration_ms = result["duration_ms"]
    query.query_text = result["query"]
    query.executed_at = timezone.now()
    query.save()
    return query


def _valid_evidence(output, hypothesis):
    """Keep only references that point at a query belonging to this hypothesis."""
    known = {str(pk) for pk in hypothesis.queries.values_list("id", flat=True)}
    kept = []
    for item in output.evidence or []:
        reference = (item.reference or "").strip()
        if item.kind == "hunt_query" and reference in known:
            kept.append({"kind": item.kind, "reference": reference, "note": item.note or ""})
    return kept


def conclude_hypothesis(hypothesis):
    queries = list(hypothesis.queries.all())
    payload = build_finding_payload(hypothesis, queries)

    try:
        output, call = invoke_structured(
            system_prompt=read_prompt(FINDING_PROMPT_NAME),
            payload=payload,
            output_schema=HuntFindingOutput,
        )
    except Exception as exc:  # noqa: BLE001 - same reasoning as generate_plan
        logger.warning("Hunt finding generation failed for %s: %s", hypothesis.id, exc)
        return None

    evidence = _valid_evidence(output, hypothesis)
    conclusion = (output.conclusion or "").strip().lower()
    if conclusion not in {
        HuntConclusion.CONFIRMED,
        HuntConclusion.REFUTED,
        HuntConclusion.INCONCLUSIVE,
    }:
        conclusion = HuntConclusion.INCONCLUSIVE

    executed = [q for q in queries if q.status == HuntQueryStatus.SUCCEEDED]
    if conclusion == HuntConclusion.CONFIRMED and not evidence:
        conclusion = HuntConclusion.INCONCLUSIVE
    if conclusion == HuntConclusion.REFUTED and not executed:
        # Nothing ran, so nothing was disproved.
        conclusion = HuntConclusion.INCONCLUSIVE

    finding = HuntFinding.objects.create(
        hypothesis=hypothesis,
        conclusion=conclusion,
        summary=(output.summary or "").strip(),
        evidence=evidence,
        llm_call=_record_llm_call(
            "hunting.finding", call, source_type="hunt_hypothesis", source_id=hypothesis.id
        ),
    )
    hypothesis.status = {
        HuntConclusion.CONFIRMED: HuntHypothesisStatus.CONFIRMED,
        HuntConclusion.REFUTED: HuntHypothesisStatus.REFUTED,
    }.get(conclusion, HuntHypothesisStatus.INCONCLUSIVE)
    hypothesis.save(update_fields=["status", "updated_at"])

    # A settled hypothesis is worth remembering so the next hunt over the same
    # entities does not re-ask it. Failure here must not lose the finding.
    try:
        from apps.knowledge.curation import capture_from_hunt

        capture_from_hunt(finding)
    except Exception:  # noqa: BLE001
        logger.exception("Failed to capture hunt knowledge for hypothesis %s", hypothesis.id)

    return finding


def _plan_query_count(plan):
    return HuntQuery.objects.filter(hypothesis__plan=plan).count()


def _call_tokens(record):
    if record is None:
        return 0
    return (record.tokens_in or 0) + (record.tokens_out or 0)


def propose_followup_queries(hypothesis, finding, *, plan, config, iteration):
    """Ask for follow-up queries after an inconclusive round.

    Returning nothing is an accepted answer and ends the loop: another
    speculative query costs a real SIEM search and tells the analyst less than
    an honest "this cannot be settled with the telemetry available".
    """
    queries = list(hypothesis.queries.all())
    payload = build_refine_payload(
        hypothesis,
        queries,
        finding,
        iteration=iteration,
        max_window_hours=config["max_window_hours"],
        max_rows=config["max_rows"],
    )

    try:
        output, call = invoke_structured(
            system_prompt=read_prompt(REFINE_PROMPT_NAME),
            payload=payload,
            output_schema=HuntRefinementOutput,
        )
    except Exception as exc:  # noqa: BLE001 - same reasoning as generate_plan
        logger.warning("Hunt refinement failed for %s: %s", hypothesis.id, exc)
        return [], None

    record = _record_llm_call(
        "hunting.refine", call, source_type="hunt_hypothesis", source_id=hypothesis.id
    )

    remaining = config["max_queries_per_plan"] - _plan_query_count(plan)
    seen_text = {(query.query_text or "").strip().lower() for query in queries}
    position = max((query.position for query in queries), default=-1) + 1

    created = []
    for query_out in output.queries or []:
        if remaining <= 0:
            break
        target = (query_out.target or "").strip().lower()
        text = (query_out.query_text or "").strip()
        if target not in {HuntQueryTarget.QRADAR, HuntQueryTarget.TRELLIX} or not text:
            continue
        if text.lower() in seen_text:
            # The model re-proposed a query that already ran; running it again
            # would burn a search slot for a result we already have.
            continue
        seen_text.add(text.lower())
        created.append(
            HuntQuery.objects.create(
                hypothesis=hypothesis,
                target=target,
                query_text=text,
                purpose=(query_out.purpose or "").strip(),
                expected_evidence=(query_out.expected_evidence or "").strip(),
                negative_interpretation=(query_out.negative_interpretation or "").strip(),
                position=position,
            )
        )
        position += 1
        remaining -= 1

    return created, record


def run_plan(plan, *, user=None):
    """Execute an auto-mode plan, refining each hypothesis while it stays inconclusive.

    The loop is bounded twice over: by `max_iterations` per hypothesis and by the
    plan token ceiling. Either bound stops the plan and records which one did.
    """
    config = get_hunting_config()
    plan.status = HuntPlanStatus.RUNNING
    plan.save(update_fields=["status", "updated_at"])

    tokens_used = _call_tokens(plan.llm_call)
    max_tokens = config["max_tokens_per_plan"]
    max_iterations = max(1, config["max_iterations"])
    stop_reason = ""

    for hypothesis in plan.hypotheses.all():
        for iteration in range(1, max_iterations + 1):
            pending = [
                query
                for query in hypothesis.queries.all()
                if query.status == HuntQueryStatus.PENDING
            ]
            for query in pending:
                if tokens_used >= max_tokens:
                    stop_reason = (
                        f"Token ceiling of {max_tokens} reached during hypothesis "
                        f"{hypothesis.position}, iteration {iteration}."
                    )
                    break
                execute_query(query, user=user)
            if stop_reason:
                break

            finding = conclude_hypothesis(hypothesis)
            tokens_used += _call_tokens(getattr(finding, "llm_call", None))

            if finding is None or finding.conclusion != HuntConclusion.INCONCLUSIVE:
                break
            if iteration >= max_iterations:
                break
            if tokens_used >= max_tokens:
                stop_reason = f"Token ceiling of {max_tokens} reached before refining."
                break

            created, record = propose_followup_queries(
                hypothesis, finding, plan=plan, config=config, iteration=iteration
            )
            tokens_used += _call_tokens(record)
            if not created:
                break

        if stop_reason:
            break

    plan.status = HuntPlanStatus.BUDGET_EXHAUSTED if stop_reason else HuntPlanStatus.COMPLETED
    if stop_reason:
        plan.stop_reason = stop_reason
    plan.hypotheses_count = plan.hypotheses.count()
    plan.completed_at = timezone.now()
    plan.save()
    return plan
