"""Prompt loading and payload construction for hunt plans.

Prompts live under `custom/data/hunting/` so an SHB analyst can revise the
hunting instructions without a code change, the same way module and playbook
prompts work.
"""

from pathlib import Path

from django.conf import settings

from apps.settings.runtime_config import get_prompt_language

PROMPT_DIRECTORY = "hunting"
PLAN_PROMPT_NAME = "System"
FINDING_PROMPT_NAME = "Finding"
REFINE_PROMPT_NAME = "Refine"

MAX_ENTITY_VALUES = 20
MAX_CASES_IN_PAYLOAD = 25
MAX_SAMPLE_ROWS = 5


def prompt_path(name, language=None):
    language = language or get_prompt_language()
    return (
        Path(settings.CUSTOM_DIR)
        / "data"
        / PROMPT_DIRECTORY
        / f"{name}_{language}.md"
    )


def read_prompt(name):
    for language in (get_prompt_language(), "en"):
        path = prompt_path(name, language)
        if path.exists():
            return path.read_text(encoding="utf-8")
    raise FileNotFoundError(f"Hunting prompt not found: {prompt_path(name, 'en')}")


def _trim(values, limit):
    values = list(values or [])
    return values[:limit]


def build_plan_payload(cluster, *, max_window_hours, max_rows):
    """Cluster plus triage context, trimmed to a configurable budget."""
    from apps.agentic.models import IncidentClusterMember

    members = (
        IncidentClusterMember.objects.filter(cluster=cluster)
        .select_related("case")
        .order_by("joined_at")[:MAX_CASES_IN_PAYLOAD]
    )

    cases = []
    for member in members:
        case = member.case
        if case is None:
            continue
        triage = case.triage_results.first() if hasattr(case, "triage_results") else None
        cases.append(
            {
                "case_id": case.case_id,
                "title": (case.title or "")[:200],
                "severity": getattr(case, "severity", ""),
                "verdict_ai": getattr(case, "verdict_ai", ""),
                "created_at": case.created_at.isoformat(),
                "mitre_techniques": _trim(getattr(triage, "mitre_techniques", None), 8),
                "mitre_tactics": _trim(getattr(triage, "mitre_tactics", None), 8),
            }
        )

    entities = {
        kind: _trim(values, MAX_ENTITY_VALUES)
        for kind, values in (cluster.primary_entities or {}).items()
    }

    return {
        "cluster": {
            "cluster_id": cluster.cluster_id,
            "title": cluster.title,
            "window_start": cluster.window_start.isoformat(),
            "window_end": cluster.window_end.isoformat(),
            "link_score": cluster.link_score,
            "case_count": cluster.case_count,
            "alert_count": cluster.alert_count,
        },
        "primary_entities": entities,
        "cases": cases,
        "constraints": {
            "max_window_hours": max_window_hours,
            "max_rows": max_rows,
            "qradar_dialect": "AQL, SELECT only, FROM events or flows, with LAST <n> HOURS and LIMIT",
            "trellix_dialect": "Trellix EDR real-time or historical search expression",
        },
    }


def build_finding_payload(hypothesis, queries):
    return {
        "hypothesis": {
            "statement": hypothesis.statement,
            "mitre_technique": hypothesis.mitre_technique,
            "rationale": hypothesis.rationale,
        },
        "queries": [
            {
                "hunt_query_id": str(query.id),
                "target": query.target,
                "query_text": query.query_text,
                "purpose": query.purpose,
                "expected_evidence": query.expected_evidence,
                "negative_interpretation": query.negative_interpretation,
                "status": query.status,
                "row_count": query.row_count,
                "guard_rejection_reason": query.guard_rejection_reason,
                "sample_rows": _trim(query.sample_rows, MAX_SAMPLE_ROWS),
            }
            for query in queries
        ],
    }


def build_refine_payload(hypothesis, queries, finding, *, iteration, max_window_hours, max_rows):
    """Context for one refinement round: what was asked, what came back, why it was inconclusive."""
    return {
        "iteration": iteration,
        "hypothesis": {
            "statement": hypothesis.statement,
            "mitre_technique": hypothesis.mitre_technique,
            "rationale": hypothesis.rationale,
        },
        "previous_conclusion": {
            "conclusion": getattr(finding, "conclusion", ""),
            "summary": getattr(finding, "summary", ""),
        },
        "queries_already_run": [
            {
                "target": query.target,
                "query_text": query.query_text,
                "status": query.status,
                "row_count": query.row_count,
                "guard_rejection_reason": query.guard_rejection_reason,
                "sample_rows": _trim(query.sample_rows, MAX_SAMPLE_ROWS),
            }
            for query in queries
        ],
        "constraints": {
            "max_window_hours": max_window_hours,
            "max_rows": max_rows,
            "qradar_dialect": "AQL, SELECT only, FROM events or flows, with LAST <n> HOURS and LIMIT",
            "trellix_dialect": "Trellix EDR real-time or historical search expression",
        },
    }
