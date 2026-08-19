import logging

from django.utils import timezone

from apps.agentic.analysis.analysis import run_case_analysis
from apps.agentic.models import AgenticJobStatus, CaseAnalysisJob
from apps.agentic.services.cases import (
    complete_case_analysis_job,
    fail_case_analysis_job,
    start_case_analysis_job,
)
from apps.agentic.services.playbooks import (
    claim_pending_playbook_run,
    find_playbook_class,
    mark_playbook_failed,
    mark_playbook_success,
)

logger = logging.getLogger(__name__)


def run_playbook_once(*, scripts_dir=None):
    playbook_run = claim_pending_playbook_run()
    if playbook_run is None:
        return False

    try:
        playbook_class = find_playbook_class(playbook_run.name, scripts_dir=scripts_dir)
        result = playbook_class(playbook_run=playbook_run).run()
        mark_playbook_success(playbook_run, str(result))
    except Exception as exc:
        mark_playbook_failed(playbook_run, exc)
        return True

    return True


def run_case_analysis_once():
    job = (
        CaseAnalysisJob.objects.filter(
            status=AgenticJobStatus.PENDING,
            scheduled_at__lte=timezone.now(),
        )
        .order_by("scheduled_at", "created_at")
        .first()
    )
    if job is None:
        return False

    running_job = start_case_analysis_job(job)
    try:
        result = run_case_analysis(
            case=running_job.case,
            trigger=running_job.trigger,
            source=running_job,
        )
        complete_case_analysis_job(
            running_job,
            result_json=result.analysis_record,
        )
    except Exception as exc:
        fail_case_analysis_job(running_job, str(exc))
    return True


def _run_triage(running_job):
    """Triage runs inside the same job as the investigation.

    A triage failure must not discard a completed investigation, so it is
    logged and the job still completes.
    """
    from apps.agentic.triage.service import run_case_triage

    try:
        run_case_triage(running_job.case, trigger=running_job.trigger or "analysis")
    except Exception:
        logger.exception("AI triage failed for case %s", running_job.case_id)
