from django.core.management.base import BaseCommand

from apps.agentic.correlation.service import run_correlation_once
from apps.common.worker_runner import add_worker_arguments, run_worker
from apps.settings.runtime_config import get_clustering_config

DEFAULT_INTERVAL_SECONDS = 300.0


def _default_interval():
    return get_clustering_config()["poll_interval_seconds"] or DEFAULT_INTERVAL_SECONDS


class Command(BaseCommand):
    help = "Group Cases and Alerts into incident clusters by shared entity, time proximity and MITRE tactic."

    def add_arguments(self, parser):
        add_worker_arguments(parser, interval_help="Seconds between clustering passes.")

    def handle(self, *args, **options):
        run_worker(
            self,
            options=options,
            worker_name="agentic correlation",
            worker_type="agentic-correlation",
            run_once=run_correlation_once,
            default_interval=_default_interval,
            log_role="agentic-correlation-worker",
        )
