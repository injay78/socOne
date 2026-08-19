from django.core.management.base import BaseCommand, CommandError

from apps.common.worker_runner import SLEEP_WHEN_IDLE, add_worker_arguments, run_worker
from apps.settings.runtime_config import get_qradar_config
from apps.webhook.qradar_poller import DEFAULT_BATCH_SIZE, poll_offenses_once, reset_watermark

DEFAULT_INTERVAL_SECONDS = 60.0


class Command(BaseCommand):
    help = "Poll QRadar offences and write them into Redis streams named after the detection rule."

    def add_arguments(self, parser):
        add_worker_arguments(parser, interval_help="Seconds to sleep when no new offence is available.")
        parser.add_argument("--batch-size", type=int, help="Maximum offences fetched per poll.")
        parser.add_argument("--since", type=int, help="Override the watermark with a QRadar epoch-millis value.")
        parser.add_argument("--reset-watermark", action="store_true", help="Clear the stored watermark before running.")

    def handle(self, *args, **options):
        batch_size = options.get("batch_size") or DEFAULT_BATCH_SIZE
        if batch_size <= 0:
            raise CommandError("--batch-size must be greater than 0.")

        if options.get("reset_watermark"):
            reset_watermark()
            self.stdout.write("QRadar offence watermark cleared.")

        since = options.get("since")

        def process_once():
            nonlocal since
            result = poll_offenses_once(batch_size=batch_size, since=since)
            since = None
            return result

        run_worker(
            self,
            options=options,
            worker_name="QRadar offense",
            worker_type="qradar-offense",
            run_once=process_once,
            default_interval=lambda: _configured_interval(),
            sleep_policy=SLEEP_WHEN_IDLE,
            started_message="QRadar offense worker started",
            stopped_message="QRadar offense worker stopped.",
            sleep_seconds=lambda: _configured_interval(),
            log_role="qradar-offense-worker",
        )


def _configured_interval():
    try:
        return float(get_qradar_config()["poll_interval_seconds"]) or DEFAULT_INTERVAL_SECONDS
    except Exception:
        return DEFAULT_INTERVAL_SECONDS
