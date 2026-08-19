from django.core.management.base import BaseCommand, CommandError

from apps.common.worker_runner import SLEEP_WHEN_IDLE, add_worker_arguments, run_worker
from apps.notifications.delivery import BATCH_SIZE, deliver_once

DEFAULT_INTERVAL_SECONDS = 10.0


class Command(BaseCommand):
    help = "Deliver queued notifications to their configured channels."

    def add_arguments(self, parser):
        add_worker_arguments(parser, interval_help="Seconds to sleep when the outbox is empty.")
        parser.add_argument("--batch-size", type=int, help="Maximum messages claimed per iteration.")

    def handle(self, *args, **options):
        batch_size = options.get("batch_size") or BATCH_SIZE
        if batch_size <= 0:
            raise CommandError("--batch-size must be greater than 0.")

        run_worker(
            self,
            options=options,
            worker_name="notification",
            worker_type="notification",
            run_once=lambda: deliver_once(batch_size),
            default_interval=DEFAULT_INTERVAL_SECONDS,
            sleep_policy=SLEEP_WHEN_IDLE,
            started_message="Notification worker started",
            stopped_message="Notification worker stopped.",
            log_role="notification-worker",
        )
