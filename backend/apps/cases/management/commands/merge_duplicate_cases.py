"""Merge Cases that the old bucket-based correlation split apart.

Cases created before correlation moved to a sliding window carry a
time-bucketed `correlation_uid`, so one recurring behaviour on one host became
several Cases. This command regroups them by the key correlation uses now —
product, rule and host — and folds each group into its earliest Case.

Dry run by default. Nothing moves until `--apply` is passed.
"""

from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.agentic.runtime.base import correlation_identity
from apps.alerts.models import Alert
from apps.cases.models import Case, CaseRelationship, CaseRelationshipType, CaseStatus

OPEN_STATUSES = (CaseStatus.NEW, CaseStatus.IN_PROGRESS, CaseStatus.ON_HOLD)
MERGE_NOTE = "Merged into {case_id} by merge_duplicate_cases: same rule and host."


def _hostname_of(case):
    for alert in case.alerts.all():
        for artifact in alert.artifacts.all():
            if str(getattr(artifact, "type", "")).strip().lower() == "hostname":
                return str(artifact.value).strip().lower()
    return ""


def _group_key(case):
    """The key correlation would produce for this Case today."""
    alert = case.alerts.order_by("created_at").first()
    if alert is None:
        return None

    hostname = _hostname_of(case)
    if not hostname:
        return None

    # Trellix: detections of one threat carry different rule tags, so the key
    # is threat + host — the exact formula custom/modules/trellix_generic.py
    # uses at ingest time.
    threat_id = str((alert.unmapped or {}).get("trellix_threat_id") or "").strip()
    if threat_id:
        return correlation_identity(rule_id=f"trellix:{threat_id}", keys=[hostname])

    rule = str(getattr(alert, "rule_name", "") or "").strip().lower()
    product = str(getattr(alert, "product_name", "") or "").strip().lower()
    if not rule:
        return None

    return correlation_identity(rule_id=f"{product}:{rule}", keys=[hostname])


class Command(BaseCommand):
    help = "Merge Cases split by the old time-bucketed correlation key."

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Perform the merge. Without this the command only reports.")
        parser.add_argument("--limit", type=int, help="Process at most this many groups.")
        parser.add_argument("--product", help="Only consider Cases whose alerts come from this product name.")

    def handle(self, *args, **options):
        limit = options.get("limit")
        if limit is not None and limit <= 0:
            raise CommandError("--limit must be greater than 0.")

        queryset = (
            Case.objects.filter(status__in=OPEN_STATUSES)
            .prefetch_related("alerts__artifacts")
            .order_by("created_at")
        )
        product = options.get("product")
        if product:
            queryset = queryset.filter(alerts__product_name__iexact=product).distinct()

        groups = defaultdict(list)
        for case in queryset:
            key = _group_key(case)
            if key:
                groups[key].append(case)

        duplicates = {key: cases for key, cases in groups.items() if len(cases) > 1}
        if limit:
            duplicates = dict(list(duplicates.items())[:limit])

        # Cases whose stored uid no longer matches the current formula would
        # never receive another alert; refresh them even when nothing merges.
        rekeyed = 0
        for key, cases in groups.items():
            survivor = cases[0]
            if survivor.correlation_uid != key:
                rekeyed += 1
                if options["apply"]:
                    Case.objects.filter(pk=survivor.pk).update(correlation_uid=key, updated_at=timezone.now())
        if rekeyed:
            verb = "Rekeyed" if options["apply"] else "Would rekey"
            self.stdout.write(f"{verb} correlation_uid on {rekeyed} surviving Case(s).")

        if not duplicates:
            self.stdout.write("No duplicate Case groups found.")
            return

        total_merged = 0
        total_alerts = 0
        for key, cases in duplicates.items():
            survivor, *rest = cases
            alert_count = Alert.objects.filter(case__in=[case.pk for case in rest]).count()
            total_merged += len(rest)
            total_alerts += alert_count

            self.stdout.write(
                f"{survivor.case_id} <- {', '.join(case.case_id for case in rest)} "
                f"({alert_count} alert(s), key {key[:14]})"
            )
            if options["apply"]:
                self._merge(survivor, rest)

        verb = "Merged" if options["apply"] else "Would merge"
        self.stdout.write(
            self.style.SUCCESS(
                f"{verb} {total_merged} Case(s) carrying {total_alerts} alert(s) "
                f"into {len(duplicates)} surviving Case(s)."
            )
        )
        if not options["apply"]:
            self.stdout.write("Dry run only. Re-run with --apply to perform the merge.")

    @transaction.atomic
    def _merge(self, survivor, duplicates):
        """Move alerts onto the survivor and close each duplicate with a trail."""
        locked = Case.objects.select_for_update().get(pk=survivor.pk)

        for duplicate in duplicates:
            locked_duplicate = Case.objects.select_for_update().get(pk=duplicate.pk)
            Alert.objects.filter(case=locked_duplicate).update(case=locked)

            # Keep the link so an analyst can still find the original record.
            CaseRelationship.objects.get_or_create(
                source_case=locked_duplicate,
                target_case=locked,
                relationship_type=CaseRelationshipType.DUPLICATE_OF,
                defaults={"note": MERGE_NOTE.format(case_id=locked.case_id)[:500]},
            )

            locked_duplicate.status = CaseStatus.CLOSED
            locked_duplicate.description = (
                f"{locked_duplicate.description}\n\n{MERGE_NOTE.format(case_id=locked.case_id)}"
            ).strip()
            locked_duplicate.save(update_fields=["status", "description", "updated_at"])

        locked.updated_at = timezone.now()
        locked.save(update_fields=["updated_at"])
