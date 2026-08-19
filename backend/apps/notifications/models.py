from django.db import models

from apps.common.models import BaseModel
from apps.notifications.events import NotificationEvent


class NotificationChannel(models.TextChoices):
    TELEGRAM = "telegram", "Telegram"


class NotificationDestination(BaseModel):
    name = models.CharField(max_length=100, unique=True)
    channel = models.CharField(
        max_length=20, choices=NotificationChannel, default=NotificationChannel.TELEGRAM
    )
    chat_id = models.CharField(
        max_length=100,
        help_text="Telegram chat id. Channels look like -1001234567890.",
    )
    message_thread_id = models.CharField(
        max_length=50,
        blank=True,
        default="",
        help_text="Topic id inside a forum group. Leave empty for a plain chat or channel.",
    )
    language = models.CharField(max_length=10, default="vi")
    enabled = models.BooleanField(default=True, db_index=True)
    event_types = models.JSONField(default=list, blank=True)
    min_severity = models.CharField(max_length=20, blank=True, default="")
    min_confidence = models.FloatField(default=0.0)
    verdict_filter = models.JSONField(default=list, blank=True)
    source_filter = models.JSONField(default=list, blank=True)
    min_asset_criticality = models.CharField(max_length=20, blank=True, default="")

    class Meta:
        db_table = "notification_destinations"
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.chat_id})"

    def subscribes_to(self, event_type):
        return not self.event_types or event_type in self.event_types


class OutboxStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    SENT = "sent", "Sent"
    FAILED = "failed", "Failed"
    SUPPRESSED = "suppressed", "Suppressed"


class NotificationOutbox(BaseModel):
    event_type = models.CharField(max_length=50, choices=NotificationEvent, db_index=True)
    destination = models.ForeignKey(
        NotificationDestination,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="messages",
    )
    payload = models.JSONField(default=dict, blank=True)
    rendered_text = models.TextField(blank=True, default="")
    status = models.CharField(
        max_length=20, choices=OutboxStatus, default=OutboxStatus.PENDING, db_index=True
    )
    attempts = models.PositiveSmallIntegerField(default=0)
    last_error = models.TextField(blank=True, default="")
    aggregated_count = models.PositiveIntegerField(default=1)
    dedup_key = models.CharField(max_length=128, blank=True, default="", db_index=True)
    scheduled_for = models.DateTimeField(null=True, blank=True, db_index=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "notification_outbox"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "scheduled_for"], name="outbox_status_sched_idx"),
        ]

    def __str__(self):
        return f"{self.event_type} -> {self.destination_id} [{self.status}]"
