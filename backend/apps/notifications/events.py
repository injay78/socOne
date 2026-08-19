"""Registered notification events.

Only registered names may be emitted, and destinations subscribe by name. The
Agent API refuses anything outside this catalogue so the endpoint cannot be
used to inject arbitrary messages into a channel.
"""

from django.db import models


class NotificationEvent(models.TextChoices):
    TRIAGE_COMPLETED = "triage.completed", "Triage completed"
    TRIAGE_NEEDS_HUMAN = "triage.needs_human", "Triage needs human review"
    DISCOVERY_CREATED = "discovery.created", "Attack discovery created"
    HUNT_FINDING_CONFIRMED = "hunt.finding_confirmed", "Hunt finding confirmed"
    AUDIT_CRITICAL_FINDING = "audit.critical_finding", "Critical MSSP audit finding"
    WORKER_UNHEALTHY = "system.worker_unhealthy", "Worker unhealthy"
    MSSP_SYNC_FAILED = "mssp.sync_failed", "MSSP sync failed"
    INTEGRATION_AUTH_FAILED = "integration.auth_failed", "Integration authentication failed"


# Events emitted by capabilities that ship in this release. The rest are
# registered so destinations can subscribe ahead of S4, S5 and S7 landing.
IMPLEMENTED_EVENTS = {
    NotificationEvent.TRIAGE_COMPLETED,
    NotificationEvent.TRIAGE_NEEDS_HUMAN,
    NotificationEvent.WORKER_UNHEALTHY,
    NotificationEvent.INTEGRATION_AUTH_FAILED,
}

CRITICAL_EVENTS = {
    NotificationEvent.AUDIT_CRITICAL_FINDING,
    NotificationEvent.WORKER_UNHEALTHY,
    NotificationEvent.INTEGRATION_AUTH_FAILED,
}

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


def severity_rank(value):
    try:
        return SEVERITY_ORDER.index(str(value or "").title())
    except ValueError:
        return -1
