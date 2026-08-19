"""Bounds for Trellix EDR searches.

Same shape as the QRadar AQL guard: mandatory and capped time range, capped
host and row counts, and rejection of query forms that would sweep the whole
estate. Rejections carry a machine-readable reason so a hunting loop can repair
and retry.
"""

import re
from dataclasses import dataclass

FORBIDDEN_PATTERNS = (
    (re.compile(r"^\s*\*\s*$"), "unbounded_wildcard"),
    (re.compile(r"\bdelete\b|\bremove\b|\bterminate\b", re.IGNORECASE), "write_operation"),
)

REASON_EMPTY = "empty_query"
REASON_WINDOW_TOO_WIDE = "time_window_too_wide"
REASON_WINDOW_MISSING = "time_window_missing"
REASON_TOO_MANY_HOSTS = "too_many_hosts"


@dataclass(frozen=True)
class EdrGuardResult:
    allowed: bool
    query: str = ""
    hours: float = 0.0
    limit: int = 0
    host_ids: tuple = ()
    reason: str = ""
    detail: str = ""
    rewrites: tuple = ()

    def raise_for_rejection(self):
        if not self.allowed:
            raise EdrQueryRejected(self.detail, reason=self.reason)
        return self.query


class EdrQueryRejected(ValueError):
    def __init__(self, message, *, reason):
        super().__init__(message)
        self.reason = reason


def guard_edr_search(query, *, hours=None, limit=None, host_ids=(), config=None, max_hosts=200):
    if config is None:
        from apps.settings.runtime_config import get_trellix_config

        config = get_trellix_config()

    text = str(query or "").strip()
    if not text:
        return EdrGuardResult(allowed=False, reason=REASON_EMPTY, detail="EDR query is empty.")

    for pattern, reason in FORBIDDEN_PATTERNS:
        if pattern.search(text):
            return EdrGuardResult(
                allowed=False,
                reason=reason,
                detail=f"EDR query rejected: {reason.replace('_', ' ')}.",
            )

    rewrites = []
    max_hours = config["max_window_hours"]
    if hours is None:
        hours = max_hours
        rewrites.append(f"applied default window of {max_hours}h")
    if hours <= 0:
        return EdrGuardResult(
            allowed=False,
            reason=REASON_WINDOW_MISSING,
            detail="EDR query requires a positive time window.",
        )
    if hours > max_hours:
        return EdrGuardResult(
            allowed=False,
            reason=REASON_WINDOW_TOO_WIDE,
            detail=f"Time window of {hours:g}h exceeds the configured maximum of {max_hours}h.",
        )

    hosts = tuple(str(item) for item in (host_ids or []) if str(item).strip())
    if len(hosts) > max_hosts:
        return EdrGuardResult(
            allowed=False,
            reason=REASON_TOO_MANY_HOSTS,
            detail=f"EDR query targets {len(hosts)} hosts, above the {max_hosts} host ceiling.",
        )

    max_rows = config["max_rows"]
    effective_limit = min(limit or max_rows, max_rows)
    if limit and limit > max_rows:
        rewrites.append(f"reduced limit from {limit} to {max_rows}")

    return EdrGuardResult(
        allowed=True,
        query=text,
        hours=float(hours),
        limit=effective_limit,
        host_ids=hosts,
        rewrites=tuple(rewrites),
    )
