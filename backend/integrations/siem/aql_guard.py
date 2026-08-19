"""Read-only guard for AQL statements executed against QRadar.

Every statement, hand-written or model-generated, passes through `guard_aql`
before it reaches the client. Rejections carry a machine-readable reason so a
hunting loop can repair the query and retry instead of failing blind.
"""

import re
from dataclasses import dataclass

SELECT_RE = re.compile(r"^\s*SELECT\s", re.IGNORECASE)
FROM_RE = re.compile(r"\bFROM\s+(events|flows)\b", re.IGNORECASE)
LIMIT_RE = re.compile(r"\bLIMIT\s+(\d+)\b", re.IGNORECASE)
LAST_RE = re.compile(r"\bLAST\s+(\d+)\s+(MINUTES?|HOURS?|DAYS?)\b", re.IGNORECASE)
START_STOP_RE = re.compile(r"\bSTART\b.+?\bSTOP\b", re.IGNORECASE | re.DOTALL)
LINE_COMMENT_RE = re.compile(r"--[^\n]*")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

FORBIDDEN_KEYWORDS = (
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "CREATE",
    "ALTER",
    "TRUNCATE",
    "GRANT",
    "REVOKE",
    "EXEC",
    "CALL",
    "MERGE",
    "REPLACE",
    "INTO",
)

REASON_NOT_SELECT = "not_select"
REASON_BAD_SOURCE = "unsupported_source"
REASON_FORBIDDEN_KEYWORD = "forbidden_keyword"
REASON_MULTI_STATEMENT = "multiple_statements"
REASON_WINDOW_TOO_WIDE = "time_window_too_wide"
REASON_EMPTY = "empty_query"


@dataclass(frozen=True)
class AqlGuardResult:
    allowed: bool
    query: str = ""
    reason: str = ""
    detail: str = ""
    rewrites: tuple = ()

    def raise_for_rejection(self):
        if not self.allowed:
            raise AqlRejected(self.detail, reason=self.reason)
        return self.query


class AqlRejected(ValueError):
    def __init__(self, message, *, reason):
        super().__init__(message)
        self.reason = reason


def _strip_comments(query):
    return BLOCK_COMMENT_RE.sub(" ", LINE_COMMENT_RE.sub(" ", query))


def _window_hours(query):
    match = LAST_RE.search(query)
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2).upper()
    if unit.startswith("MINUTE"):
        return amount / 60
    if unit.startswith("HOUR"):
        return float(amount)
    return amount * 24.0


def guard_aql(query, *, max_rows, default_window_minutes, max_window_hours):
    """Normalise an AQL statement or explain why it is not allowed to run."""
    raw = _strip_comments(str(query or "")).strip().rstrip(";").strip()
    if not raw:
        return AqlGuardResult(allowed=False, reason=REASON_EMPTY, detail="AQL query is empty.")

    if ";" in raw:
        return AqlGuardResult(
            allowed=False,
            reason=REASON_MULTI_STATEMENT,
            detail="Only a single AQL statement may be executed.",
        )

    if not SELECT_RE.match(raw):
        return AqlGuardResult(
            allowed=False,
            reason=REASON_NOT_SELECT,
            detail="Only SELECT statements are allowed.",
        )

    upper = raw.upper()
    for keyword in FORBIDDEN_KEYWORDS:
        if re.search(rf"\b{keyword}\b", upper):
            return AqlGuardResult(
                allowed=False,
                reason=REASON_FORBIDDEN_KEYWORD,
                detail=f"AQL keyword {keyword} is not allowed on a read-only connection.",
            )

    if not FROM_RE.search(raw):
        return AqlGuardResult(
            allowed=False,
            reason=REASON_BAD_SOURCE,
            detail="Only FROM events or FROM flows is allowed.",
        )

    rewrites = []
    normalized = raw

    has_explicit_range = bool(START_STOP_RE.search(normalized))
    window = _window_hours(normalized)
    if not has_explicit_range and window is None:
        normalized = f"{normalized} LAST {int(default_window_minutes)} MINUTES"
        rewrites.append(f"added default window of {int(default_window_minutes)} minutes")
    elif window is not None and window > max_window_hours:
        return AqlGuardResult(
            allowed=False,
            reason=REASON_WINDOW_TOO_WIDE,
            detail=f"Time window of {window:g}h exceeds the configured maximum of {max_window_hours}h.",
        )

    limit_match = LIMIT_RE.search(normalized)
    if limit_match:
        requested = int(limit_match.group(1))
        if requested > max_rows:
            normalized = LIMIT_RE.sub(f"LIMIT {max_rows}", normalized, count=1)
            rewrites.append(f"reduced LIMIT from {requested} to {max_rows}")
    else:
        normalized = f"{normalized} LIMIT {max_rows}"
        rewrites.append(f"added LIMIT {max_rows}")

    return AqlGuardResult(allowed=True, query=normalized, rewrites=tuple(rewrites))


def guard_aql_with_config(query, config=None):
    """Guard using the current QRadar runtime configuration."""
    if config is None:
        from apps.settings.runtime_config import get_qradar_config

        config = get_qradar_config()
    return guard_aql(
        query,
        max_rows=config["max_rows"],
        default_window_minutes=config["default_window_minutes"],
        max_window_hours=config["max_window_hours"],
    )
