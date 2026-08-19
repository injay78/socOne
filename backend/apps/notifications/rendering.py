"""Message rendering for outbound notifications.

Every dynamic value is HTML-escaped: hostnames, usernames, analyst notes and
IOCs are all uncontrolled input, and indicators routinely carry characters that
break formatting. Templates live under custom/data/notifications so SHB can
edit them without a deployment.
"""

import html
import logging
import re
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

TELEGRAM_MAX_LENGTH = 4096
TRUNCATION_SUFFIX_EN = "\n\n… see details in ASP"
TRUNCATION_SUFFIX_VI = "\n\n… xem chi tiết trên ASP"
# {{{var}}} substitutes pre-built, already-escaped HTML verbatim (title link,
# missing-fields block); {{var}} escapes the value. Raw must match first.
RAW_PLACEHOLDER_RE = re.compile(r"\{\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}\}")
PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")
COMMENT_RE = re.compile(r"<!--.*?-->\n?", re.DOTALL)
OPEN_TAG_RE = re.compile(r"<(/?)([a-zA-Z]+)[^>]*>")

TEMPLATE_DIRECTORY = "notifications"


def template_path(event_type, language):
    return Path(settings.CUSTOM_DIR) / "data" / TEMPLATE_DIRECTORY / f"{event_type}_{language}.md"


def read_template(event_type, language):
    for candidate_language in (language, "en"):
        path = template_path(event_type, candidate_language)
        if path.exists():
            return path.read_text(encoding="utf-8")
    return None


def _lookup(payload, dotted_key):
    node = payload
    for part in dotted_key.split("."):
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return ""
        if node is None:
            return ""
    if isinstance(node, (list, tuple)):
        return ", ".join(str(item) for item in node)
    return str(node)


def render_template(template, payload):
    """Substitute placeholders, escaping every substituted value.

    Template comments (<!-- ... -->) are stripped so guidance for editors —
    e.g. the do-not-translate term list — never reaches the chat.
    """
    template = COMMENT_RE.sub("", template)

    def replace_raw(match):
        # Trusted pre-built HTML from the payload builder; values inside were
        # escaped at build time.
        return _lookup(payload, match.group(1))

    def replace(match):
        value = _lookup(payload, match.group(1))
        return html.escape(value, quote=False)

    template = RAW_PLACEHOLDER_RE.sub(replace_raw, template)
    return PLACEHOLDER_RE.sub(replace, template)


def _unclosed_tag_safe_cut(text, limit):
    """Cut without splitting an HTML tag or leaving one unbalanced."""
    cut = text[:limit]
    last_open = cut.rfind("<")
    last_close = cut.rfind(">")
    if last_open > last_close:
        cut = cut[:last_open]

    open_tags = []
    for match in OPEN_TAG_RE.finditer(cut):
        closing, name = match.group(1), match.group(2).lower()
        if closing:
            if open_tags and open_tags[-1] == name:
                open_tags.pop()
        else:
            open_tags.append(name)
    for name in reversed(open_tags):
        cut += f"</{name}>"
    return cut


def truncate(text, language="vi", limit=TELEGRAM_MAX_LENGTH):
    if len(text) <= limit:
        return text
    suffix = TRUNCATION_SUFFIX_VI if language == "vi" else TRUNCATION_SUFFIX_EN
    return _unclosed_tag_safe_cut(text, limit - len(suffix)) + suffix


def scrub(text):
    from apps.agentic.services.playbooks import _sanitize_visible_text

    return _sanitize_visible_text(text, max_length=TELEGRAM_MAX_LENGTH * 2)


def render_message(event_type, payload, *, language="vi"):
    """Render one event into Telegram-ready HTML."""
    template = read_template(event_type, language)
    if template is None:
        logger.warning("No notification template for %s (%s); using fallback", event_type, language)
        template = _fallback_template(event_type)

    body = render_template(template, payload)
    return truncate(scrub(body).strip(), language=language)


def _fallback_template(event_type):
    return (
        f"<b>{html.escape(event_type)}</b>\n"
        "{{ title }}\n"
        "{{ link }}"
    )


AGGREGATE_TOP_CASES = 5


def render_aggregate(event_type, payloads, *, language="vi"):
    """Collapse a burst of same-type events into one summary message.

    An alert storm that fires hundreds of messages makes the channel useless,
    so aggregation is a hard requirement rather than an option. Format: one
    header, the first few cases as links, a remainder count, a dashboard link.
    """
    count = len(payloads)
    window_minutes = max(1, int(payloads[0].get("aggregation_window_seconds") or 300) // 60)
    dashboard_url = str(payloads[0].get("dashboard_url") or "")

    lines = []
    if language == "vi":
        lines.append(f"🔴 <b>{count} alert mới</b> trong {window_minutes} phút\n")
    else:
        lines.append(f"🔴 <b>{count} new alerts</b> within {window_minutes} minutes\n")

    for payload in payloads[:AGGREGATE_TOP_CASES]:
        case_id = html.escape(str(payload.get("case_id") or "?"), quote=False)
        rule = html.escape(str(payload.get("rule_name") or payload.get("title") or ""), quote=False)
        host = html.escape(str(payload.get("hostname") or ""), quote=False)
        verdict = html.escape(str(payload.get("verdict") or ""), quote=False)
        confidence = payload.get("confidence")
        case_url = str(payload.get("case_url") or "")
        label = f"{case_id}"
        if case_url:
            label = f'<a href="{case_url}">{case_id}</a>'
        detail = f"{rule} on {host}" if host else rule
        suffix = f" ({verdict}, {confidence})" if verdict else ""
        lines.append(f"• {label} — {detail}{suffix}")

    remaining = count - AGGREGATE_TOP_CASES
    if remaining > 0:
        lines.append(f"… và {remaining} alert khác" if language == "vi" else f"… and {remaining} more alerts")

    if dashboard_url:
        label = "Xem tất cả" if language == "vi" else "View all"
        lines.append(f'\n{label}: <a href="{dashboard_url}">Dashboard</a>')

    return truncate("\n".join(lines), language=language)
