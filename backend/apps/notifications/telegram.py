"""Telegram Bot API transport."""

import logging

import httpx

logger = logging.getLogger(__name__)

API_BASE = "https://api.telegram.org"
DEFAULT_TIMEOUT_SECONDS = 20


class TelegramError(RuntimeError):
    def __init__(self, message, *, status_code=None, retry_after=None, description=""):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after
        self.description = description


class TelegramRateLimited(TelegramError):
    pass


def send_message(*, bot_token, chat_id, text, message_thread_id="", timeout=DEFAULT_TIMEOUT_SECONDS):
    if not bot_token:
        raise TelegramError("Telegram bot token is not configured.")
    if not chat_id:
        raise TelegramError("Telegram chat id is not configured.")

    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if message_thread_id:
        payload["message_thread_id"] = message_thread_id

    url = f"{API_BASE}/bot{bot_token}/sendMessage"
    try:
        with httpx.Client(timeout=timeout, trust_env=False) as client:
            response = client.post(url, json=payload)
    except httpx.HTTPError as exc:
        raise TelegramError(f"Telegram request failed: {type(exc).__name__}") from exc

    try:
        body = response.json()
    except ValueError:
        body = {}

    description = str(body.get("description") or response.text[:200])

    if response.status_code == 429:
        retry_after = (body.get("parameters") or {}).get("retry_after")
        raise TelegramRateLimited(
            f"Telegram rate limited: {description}",
            status_code=429,
            retry_after=retry_after,
            description=description,
        )

    if not response.is_success or not body.get("ok", False):
        raise TelegramError(
            f"Telegram returned HTTP {response.status_code}: {description}",
            status_code=response.status_code,
            description=description,
        )

    return body.get("result") or {}


def describe_error(exc):
    """Turn a Telegram failure into something a person can act on."""
    description = (getattr(exc, "description", "") or str(exc)).lower()
    if "unauthorized" in description:
        return "Bot token is invalid or revoked."
    if "chat not found" in description:
        return "Chat id not found. Add the bot to the channel or group first."
    if "not enough rights" in description or "have no rights" in description:
        return "The bot lacks permission to post in this chat."
    if "message thread not found" in description or "topic" in description:
        return "Topic id not found in this group."
    if "bot was kicked" in description or "bot is not a member" in description:
        return "The bot is not a member of this chat."
    return str(exc)
