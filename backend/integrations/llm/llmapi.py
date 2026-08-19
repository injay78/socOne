import logging
import time

import httpx
from django.core.cache import caches
from langchain_openai import ChatOpenAI

from apps.settings.runtime_config import get_llm_configs

logger = logging.getLogger(__name__)

# A provider that just failed with a quota/availability error is skipped for
# this long so the drip of retries goes straight to the next model instead of
# re-burning the dead one. Ignored when every candidate is cooling down.
COOLDOWN_SECONDS = 120
COOLDOWN_CACHE_KEY = "asp:llm:cooldown:{name}"

_QUOTA_MARKERS = (
    "error code: 429",
    "http/1.1 429",
    "[429]",
    "too many requests",
    "rate limit",
    "rate_limit",
    "usage limit",
    "quota",
    "insufficient_quota",
    "overloaded",
    "error code: 500",
    "error code: 502",
    "error code: 503",
    "service unavailable",
    "connection error",
    "timed out",
    "timeout",
)


def _http_client_kwargs(config):
    if "proxy" not in config:
        return {}

    proxy = (config.get("proxy") or "").strip()
    client_kwargs = {"trust_env": False}
    if proxy:
        client_kwargs["proxy"] = proxy
    return {
        "http_client": httpx.Client(**client_kwargs),
        "http_async_client": httpx.AsyncClient(**client_kwargs),
        "http_socket_options": (),
    }


def _is_quota_error(exc):
    text = str(exc).lower()
    return any(marker in text for marker in _QUOTA_MARKERS)


def _cooldown_key(config, model_name):
    return COOLDOWN_CACHE_KEY.format(name=f"{config.get('name') or '?'}:{model_name or config.get('model') or '?'}")


def _in_cooldown(config, model_name):
    try:
        return bool(caches["default"].get(_cooldown_key(config, model_name)))
    except Exception:
        return False


def _start_cooldown(config, model_name):
    try:
        caches["default"].set(_cooldown_key(config, model_name), int(time.time()), COOLDOWN_SECONDS)
    except Exception:
        logger.debug("Could not record LLM provider cooldown", exc_info=True)


class FailoverChatModel:
    """Tries every (provider, model) pair in priority order on invoke().

    A provider row can carry several models (primary + fallback_models); each
    is a separate candidate. Quota and availability failures put the exact
    (provider, model) pair on a short cooldown so subsequent calls jump
    straight to the next candidate. When everything is cooling down the
    cooldown is ignored — a call is always attempted.
    """

    def __init__(self, configs, *, temperature, kwargs):
        self.configs = configs
        self.temperature = temperature
        self.kwargs = kwargs

    def _candidates(self):
        pairs = []
        for config in self.configs:
            for model_name in config.get("models") or [config.get("model")]:
                if model_name:
                    pairs.append((config, model_name))
        return pairs

    def _build(self, config, model_name=None):
        params = {
            "temperature": self.temperature,
            "model": model_name or config.get("model"),
            "base_url": config.get("base_url"),
            "api_key": config.get("api_key"),
            **_http_client_kwargs(config),
        }
        if config.get("request_timeout_seconds"):
            params["timeout"] = config["request_timeout_seconds"]
        if config.get("max_output_tokens"):
            params["max_completion_tokens"] = config["max_output_tokens"]
        if config.get("max_retries") is not None:
            params["max_retries"] = config["max_retries"]

        extra = dict(self.kwargs)
        # JSON mode is per-provider: strip it for providers that don't support it.
        model_kwargs = dict(extra.get("model_kwargs") or {})
        if "response_format" in model_kwargs and not config.get("supports_json_mode"):
            model_kwargs.pop("response_format")
            if model_kwargs:
                extra["model_kwargs"] = model_kwargs
            else:
                extra.pop("model_kwargs", None)
        params.update(extra)
        return ChatOpenAI(**params)

    def invoke(self, input, **kwargs):
        all_pairs = self._candidates()
        candidates = [pair for pair in all_pairs if not _in_cooldown(*pair)]
        if not candidates:
            candidates = all_pairs

        last_error = None
        for index, (config, model_name) in enumerate(candidates):
            label = f"{config.get('name') or '?'}/{model_name}"
            try:
                result = self._build(config, model_name).invoke(input, **kwargs)
                if index > 0:
                    logger.info("LLM failover succeeded on %r (attempt %d)", label, index + 1)
                return result
            except Exception as exc:
                last_error = exc
                if _is_quota_error(exc):
                    _start_cooldown(config, model_name)
                if index + 1 < len(candidates):
                    next_config, next_model = candidates[index + 1]
                    logger.warning(
                        "LLM candidate %r failed (%s); failing over to %r",
                        label,
                        str(exc)[:200],
                        f"{next_config.get('name') or '?'}/{next_model}",
                    )
        raise last_error


class LLMAPI:
    def __init__(self, *, temperature=0.0, configs=None):
        self.temperature = temperature
        self.configs = get_llm_configs() if configs is None else configs
        if not isinstance(self.configs, list):
            raise ValueError("LLM provider configurations must be a list.")
        if not self.configs:
            raise ValueError("No enabled LLM provider configurations found.")

    def select_configs(self, tag=None):
        """All enabled configs matching the tag, in priority order."""
        if tag is None:
            return list(self.configs)

        required_tags = {tag} if isinstance(tag, str) else set(tag)
        matched = [
            config
            for config in self.configs
            if required_tags.issubset(set(config.get("tags", [])))
        ]
        if not matched:
            raise ValueError(f"No LLM configuration found matching tag(s): {tag}")
        return matched

    def select_config(self, tag=None):
        return self.select_configs(tag=tag)[0]

    def get_model(self, tag=None, **kwargs):
        configs = self.select_configs(tag=tag)
        wrapper = FailoverChatModel(configs, temperature=self.temperature, kwargs=kwargs)
        if len(wrapper._candidates()) <= 1:
            return wrapper._build(configs[0])
        return wrapper
