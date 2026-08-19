import json
from dataclasses import dataclass, field

DEFAULT_CHARS_PER_TOKEN = 3.5
PROMPT_ALLOWANCE_TOKENS = 1500


@dataclass(frozen=True)
class PayloadTier:
    """One priority level of the payload. Lower order is kept first."""

    name: str
    order: int
    value: object
    truncatable: bool = True


@dataclass
class BudgetResult:
    payload: dict
    trimmed_tiers: list = field(default_factory=list)
    estimated_tokens: int = 0


def estimate_tokens(value, *, chars_per_token=DEFAULT_CHARS_PER_TOKEN):
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, default=str)
    return int(len(text) / chars_per_token) + 1


def _truncate_list(value, keep):
    return value[:keep] if isinstance(value, list) else value


def apply_budget(tiers, *, context_window_tokens, max_output_tokens, chars_per_token=DEFAULT_CHARS_PER_TOKEN):
    """Assemble a payload that fits the model's input budget.

    Tiers are serialised highest priority first. Lower tiers are shortened,
    then dropped, until the estimate fits. Every reduction is reported so the
    caller can surface it instead of silently losing context.
    """
    available = context_window_tokens - max_output_tokens - PROMPT_ALLOWANCE_TOKENS
    if available <= 0:
        raise ValueError(
            "LLM context window is too small for the configured max_output_tokens."
        )

    ordered = sorted(tiers, key=lambda tier: tier.order)
    payload = {}
    trimmed = []
    used = 0

    for tier in ordered:
        cost = estimate_tokens(tier.value, chars_per_token=chars_per_token)
        if used + cost <= available:
            payload[tier.name] = tier.value
            used += cost
            continue

        placed = False
        if tier.truncatable and isinstance(tier.value, list) and tier.value:
            keep = len(tier.value) // 2
            while keep > 0:
                candidate = _truncate_list(tier.value, keep)
                cost = estimate_tokens(candidate, chars_per_token=chars_per_token)
                if used + cost <= available:
                    payload[tier.name] = candidate
                    used += cost
                    trimmed.append({
                        "tier": tier.name,
                        "action": "truncated",
                        "kept": keep,
                        "original": len(tier.value),
                    })
                    placed = True
                    break
                keep = keep // 2

        if not placed:
            trimmed.append({"tier": tier.name, "action": "dropped"})

    return BudgetResult(payload=payload, trimmed_tiers=trimmed, estimated_tokens=used)
