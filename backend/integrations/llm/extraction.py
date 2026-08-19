import json
import re

THINKING_BLOCK_RE = re.compile(r"<(thinking|think|reasoning)>.*?</\1>", re.DOTALL | re.IGNORECASE)
UNCLOSED_THINKING_RE = re.compile(r"<(thinking|think|reasoning)>.*\Z", re.DOTALL | re.IGNORECASE)
CODE_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)
TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
SMART_QUOTES = {
    "“": '"',
    "”": '"',
    "‘": "'",
    "’": "'",
}


class JsonExtractionError(ValueError):
    pass


def _strip_reasoning(text):
    text = THINKING_BLOCK_RE.sub("", text)
    return UNCLOSED_THINKING_RE.sub("", text)


def _normalize_quotes(text):
    for source, target in SMART_QUOTES.items():
        text = text.replace(source, target)
    return text


def _fenced_candidates(text):
    return [match.group(1).strip() for match in CODE_FENCE_RE.finditer(text)]


def _balanced_object(text):
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return None


def _candidates(text):
    seen = []
    for candidate in [*_fenced_candidates(text), text]:
        balanced = _balanced_object(candidate)
        for option in (balanced, candidate.strip()):
            if option and option not in seen:
                seen.append(option)
    return seen


def extract_json_object(raw_text):
    """Recover a single JSON object from a chat completion body.

    Self-hosted and reasoning models routinely wrap the answer in <thinking>
    blocks, code fences or prose. Repair stays outside string literals so
    values are never rewritten.
    """
    if raw_text is None:
        raise JsonExtractionError("LLM response was empty.")

    text = _normalize_quotes(_strip_reasoning(str(raw_text))).strip()
    if not text:
        raise JsonExtractionError("LLM response contained no content outside reasoning blocks.")

    errors = []
    for candidate in _candidates(text):
        for attempt in (candidate, TRAILING_COMMA_RE.sub(r"\1", candidate)):
            try:
                parsed = json.loads(attempt)
            except (json.JSONDecodeError, TypeError) as exc:
                errors.append(str(exc))
                continue
            if isinstance(parsed, dict):
                return parsed
            errors.append(f"expected a JSON object, got {type(parsed).__name__}")

    raise JsonExtractionError(
        f"Could not recover a JSON object from the LLM response ({'; '.join(errors[:3]) or 'no candidates'})."
    )
