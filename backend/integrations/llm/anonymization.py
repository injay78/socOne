import ipaddress
import re

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FIELD_HOST = "host"
FIELD_USER = "user"
FIELD_IP = "internal_ip"
FIELD_EMAIL = "email"

DEFAULT_FIELDS = [FIELD_HOST, FIELD_USER, FIELD_IP, FIELD_EMAIL]

HOST_KEYS = {"host", "hostname", "host_name", "computer", "computer_name", "device", "asset"}
USER_KEYS = {"user", "username", "user_name", "account", "actor", "owner", "assignee"}


def _is_internal_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


class Anonymizer:
    """Reversible placeholder substitution for values sent to an LLM.

    Default-off. SHB runs the model inside the bank, so identifiers normally
    stay intact; this exists for the case where a skill is pointed at an
    endpoint outside the organisation.
    """

    def __init__(self, *, fields=None):
        self.fields = set(fields or DEFAULT_FIELDS)
        self._to_placeholder = {}
        self._to_original = {}
        self._counters = {}

    @property
    def mapping(self):
        return dict(self._to_original)

    def _placeholder(self, kind, value):
        known = self._to_placeholder.get(value)
        if known:
            return known
        index = self._counters.get(kind, 0) + 1
        self._counters[kind] = index
        placeholder = f"{{{{ {kind} {kind}{index} }}}}"
        self._to_placeholder[value] = placeholder
        self._to_original[placeholder] = value
        return placeholder

    def _anonymize_text(self, text):
        if FIELD_EMAIL in self.fields:
            text = EMAIL_RE.sub(lambda m: self._placeholder(FIELD_EMAIL, m.group(0)), text)
        if FIELD_IP in self.fields:
            text = IPV4_RE.sub(
                lambda m: self._placeholder(FIELD_IP, m.group(0)) if _is_internal_ip(m.group(0)) else m.group(0),
                text,
            )
        for original, placeholder in list(self._to_placeholder.items()):
            if original and original in text:
                text = text.replace(original, placeholder)
        return text

    def _register_keyed_values(self, node):
        if isinstance(node, dict):
            for key, value in node.items():
                lowered = str(key).lower()
                if isinstance(value, str) and value.strip():
                    if FIELD_HOST in self.fields and lowered in HOST_KEYS:
                        self._placeholder(FIELD_HOST, value)
                    elif FIELD_USER in self.fields and lowered in USER_KEYS:
                        self._placeholder(FIELD_USER, value)
                self._register_keyed_values(value)
        elif isinstance(node, list):
            for item in node:
                self._register_keyed_values(item)

    def anonymize(self, payload):
        self._register_keyed_values(payload)
        return self._walk(payload, self._anonymize_text)

    def rehydrate(self, payload):
        return self._walk(payload, self._rehydrate_text)

    def _rehydrate_text(self, text):
        for placeholder, original in self._to_original.items():
            if placeholder in text:
                text = text.replace(placeholder, original)
        return text

    def _walk(self, node, transform):
        if isinstance(node, str):
            return transform(node)
        if isinstance(node, dict):
            return {key: self._walk(value, transform) for key, value in node.items()}
        if isinstance(node, list):
            return [self._walk(item, transform) for item in node]
        return node


def build_anonymizer():
    """Return an Anonymizer when runtime config enables it, otherwise None."""
    from apps.settings.runtime_config import get_anonymization_settings

    settings = get_anonymization_settings()
    if not settings["enabled"]:
        return None
    return Anonymizer(fields=settings["fields"] or DEFAULT_FIELDS)
