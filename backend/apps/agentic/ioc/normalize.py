"""Indicator normalisation and internal-scope detection.

Refanging happens here so a defanged indicator and its plain form resolve to
the same cache entry. Internal indicators are identified before any external
lookup so they never leave the organisation.
"""

import ipaddress
import re

IOC_IP = "ip"
IOC_DOMAIN = "domain"
IOC_URL = "url"
IOC_MD5 = "md5"
IOC_SHA1 = "sha1"
IOC_SHA256 = "sha256"
IOC_EMAIL = "email"
IOC_UNKNOWN = "unknown"

HASH_TYPES = {IOC_MD5, IOC_SHA1, IOC_SHA256}

MD5_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
SHA1_RE = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$", re.IGNORECASE)
URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

DEFANG_REPLACEMENTS = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    (" dot ", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("[at]", "@"),
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("hxxps://", "https://"),
    ("fxp", "ftp"),
    ("[//]", "//"),
)

DEFAULT_INTERNAL_DOMAINS = ("local", "internal", "corp", "lan", "intranet")


def refang(value):
    text = str(value or "").strip()
    lowered = text
    for needle, replacement in DEFANG_REPLACEMENTS:
        lowered = lowered.replace(needle, replacement)
        lowered = lowered.replace(needle.upper(), replacement)
    return lowered.strip().strip(".,;")


def classify(value):
    """Return (type, normalised_value) for an indicator."""
    text = refang(value)
    if not text:
        return IOC_UNKNOWN, ""

    if URL_RE.match(text):
        return IOC_URL, text

    if EMAIL_RE.match(text):
        return IOC_EMAIL, text.lower()

    if MD5_RE.match(text):
        return IOC_MD5, text.lower()
    if SHA1_RE.match(text):
        return IOC_SHA1, text.lower()
    if SHA256_RE.match(text):
        return IOC_SHA256, text.lower()

    try:
        address = ipaddress.ip_address(text)
        return IOC_IP, str(address)
    except ValueError:
        pass

    if DOMAIN_RE.match(text):
        return IOC_DOMAIN, text.lower()

    return IOC_UNKNOWN, text


def _host_of(indicator_type, value):
    if indicator_type == IOC_URL:
        without_scheme = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value, flags=re.IGNORECASE)
        return without_scheme.split("/")[0].split(":")[0].lower()
    if indicator_type == IOC_EMAIL:
        return value.split("@")[-1].lower()
    return value.lower()


def is_internal(indicator_type, value, *, internal_networks=(), internal_domains=()):
    """Internal indicators are never sent to an external source."""
    if indicator_type in HASH_TYPES:
        return False

    host = _host_of(indicator_type, value)

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if address is not None:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            return True
        for network in internal_networks or ():
            try:
                if address in ipaddress.ip_network(str(network), strict=False):
                    return True
            except ValueError:
                continue
        return False

    suffixes = [str(item).strip().lower().lstrip(".") for item in (internal_domains or ()) if str(item).strip()]
    suffixes.extend(DEFAULT_INTERNAL_DOMAINS)
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in suffixes)


def artifact_type_to_ioc(artifact_type):
    """Map an ASP Artifact type onto an indicator type when it is unambiguous."""
    mapping = {
        "ip address": IOC_IP,
        "ip": IOC_IP,
        "domain": IOC_DOMAIN,
        "url": IOC_URL,
        "hash": None,  # ambiguous: decided by length
        "email": IOC_EMAIL,
        "email address": IOC_EMAIL,
    }
    return mapping.get(str(artifact_type or "").strip().lower())
