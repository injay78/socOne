import base64
import logging
import ipaddress
import re
import time
from urllib.parse import quote

import httpx
from django.core.cache import caches
from pycti import OpenCTIApiClient

from apps.artifacts.models import ArtifactType
from apps.settings.runtime_config import get_opencti_config, get_otx_config, get_virustotal_config
from integrations.threat_intel.models import TIProviderResult

MOCK_PROVIDER_NAME = "MockTIProvider"
OTX_PROVIDER_NAME = "AlienVaultOTX"
OPENCTI_PROVIDER_NAME = "OpenCTI"
VIRUSTOTAL_PROVIDER_NAME = "VirusTotal"
VT_KEY_CURSOR_CACHE_KEY = "asp:vt:key_cursor"
VT_RATE_CACHE_KEY = "asp:vt:rl:{index}:{minute}"
MAX_PULSE_SUMMARIES = 5
MAX_LIST_ITEMS = 12
OPENCTI_SEARCH_LIMIT = 5
OPENCTI_CONTEXT_RELATION_LIMIT = 30
OPENCTI_CONTEXT_PER_TYPE_LIMIT = 5
SUPPORTED_TYPES = {
    ArtifactType.IP_ADDRESS,
    ArtifactType.HOSTNAME,
    ArtifactType.URL_STRING,
    ArtifactType.HASH,
    ArtifactType.EMAIL_ADDRESS,
}
MALICIOUS_KEYWORDS = {"evil", "malware", "phishing", "suspicious"}
OPENCTI_MALICIOUS_CONTEXT_TYPES = {
    "Attack-Pattern",
    "Campaign",
    "Intrusion-Set",
    "Malware",
    "Threat-Actor",
    "Threat-Actor-Group",
    "Tool",
    "Vulnerability",
}
OPENCTI_UNSUPPORTED_TYPES = {
    ArtifactType.UNKNOWN,
    ArtifactType.CONTAINER,
    ArtifactType.GROUP,
    ArtifactType.MESSAGE,
    ArtifactType.OTHER,
    ArtifactType.PORT,
    ArtifactType.SCRIPT_CONTENT,
}

logger = logging.getLogger(__name__)


class BaseThreatIntelProvider:
    name = ""

    def query(self, indicator, *, artifact_type):
        raise NotImplementedError


class MockThreatIntelProvider(BaseThreatIntelProvider):
    name = MOCK_PROVIDER_NAME

    def query(self, indicator, *, artifact_type):
        artifact_type = _artifact_type_value(artifact_type)
        indicator = str(indicator or "").strip()
        if artifact_type not in SUPPORTED_TYPES:
            return TIProviderResult(
                indicator=indicator,
                indicator_type=artifact_type,
                provider=self.name,
                error="Unsupported artifact type.",
            )

        lowered = indicator.lower()
        if artifact_type == ArtifactType.IP_ADDRESS and _is_private_ip(indicator):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=artifact_type,
                provider=self.name,
                risk_level="low",
                reputation_score=5,
                is_malicious=False,
                tags=["private"],
                raw={"source": self.name, "rule": "private-ip"},
            )

        if any(keyword in lowered for keyword in MALICIOUS_KEYWORDS):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=artifact_type,
                provider=self.name,
                risk_level="high",
                reputation_score=95,
                is_malicious=True,
                tags=[keyword for keyword in MALICIOUS_KEYWORDS if keyword in lowered],
                raw={"source": self.name, "rule": "keyword-match"},
            )

        risk_level = "medium" if artifact_type == ArtifactType.HASH else "low"
        return TIProviderResult(
            indicator=indicator,
            indicator_type=artifact_type,
            provider=self.name,
            risk_level=risk_level,
            reputation_score=50 if risk_level == "medium" else 10,
            is_malicious=False,
            tags=["mock"],
            raw={"source": self.name, "rule": "default"},
        )


class OpenCTIProvider(BaseThreatIntelProvider):
    name = OPENCTI_PROVIDER_NAME

    def __init__(self, *, url=None, token=None, ssl_verify=None, proxy=None, client=None):
        config = None
        if any(value is None for value in (url, token, ssl_verify, proxy)):
            config = get_opencti_config()
        self.url = (url if url is not None else config["url"]).rstrip("/")
        self.token = token if token is not None else config["token"]
        self.ssl_verify = ssl_verify if ssl_verify is not None else config["ssl_verify"]
        self.proxy = proxy if proxy is not None else config["proxy"]
        self.client = client

    def query(self, indicator, *, artifact_type):
        artifact_type = _artifact_type_value(artifact_type)
        indicator = str(indicator or "").strip()
        if not indicator:
            return self._error(indicator, artifact_type, "Indicator is required.")
        if not self.url or not self.token:
            return self._error(indicator, artifact_type, "OpenCTI URL or API token is not configured.")

        plan = self._query_plan(indicator, artifact_type)
        if plan.get("error"):
            return self._error(indicator, artifact_type, plan["error"], indicator_type=plan.get("indicator_type"))

        try:
            client = self._client()
            matches = self._find_matches(client, indicator, plan)
            context = self._load_context(client, matches)
            return self._summarize(indicator, artifact_type, plan, matches, context)
        except Exception:
            logger.exception("OpenCTI query failed")
            return self._error(indicator, artifact_type, "OpenCTI query failed.", indicator_type=plan.get("indicator_type"))

    def _client(self):
        if self.client is not None:
            return self.client
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        self.client = OpenCTIApiClient(
            self.url,
            self.token,
            log_level="error",
            ssl_verify=self.ssl_verify,
            proxies=proxies,
            perform_health_check=True,
            provider="AspOpenCTI/1.0",
        )
        return self.client

    def _query_plan(self, indicator, artifact_type):
        if artifact_type in OPENCTI_UNSUPPORTED_TYPES:
            return {"error": f"Unsupported artifact type for OpenCTI: {artifact_type}", "indicator_type": artifact_type}

        if artifact_type == ArtifactType.IP_ADDRESS:
            try:
                parsed = ipaddress.ip_address(indicator)
            except ValueError:
                return {"error": "Invalid IP address.", "indicator_type": "ip"}
            observable_type = "IPv4-Addr" if parsed.version == 4 else "IPv6-Addr"
            return {"indicator_type": "ip", "observable_types": [observable_type], "include_indicators": True}

        mapping = {
            ArtifactType.HOSTNAME: ("hostname", ["Hostname", "Domain-Name"], True),
            ArtifactType.ENDPOINT: ("hostname", ["Hostname", "Domain-Name"], True),
            ArtifactType.URL_STRING: ("url", ["Url"], True),
            ArtifactType.UNIFORM_RESOURCE_LOCATOR: ("url", ["Url"], True),
            ArtifactType.HASH: ("file", ["StixFile"], True),
            ArtifactType.FILE: ("file", ["StixFile"], True),
            ArtifactType.FILE_NAME: ("file", ["StixFile"], True),
            ArtifactType.FILE_PATH: ("file", ["StixFile"], True),
            ArtifactType.FINGERPRINT: ("file", ["StixFile"], True),
            ArtifactType.EMAIL_ADDRESS: ("email", ["Email-Addr", "Email-Message"], True),
            ArtifactType.EMAIL: ("email", ["Email-Addr", "Email-Message"], True),
            ArtifactType.MAC_ADDRESS: ("mac", ["Mac-Addr"], True),
            ArtifactType.PROCESS_NAME: ("process", ["Process"], True),
            ArtifactType.PROCESS: ("process", ["Process"], True),
            ArtifactType.PROCESS_ID: ("process", ["Process"], True),
            ArtifactType.COMMAND_LINE: ("process", ["Process"], True),
            ArtifactType.REGISTRY: ("registry", ["Windows-Registry-Key"], True),
            ArtifactType.REGISTRY_PATH: ("registry", ["Windows-Registry-Key"], True),
            ArtifactType.HTTP_USER_AGENT: ("user-agent", ["User-Agent"], True),
            ArtifactType.USER_NAME: ("user-account", ["User-Account"], True),
            ArtifactType.USER: ("user-account", ["User-Account"], True),
            ArtifactType.ACCOUNT: ("user-account", ["User-Account"], True),
            ArtifactType.USER_CREDENTIAL_ID: ("credential", ["Credential"], True),
            ArtifactType.RESOURCE_UID: ("simple-observable", ["Simple-Observable"], False),
            ArtifactType.RESOURCE: ("simple-observable", ["Simple-Observable"], False),
            ArtifactType.DEVICE: ("simple-observable", ["Simple-Observable"], False),
            ArtifactType.SERIAL_NUMBER: ("simple-observable", ["Simple-Observable"], False),
            ArtifactType.SUBNET: ("ip", ["IPv4-Addr", "IPv6-Addr"], True),
        }
        if artifact_type in mapping:
            indicator_type, observable_types, include_indicators = mapping[artifact_type]
            return {
                "indicator_type": indicator_type,
                "observable_types": observable_types,
                "include_indicators": include_indicators,
            }

        if artifact_type == ArtifactType.CVE:
            return {"indicator_type": "vulnerability", "domain_helpers": ["vulnerability"], "include_indicators": False}
        if artifact_type == ArtifactType.CWE:
            return {"indicator_type": "vulnerability", "domain_helpers": ["vulnerability"], "include_indicators": False}
        if artifact_type in {ArtifactType.COUNTRY, ArtifactType.GEO_LOCATION}:
            return {"indicator_type": "location", "domain_helpers": ["location"], "include_indicators": False}
        if artifact_type == ArtifactType.ADVISORY:
            return {"indicator_type": "report", "domain_helpers": ["report"], "include_indicators": False}

        return {"error": f"Unsupported artifact type for OpenCTI: {artifact_type}", "indicator_type": artifact_type}

    def _find_matches(self, client, indicator, plan):
        matches = []
        if plan.get("include_indicators"):
            matches.extend(self._list_helper(client.indicator, search=indicator))
        for observable_type in plan.get("observable_types", []):
            matches.extend(self._list_observables(client, observable_type, indicator))
        for helper_name in plan.get("domain_helpers", []):
            matches.extend(self._list_helper(getattr(client, helper_name), search=indicator))
        return self._dedupe_objects([item for item in matches if self._matches_value(item, indicator)])

    def _list_helper(self, helper, *, search):
        return helper.list(search=search, first=OPENCTI_SEARCH_LIMIT) or []

    def _list_observables(self, client, observable_type, indicator):
        return client.stix_cyber_observable.list(types=[observable_type], search=indicator, first=OPENCTI_SEARCH_LIMIT) or []

    def _matches_value(self, item, indicator):
        lowered = indicator.lower()
        pattern = item.get("pattern")
        if isinstance(pattern, str) and self._pattern_contains_value(pattern, indicator):
            return True
        candidates = [
            item.get("name"),
            item.get("value"),
            item.get("observable_value"),
            item.get("x_opencti_cwe"),
        ]
        for observable in item.get("x_opencti_observable_values") or []:
            if isinstance(observable, dict):
                candidates.append(observable.get("value"))
        for ref in item.get("externalReferences") or []:
            if isinstance(ref, dict):
                candidates.extend([ref.get("external_id"), ref.get("url")])
        return any(lowered == str(candidate or "").lower() for candidate in candidates)

    @staticmethod
    def _pattern_contains_value(pattern, indicator):
        lowered = indicator.lower()
        for value in _single_quoted_values(pattern):
            unescaped = value.replace("\\'", "'").replace("\\\\", "\\")
            if unescaped.lower() == lowered:
                return True
        return False

    def _load_context(self, client, matches):
        relationships = []
        related_by_type = {}
        for item in matches[:OPENCTI_SEARCH_LIMIT]:
            item_id = item.get("id")
            if not item_id:
                continue
            for relationship in client.stix_core_relationship.list(fromOrToId=[item_id], first=OPENCTI_CONTEXT_RELATION_LIMIT) or []:
                relationships.append(self._compact_relationship(relationship))
                related = self._other_relationship_side(relationship, item_id)
                if not related:
                    continue
                entity_type = related.get("entity_type") or related.get("type") or "Unknown"
                bucket = related_by_type.setdefault(entity_type, [])
                if len(bucket) < OPENCTI_CONTEXT_PER_TYPE_LIMIT:
                    bucket.append(self._compact_object(related))
        return {
            "relationships": self._dedupe_objects(relationships),
            "related_by_type": {key: self._dedupe_objects(value) for key, value in related_by_type.items()},
        }

    def _summarize(self, indicator, artifact_type, plan, matches, context):
        score = self._score(matches, context)
        risk_level = self._risk_level(score, context)
        related_by_type = context["related_by_type"]
        opencti_raw = {
            "artifact_type": artifact_type,
            "stix_type": self._stix_type(plan),
            "opencti_entity_types": self._entity_types(matches),
            "matched_by": "strict_type_mapping",
            "matches": [self._compact_object(item) for item in matches[:OPENCTI_SEARCH_LIMIT]],
            "relationships": context["relationships"][:OPENCTI_CONTEXT_RELATION_LIMIT],
            "related_by_type": related_by_type,
        }
        return TIProviderResult(
            indicator=indicator,
            indicator_type=plan.get("indicator_type") or artifact_type,
            provider=self.name,
            risk_level=risk_level,
            reputation_score=score,
            is_malicious=risk_level in {"high", "medium"},
            tags=self._limit_list(self._labels(matches, related_by_type)),
            attack_techniques=self._names_for_types(related_by_type, {"Attack-Pattern"}),
            malware_families=self._names_for_types(related_by_type, {"Malware"}),
            adversaries=self._names_for_types(related_by_type, {"Threat-Actor", "Threat-Actor-Group", "Intrusion-Set"}),
            industries=self._names_for_types(related_by_type, {"Sector"}),
            pulses=self._reports(related_by_type),
            network_context=self._network_context_from_related(related_by_type),
            raw={"source": self.name, "opencti": opencti_raw},
        )

    def _score(self, matches, context):
        scores = []
        for item in matches:
            score = self._coerce_score(item.get("x_opencti_score"))
            if score is not None:
                scores.append(score)
            cvss = self._coerce_score(item.get("x_opencti_cvss_base_score"))
            if cvss is not None:
                scores.append(min(100, int(cvss * 10)))
        return max(scores) if scores else None

    def _risk_level(self, score, context):
        if score is not None:
            if score >= 70:
                return "high"
            if score >= 40:
                return "medium"
            if score > 0:
                return "low"
        if any(entity_type in OPENCTI_MALICIOUS_CONTEXT_TYPES for entity_type in context["related_by_type"]):
            return "medium"
        return "low" if context["related_by_type"] else None

    @staticmethod
    def _coerce_score(value):
        try:
            if value is None or value == "":
                return None
            return int(float(value))
        except (TypeError, ValueError):
            return None

    def _stix_type(self, plan):
        if plan.get("observable_types"):
            return plan["observable_types"][0]
        if plan.get("domain_helpers") == ["vulnerability"]:
            return "vulnerability"
        if plan.get("domain_helpers") == ["location"]:
            return "location"
        if plan.get("domain_helpers") == ["report"]:
            return "report"
        return plan.get("indicator_type")

    def _entity_types(self, matches):
        return self._limit_list(self._unique_items(item.get("entity_type") or item.get("type") for item in matches))

    def _labels(self, matches, related_by_type):
        labels = []
        for item in matches:
            labels.extend(self._object_labels(item))
        for items in related_by_type.values():
            for item in items:
                labels.extend(item.get("labels") or [])
        return self._unique_items(labels)

    def _names_for_types(self, related_by_type, entity_types):
        names = []
        for entity_type in entity_types:
            names.extend(item.get("name") for item in related_by_type.get(entity_type, []))
        return self._limit_list(self._unique_items(name for name in names if name))

    def _reports(self, related_by_type):
        reports = []
        for item in related_by_type.get("Report", []):
            reports.append(
                {
                    "name": item.get("name"),
                    "description": item.get("description"),
                    "tags": item.get("labels") or [],
                    "created": item.get("created"),
                    "modified": item.get("modified"),
                }
            )
        return reports[:MAX_PULSE_SUMMARIES]

    @staticmethod
    def _network_context_from_related(related_by_type):
        context = {}
        autonomous_systems = related_by_type.get("Autonomous-System") or []
        locations = (related_by_type.get("Country") or []) + (related_by_type.get("Location") or [])
        if autonomous_systems:
            context["autonomous_systems"] = autonomous_systems[:OPENCTI_CONTEXT_PER_TYPE_LIMIT]
        if locations:
            context["locations"] = locations[:OPENCTI_CONTEXT_PER_TYPE_LIMIT]
        return context or None

    def _compact_relationship(self, relationship):
        return {
            "id": relationship.get("id"),
            "standard_id": relationship.get("standard_id"),
            "relationship_type": relationship.get("relationship_type") or relationship.get("entity_type"),
            "from": self._compact_object(relationship.get("from") or {}),
            "to": self._compact_object(relationship.get("to") or {}),
        }

    def _other_relationship_side(self, relationship, source_id):
        from_obj = relationship.get("from") or {}
        to_obj = relationship.get("to") or {}
        if from_obj.get("id") == source_id:
            return to_obj
        if to_obj.get("id") == source_id:
            return from_obj
        return to_obj or from_obj

    def _compact_object(self, item):
        return {
            "id": item.get("id"),
            "standard_id": item.get("standard_id"),
            "entity_type": item.get("entity_type") or item.get("type"),
            "name": item.get("name") or item.get("observable_value") or item.get("value") or item.get("pattern"),
            "description": item.get("description") or item.get("x_opencti_description"),
            "score": item.get("x_opencti_score"),
            "labels": self._object_labels(item),
            "created": item.get("created"),
            "modified": item.get("modified") or item.get("updated_at"),
        }

    @staticmethod
    def _object_labels(item):
        labels = []
        for label in item.get("objectLabel") or []:
            if isinstance(label, dict) and label.get("value"):
                labels.append(label["value"])
        if item.get("labels"):
            labels.extend(item.get("labels"))
        return labels

    @staticmethod
    def _dedupe_objects(items):
        result = []
        seen = set()
        for item in items:
            key = item.get("id") or item.get("standard_id") or repr(sorted(item.items()))
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @staticmethod
    def _unique_items(items):
        unique = []
        for item in items:
            if item and item not in unique:
                unique.append(item)
        return unique

    @staticmethod
    def _limit_list(items, limit=MAX_LIST_ITEMS):
        return items[:limit]

    def _error(self, indicator, artifact_type, error, *, indicator_type=None):
        return TIProviderResult(
            indicator=indicator,
            indicator_type=indicator_type or artifact_type or "unknown",
            provider=self.name,
            error=error,
        )


class AlienVaultOTXProvider(BaseThreatIntelProvider):
    name = OTX_PROVIDER_NAME

    def __init__(self, *, api_key=None, base_url=None, proxy=None, http_client=None):
        config = get_otx_config()
        self.api_key = config["api_key"] if api_key is None else api_key
        self.base_url = (base_url or config["base_url"]).rstrip("/")
        self.proxy = config["proxy"] if proxy is None else proxy
        self.http_client = http_client

    def query(self, indicator, *, artifact_type):
        artifact_type = _artifact_type_value(artifact_type)
        indicator = str(indicator or "").strip()
        endpoint = self._endpoint_for(indicator, artifact_type)
        if endpoint["error"]:
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                error=endpoint["error"],
            )
        if not self.api_key:
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                error="AlienVault OTX API key is not configured.",
            )

        response = self._request_json(endpoint["path"])
        if response.get("error"):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                raw=response,
                error=response["error"],
            )

        if endpoint["indicator_type"] in {"ip", "file"}:
            response["reputation_score"] = self.calculate_reputation_score(response)
        return self.summarize_result(response, endpoint["indicator_type"], indicator)

    def _endpoint_for(self, indicator, artifact_type):
        if artifact_type == ArtifactType.IP_ADDRESS:
            try:
                ip = ipaddress.ip_address(indicator)
            except ValueError:
                return {"path": "", "indicator_type": "ip", "error": "Invalid IPv4 address."}
            if ip.version != 4:
                return {"path": "", "indicator_type": "ip", "error": "Only IPv4 indicators are supported."}
            return {"path": f"/indicators/IPv4/{indicator}/general", "indicator_type": "ip", "error": None}

        if artifact_type == ArtifactType.URL_STRING:
            if not _looks_like_url(indicator):
                return {"path": "", "indicator_type": "url", "error": "Invalid URL indicator."}
            return {
                "path": f"/indicators/url/{quote(indicator, safe='')}/general",
                "indicator_type": "url",
                "error": None,
            }

        if artifact_type == ArtifactType.HASH:
            if not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", indicator):
                return {
                    "path": "",
                    "indicator_type": "file",
                    "error": "Invalid hash. Must be MD5, SHA1, or SHA256 hex.",
                }
            return {"path": f"/indicators/file/{indicator}/general", "indicator_type": "file", "error": None}

        return {
            "path": "",
            "indicator_type": artifact_type or "unknown",
            "error": f"Unsupported artifact type for AlienVault OTX: {artifact_type}",
        }

    def _request_json(self, path):
        headers = {
            "accept": "application/json",
            "X-OTX-API-KEY": self.api_key,
        }
        url = f"{self.base_url}{path}"
        try:
            if self.http_client is None:
                client_kwargs = {}
                if self.proxy:
                    client_kwargs["proxy"] = self.proxy
                with httpx.Client(**client_kwargs) as client:
                    response = client.get(url, headers=headers)
            else:
                response = self.http_client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            logger.info("OTX request returned HTTP %s", exc.response.status_code)
            return {"error": f"OTX HTTP {exc.response.status_code}."}
        except httpx.HTTPError:
            logger.exception("OTX request failed")
            return {"error": "OTX request failed."}
        except ValueError:
            logger.exception("OTX response is not valid JSON")
            return {"error": "OTX response is not valid JSON."}

    def summarize_result(self, attributes, indicator_type, indicator):
        if attributes.get("error"):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                raw=attributes,
                error=attributes["error"],
            )

        pulse_info = attributes.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        reputation_score = attributes.get("reputation_score")
        pulse_count = pulse_info.get("count", len(pulses))
        risk_level = self._risk_level(reputation_score, pulse_count)
        validation = self._compact_named_items(attributes.get("validation") or [])
        false_positive = self._compact_named_items(attributes.get("false_positive") or [])
        raw = {
            "source": self.name,
            "pulse_count": pulse_count,
            "validation": validation,
            "false_positive": false_positive,
        }

        return TIProviderResult(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self.name,
            risk_level=risk_level,
            reputation_score=reputation_score,
            is_malicious=risk_level in {"high", "medium"},
            tags=self._limit_list(self._unique_items(tag for pulse in pulses for tag in pulse.get("tags", []))),
            attack_techniques=self._limit_list(self._extract_attack_techniques(pulses)),
            malware_families=self._limit_list(self._extract_related_values(pulse_info, "malware_families")),
            adversaries=self._limit_list(self._extract_related_values(pulse_info, "adversary")),
            industries=self._limit_list(self._extract_related_values(pulse_info, "industries")),
            pulses=self._compact_pulses(pulses),
            network_context=self._network_context(attributes),
            raw=raw,
        )

    @staticmethod
    def _unique_items(items):
        unique = []
        for item in items:
            if item and item not in unique:
                unique.append(item)
        return unique

    @staticmethod
    def _limit_list(items, limit=MAX_LIST_ITEMS):
        return items[:limit]

    @classmethod
    def _extract_attack_techniques(cls, pulses):
        techniques = []
        for pulse in pulses:
            for attack in pulse.get("attack_ids", []) or []:
                display_name = attack.get("display_name") or attack.get("name") or attack.get("id")
                if display_name:
                    techniques.append(display_name)
        return cls._unique_items(techniques)

    @classmethod
    def _extract_related_values(cls, pulse_info, key):
        related = pulse_info.get("related") or {}
        values = []
        for source in ("alienvault", "other"):
            values.extend((related.get(source) or {}).get(key, []) or [])
        return cls._unique_items(values)

    @classmethod
    def _compact_named_items(cls, items):
        compact = []
        for item in items:
            if isinstance(item, dict):
                value = item.get("name") or item.get("source") or item.get("description")
                if value:
                    compact.append(value)
            elif item:
                compact.append(item)
        return cls._limit_list(cls._unique_items(compact))

    @classmethod
    def _compact_pulses(cls, pulses):
        compact = []
        for pulse in pulses[:MAX_PULSE_SUMMARIES]:
            compact.append(
                {
                    "name": pulse.get("name"),
                    "description": pulse.get("description"),
                    "tags": cls._limit_list(pulse.get("tags", [])),
                    "attack_techniques": cls._limit_list(cls._extract_attack_techniques([pulse])),
                    "malware_families": cls._limit_list(pulse.get("malware_families", []) or []),
                    "adversary": pulse.get("adversary"),
                    "created": pulse.get("created"),
                    "modified": pulse.get("modified"),
                    "tlp": pulse.get("TLP"),
                }
            )
        return compact

    @staticmethod
    def _network_context(attributes):
        context = {}
        for field in ("asn", "country_name", "country_code", "region", "city"):
            if attributes.get(field):
                context[field] = attributes[field]
        return context or None

    @staticmethod
    def _risk_level(reputation_score, pulse_count):
        score = reputation_score or 0
        if score >= 50 or pulse_count >= 5:
            return "high"
        if score >= 20 or pulse_count > 0:
            return "medium"
        return "low"

    @staticmethod
    def calculate_reputation_score(attributes):
        score = 0
        pulse_info = attributes.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])
        score -= pulse_count * 10

        related = pulse_info.get("related", {})
        malware_families = (related.get("alienvault", {}).get("malware_families", []) or []) + (
            related.get("other", {}).get("malware_families", []) or []
        )
        score -= len(malware_families) * 15

        adversaries = (related.get("alienvault", {}).get("adversary", []) or []) + (
            related.get("other", {}).get("adversary", []) or []
        )
        score -= len(adversaries) * 12

        for validation in attributes.get("validation", []):
            if validation.get("name") == "whitelist":
                score += 20
            elif validation.get("name") == "blacklist":
                score -= 25

        false_positive = attributes.get("false_positive", [])
        if false_positive:
            score += len(false_positive) * 10

        for pulse in pulses:
            for tag in pulse.get("tags", []):
                if tag.lower() in {"malware", "trojan", "backdoor", "botnet", "apt", "exploit"}:
                    score -= 8

        return -score


class VirusTotalProvider(BaseThreatIntelProvider):
    """VirusTotal v3 lookups with a rotating API-key pool.

    Keys are picked round-robin through a shared Redis counter so every worker
    process advances the same cursor; a key that hits its per-minute ceiling or
    returns 429/401 is skipped for the current minute and the next key is tried.
    """

    name = VIRUSTOTAL_PROVIDER_NAME

    def __init__(self, *, api_keys=None, base_url=None, proxy=None, timeout_seconds=None, requests_per_minute_per_key=None, http_client=None):
        config = get_virustotal_config()
        self.api_keys = list(api_keys) if api_keys is not None else config["api_keys"]
        self.base_url = (base_url or config["base_url"]).rstrip("/")
        self.proxy = config["proxy"] if proxy is None else proxy
        self.timeout_seconds = timeout_seconds or config["timeout_seconds"]
        self.requests_per_minute_per_key = requests_per_minute_per_key or config["requests_per_minute_per_key"]
        self.http_client = http_client

    def query(self, indicator, *, artifact_type):
        artifact_type = _artifact_type_value(artifact_type)
        indicator = str(indicator or "").strip()
        endpoint = self._endpoint_for(indicator, artifact_type)
        if endpoint["error"]:
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                error=endpoint["error"],
            )
        if not self.api_keys:
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                error="VirusTotal API keys are not configured.",
            )

        response = self._request_json(endpoint["path"])
        if response.get("error"):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                raw={"error": response["error"]},
                error=response["error"],
            )
        return self._summarize(response, endpoint["indicator_type"], indicator)

    def _endpoint_for(self, indicator, artifact_type):
        if artifact_type == ArtifactType.IP_ADDRESS:
            try:
                ipaddress.ip_address(indicator)
            except ValueError:
                return {"path": "", "indicator_type": "ip", "error": "Invalid IP address."}
            return {"path": f"/ip_addresses/{indicator}", "indicator_type": "ip", "error": None}

        if artifact_type in {ArtifactType.HOSTNAME, ArtifactType.ENDPOINT}:
            domain = indicator.lower().rstrip(".")
            if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+", domain):
                return {"path": "", "indicator_type": "domain", "error": "Invalid domain."}
            return {"path": f"/domains/{domain}", "indicator_type": "domain", "error": None}

        if artifact_type in {ArtifactType.URL_STRING, ArtifactType.UNIFORM_RESOURCE_LOCATOR}:
            if not _looks_like_url(indicator):
                return {"path": "", "indicator_type": "url", "error": "Invalid URL indicator."}
            url_id = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("ascii").rstrip("=")
            return {"path": f"/urls/{url_id}", "indicator_type": "url", "error": None}

        if artifact_type in {ArtifactType.HASH, ArtifactType.FINGERPRINT}:
            if not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", indicator):
                return {"path": "", "indicator_type": "file", "error": "Invalid hash. Must be MD5, SHA1, or SHA256 hex."}
            return {"path": f"/files/{indicator.lower()}", "indicator_type": "file", "error": None}

        return {
            "path": "",
            "indicator_type": artifact_type or "unknown",
            "error": f"Unsupported artifact type for VirusTotal: {artifact_type}",
        }

    def _next_key_index(self):
        cache = caches["default"]
        try:
            cursor = cache.incr(VT_KEY_CURSOR_CACHE_KEY)
        except ValueError:
            cache.set(VT_KEY_CURSOR_CACHE_KEY, 1, None)
            cursor = 1
        return cursor % len(self.api_keys)

    def _key_available(self, index):
        cache = caches["default"]
        minute = int(time.time() // 60)
        key = VT_RATE_CACHE_KEY.format(index=index, minute=minute)
        try:
            count = cache.incr(key)
        except ValueError:
            cache.set(key, 1, 120)
            count = 1
        return count <= self.requests_per_minute_per_key

    def _exhaust_key(self, index):
        minute = int(time.time() // 60)
        caches["default"].set(
            VT_RATE_CACHE_KEY.format(index=index, minute=minute),
            self.requests_per_minute_per_key + 1,
            120,
        )

    def _request_json(self, path):
        url = f"{self.base_url}{path}"
        start = self._next_key_index()
        last_error = "VirusTotal request failed."
        for offset in range(len(self.api_keys)):
            index = (start + offset) % len(self.api_keys)
            if not self._key_available(index):
                last_error = "All VirusTotal API keys are rate limited."
                continue
            headers = {"accept": "application/json", "x-apikey": self.api_keys[index]}
            try:
                if self.http_client is None:
                    client_kwargs = {"timeout": self.timeout_seconds}
                    if self.proxy:
                        client_kwargs["proxy"] = self.proxy
                    with httpx.Client(**client_kwargs) as client:
                        response = client.get(url, headers=headers)
                else:
                    response = self.http_client.get(url, headers=headers)
                if response.status_code == 404:
                    return {"error": "VirusTotal has no record for this indicator."}
                if response.status_code in (401, 403):
                    logger.warning("VirusTotal key #%s rejected (HTTP %s); rotating", index, response.status_code)
                    self._exhaust_key(index)
                    last_error = f"VirusTotal HTTP {response.status_code}."
                    continue
                if response.status_code == 429:
                    logger.info("VirusTotal key #%s rate limited; rotating", index)
                    self._exhaust_key(index)
                    last_error = "VirusTotal HTTP 429."
                    continue
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as exc:
                logger.info("VirusTotal request returned HTTP %s", exc.response.status_code)
                return {"error": f"VirusTotal HTTP {exc.response.status_code}."}
            except httpx.HTTPError:
                logger.exception("VirusTotal request failed")
                last_error = "VirusTotal request failed."
                continue
            except ValueError:
                logger.exception("VirusTotal response is not valid JSON")
                return {"error": "VirusTotal response is not valid JSON."}
        return {"error": last_error}

    def _summarize(self, response, indicator_type, indicator):
        attributes = (response.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total_engines = sum(int(stats.get(key) or 0) for key in ("malicious", "suspicious", "harmless", "undetected"))

        if malicious >= 5:
            risk_level = "high"
        elif malicious >= 2 or suspicious >= 5:
            risk_level = "medium"
        else:
            risk_level = "low"

        raw = {
            "source": self.name,
            "last_analysis_stats": stats,
            "vt_detection_ratio": f"{malicious}/{total_engines}" if total_engines else "",
            "reputation": attributes.get("reputation"),
            "total_votes": attributes.get("total_votes"),
            "tags": (attributes.get("tags") or [])[:MAX_LIST_ITEMS],
        }
        network_context = None
        if indicator_type == "ip":
            network_context = {
                "country": attributes.get("country") or "",
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner") or "",
                "network": attributes.get("network") or "",
            }
        elif indicator_type == "domain":
            creation_date = attributes.get("creation_date")
            if creation_date:
                raw["creation_date"] = creation_date
                raw["domain_age_days"] = max(0, int((time.time() - float(creation_date)) // 86400))
            raw["categories"] = attributes.get("categories") or {}
            raw["registrar"] = attributes.get("registrar") or ""
        elif indicator_type == "file":
            raw["meaningful_name"] = attributes.get("meaningful_name") or ""
            raw["type_description"] = attributes.get("type_description") or ""
            raw["first_submission_date"] = attributes.get("first_submission_date")
            raw["signature_info"] = {
                key: value
                for key, value in (attributes.get("signature_info") or {}).items()
                if key in ("product", "verified", "signers", "copyright")
            }
            raw["popular_threat_classification"] = (attributes.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
        elif indicator_type == "url":
            raw["final_url"] = attributes.get("last_final_url") or ""
            raw["title"] = attributes.get("title") or ""

        return TIProviderResult(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self.name,
            risk_level=risk_level,
            reputation_score=attributes.get("reputation"),
            is_malicious=malicious >= 3,
            tags=[str(tag) for tag in (attributes.get("tags") or [])][:MAX_LIST_ITEMS],
            network_context=network_context,
            raw=raw,
        )


def _artifact_type_value(artifact_type):
    return artifact_type.value if hasattr(artifact_type, "value") else str(artifact_type)


def _is_private_ip(value):
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _looks_like_url(value):
    if re.match(r"^(https?://|ftp://|www\.)", value, re.IGNORECASE):
        return True
    return "." in value and "/" in value


def _single_quoted_values(value):
    values = []
    current = []
    in_quote = False
    escaped = False
    for char in value:
        if not in_quote:
            if char == "'":
                in_quote = True
                current = []
            continue
        if escaped:
            current.append(f"\\{char}")
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'":
            values.append("".join(current))
            in_quote = False
            continue
        current.append(char)
    return values


def _redact(value, secrets):
    redacted = str(value)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def get_providers():
    providers = {}
    config = get_otx_config()
    if config["enabled"] and config["api_key"]:
        providers[OTX_PROVIDER_NAME] = AlienVaultOTXProvider()
    opencti_config = get_opencti_config()
    if opencti_config["enabled"] and opencti_config["url"] and opencti_config["token"]:
        providers[OPENCTI_PROVIDER_NAME] = OpenCTIProvider()
    virustotal_config = get_virustotal_config()
    if virustotal_config["enabled"] and virustotal_config["api_keys"]:
        providers[VIRUSTOTAL_PROVIDER_NAME] = VirusTotalProvider()
    return providers
