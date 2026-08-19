"""One normalised shape for QRadar offences.

Push (webhook) and pull (worker) ingestion both go through `normalize_offense`,
so a Module sees an identical payload no matter which path delivered it. The
stream name stays the detection rule name, matching the Splunk and ELK
contract.
"""

import logging

logger = logging.getLogger(__name__)

DEFAULT_STREAM_NAME = "QRadar-Offense"
TOP_EVENT_LIMIT = 20


def _first(source, *keys, default=None):
    for key in keys:
        value = source.get(key)
        if value not in (None, "", [], {}):
            return value
    return default


def _rule_names(offense):
    rules = offense.get("rules") or []
    names = []
    for rule in rules:
        if isinstance(rule, dict):
            name = rule.get("name") or rule.get("rule_name") or rule.get("id")
            if name:
                names.append(str(name))
        elif rule:
            names.append(str(rule))
    return names


def stream_name_for_offense(offense):
    """Redis stream name = detection rule name, with documented fallbacks."""
    rules = _rule_names(offense)
    if rules:
        return rules[0]
    for key in ("offense_type_name", "offense_type", "description", "categories"):
        value = offense.get(key)
        if isinstance(value, list) and value:
            return str(value[0]).strip()
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()
    return DEFAULT_STREAM_NAME


def resolve_ingest_stream(stream_name, *, default=DEFAULT_STREAM_NAME):
    """Pick the stream an offence is actually written to.

    The contract stays stream-name-equals-rule-name: when a Module subscribes
    to the rule, the offence goes to that stream. QRadar deployments carry
    hundreds of rules though, so an offence nobody wrote a Module for falls
    back to the generic stream instead of vanishing into a stream with no
    consumer. The payload keeps the original rule name either way.
    """
    from apps.agentic.runtime.module import discover_module_definitions

    candidate = str(stream_name or "").strip()
    if not candidate:
        return default

    try:
        subscribed = {definition.stream_name for definition in discover_module_definitions()}
    except Exception:
        logger.exception("Failed to scan Module definitions while resolving the QRadar stream")
        return candidate

    return candidate if candidate in subscribed else default


def normalize_offense(offense, *, source_addresses=None, destination_addresses=None, top_events=None):
    offense = dict(offense or {})
    offense_id = _first(offense, "id", "offense_id", "offenseId")
    if offense_id is None:
        raise ValueError("QRadar offence payload has no id.")

    return {
        "source": "qradar",
        "offense_id": offense_id,
        "rule_names": _rule_names(offense),
        "stream_name": stream_name_for_offense(offense),
        "description": (_first(offense, "description", default="") or "").strip(),
        "offense_type": _first(offense, "offense_type_name", "offense_type", default=""),
        "status": _first(offense, "status", default=""),
        "magnitude": _first(offense, "magnitude", default=0),
        "severity": _first(offense, "severity", default=0),
        "credibility": _first(offense, "credibility", default=0),
        "relevance": _first(offense, "relevance", default=0),
        "event_count": _first(offense, "event_count", default=0),
        "flow_count": _first(offense, "flow_count", default=0),
        "start_time": _first(offense, "start_time", "starttime"),
        "last_persisted_time": _first(offense, "last_persisted_time", "last_updated_time"),
        "offense_source": _first(offense, "offense_source", default=""),
        "username": _first(offense, "assigned_to", "username_count", default=""),
        "domain_id": _first(offense, "domain_id"),
        "categories": offense.get("categories") or [],
        "source_addresses": list(source_addresses or []),
        "destination_addresses": list(destination_addresses or []),
        "top_events": list(top_events or [])[:TOP_EVENT_LIMIT],
        "raw_offense": offense,
    }


def load_offense_with_context(offense_id, *, with_context=True, client=None):
    """Fetch one offence and, optionally, the addresses and events around it."""
    from integrations.siem.clients import get_qradar_client

    client = client or get_qradar_client()
    offense = client.get_offense(offense_id) or {}
    if not with_context:
        return normalize_offense(offense)

    source_addresses = []
    destination_addresses = []
    top_events = []

    try:
        source_addresses = [
            item.get("source_ip")
            for item in client.get_offense_source_addresses(offense.get("source_address_ids"))
            if isinstance(item, dict) and item.get("source_ip")
        ]
    except Exception:
        logger.warning("Failed to load QRadar source addresses for offence %s", offense_id, exc_info=True)

    try:
        destination_addresses = [
            item.get("local_destination_ip")
            for item in client.get_offense_local_destination_addresses(
                offense.get("local_destination_address_ids")
            )
            if isinstance(item, dict) and item.get("local_destination_ip")
        ]
    except Exception:
        logger.warning("Failed to load QRadar destination addresses for offence %s", offense_id, exc_info=True)

    try:
        top_events = fetch_offense_events(offense_id, client=client)
    except Exception:
        logger.warning("Failed to load QRadar events for offence %s", offense_id, exc_info=True)

    return normalize_offense(
        offense,
        source_addresses=source_addresses,
        destination_addresses=destination_addresses,
        top_events=top_events,
    )


def fetch_offense_events(offense_id, *, client=None, limit=TOP_EVENT_LIMIT):
    """Top events of an offence, fetched through the read-only AQL guard."""
    from apps.settings.runtime_config import get_qradar_config
    from integrations.siem.aql_guard import guard_aql_with_config
    from integrations.siem.audit import record_aql_execution
    from integrations.siem.clients import get_qradar_client

    config = get_qradar_config()
    client = client or get_qradar_client()
    aql = (
        "SELECT QIDNAME(qid) AS event_name, sourceip, destinationip, username, "
        "starttime, payload FROM events "
        f"WHERE INOFFENSE({int(offense_id)}) "
        f"LAST {int(config['default_window_minutes'])} MINUTES "
        f"LIMIT {min(limit, config['max_rows'])}"
    )
    guarded = guard_aql_with_config(aql, config)
    query = guarded.raise_for_rejection()
    rows = client.run_aql(query, max_rows=min(limit, config["max_rows"]))
    record_aql_execution(query=query, rewrites=guarded.rewrites, row_count=len(rows))
    return rows
