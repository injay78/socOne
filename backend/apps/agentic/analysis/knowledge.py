from dataclasses import dataclass

from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from pydantic import BaseModel, Field

from apps.agentic.analysis.profiles import AI_PROFILE_AGENT, serialize_for_ai, serialize_case_for_investigation
from apps.agentic.analysis.prompts import INVESTIGATION_KNOWLEDGE_KEYWORD_PROMPT, invoke_structured_llm, KNOWLEDGE_EXTRACTION_PROMPT
from apps.agentic.analysis.schemas import KnowledgeSearchKeywords
from apps.knowledge.models import Knowledge, KnowledgeSource

MAX_KNOWLEDGE_KEYWORDS = 8
MAX_KNOWLEDGE_RECORDS = 10
MAX_KNOWLEDGE_TAGS = 10


@dataclass(frozen=True)
class KnowledgeContext:
    keywords: list[str]
    records: list[dict]

    def as_payload(self):
        return {
            "keywords": self.keywords,
            "records": self.records,
        }


def normalize_knowledge_terms(values, *, limit, max_length=None, collapse_whitespace=True):
    normalized = []
    seen = set()
    for item in values or []:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if collapse_whitespace:
            value = " ".join(value.split())
        if max_length is not None:
            value = value[:max_length]
        if not value:
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(value)
        if len(normalized) >= limit:
            break
    return normalized


def normalize_knowledge_keywords(keywords):
    return normalize_knowledge_terms(keywords, limit=MAX_KNOWLEDGE_KEYWORDS, max_length=80)


def normalize_knowledge_tags(tags):
    return normalize_knowledge_terms(tags, limit=MAX_KNOWLEDGE_TAGS, collapse_whitespace=False)


def fallback_knowledge_keywords(case_payload):
    keywords = [case_payload.get("title", "")]
    keywords.extend(case_payload.get("tags", []) or [])
    for alert in case_payload.get("alerts", []) or []:
        keywords.append(alert.get("rule_name", ""))
        keywords.append(alert.get("title", ""))
        for artifact in alert.get("artifacts", []) or []:
            keywords.append(artifact.get("value", ""))
    return normalize_knowledge_keywords(keywords)


def extract_knowledge_keywords(case_payload):
    try:
        result = invoke_structured_llm(
            prompt_id=INVESTIGATION_KNOWLEDGE_KEYWORD_PROMPT,
            payload=case_payload,
            output_schema=KnowledgeSearchKeywords,
        )
        return normalize_knowledge_keywords(result.keywords)
    except Exception:
        return fallback_knowledge_keywords(case_payload)


def _relevance(record, entity_pairs, keywords):
    """Rank a candidate. Entity overlap first, because it is the only signal
    that ties a record to *this* investigation rather than to similar wording.

    Confidence then separates a human correction from a model's guess, and the
    retrieval count separates knowledge that keeps proving useful from
    knowledge that is merely recent.
    """
    from apps.knowledge.curation import entity_pairs as pairs_of

    overlap = len(pairs_of(record.entities) & entity_pairs) if entity_pairs else 0
    haystack = f"{record.title} {record.body}".lower()
    keyword_hits = sum(1 for keyword in keywords if keyword.lower() in haystack)
    return (
        overlap,
        round(record.confidence or 0.0, 3),
        min(record.hit_count or 0, 50),
        keyword_hits,
        record.created_at,
    )


def search_knowledge_records(keywords, limit=MAX_KNOWLEDGE_RECORDS, entities=None):
    from apps.knowledge.curation import entity_pairs as pairs_of, normalise_entities, record_usage

    keywords = normalize_knowledge_keywords(keywords)
    wanted_pairs = pairs_of(normalise_entities(entities)) if entities else set()
    if not keywords and not wanted_pairs:
        return []

    match_query = Q()
    for keyword in keywords:
        match_query |= Q(title__icontains=keyword)
        match_query |= Q(body__icontains=keyword)
        match_query |= Q(tags__contains=[keyword])
    # An entity match needs no shared wording: knowledge about a host applies to
    # that host whatever the alert happens to be called.
    for pair in wanted_pairs:
        kind, _, value = pair.partition(":")
        match_query |= Q(**{f"entities__{kind}__contains": [value]})

    if not match_query:
        return []

    valid_time_query = Q(expires_at__isnull=True) | Q(expires_at__gte=timezone.now())
    candidates = list(
        Knowledge.objects.filter(valid_time_query).filter(match_query).order_by("-created_at")[: limit * 5]
    )
    candidates.sort(key=lambda record: _relevance(record, wanted_pairs, keywords), reverse=True)
    selected = candidates[:limit]

    record_usage([record.knowledge_id for record in selected])
    return [serialize_for_ai(record, AI_PROFILE_AGENT) for record in selected]


def build_knowledge_context(case_payload):
    keywords = extract_knowledge_keywords(case_payload)
    entities = (case_payload or {}).get("entities") if isinstance(case_payload, dict) else None
    records = search_knowledge_records(keywords, entities=entities)
    return KnowledgeContext(keywords=keywords, records=records)


class KnowledgeExtractionLLMResult(BaseModel):
    has_knowledge: bool
    title: str | None = None
    body: str | None = None
    tags: list[str] = Field(default_factory=list)
    reason: str


@dataclass(frozen=True)
class KnowledgeExtractionResult:
    has_knowledge: bool
    remark: str
    knowledge: Knowledge | None = None
    reason: str = ""


def generate_knowledge_extraction(case_payload, *, user_input=""):
    payload = {"case": case_payload}
    if user_input:
        payload["user_input"] = user_input
    return invoke_structured_llm(
        prompt_id=KNOWLEDGE_EXTRACTION_PROMPT,
        payload=payload,
        output_schema=KnowledgeExtractionLLMResult,
    )


@transaction.atomic
def extract_knowledge_from_case(*, case, user_input="", source=None):
    locked_case = case.__class__.objects.select_for_update().get(pk=case.pk)
    if not locked_case.verdict:
        return KnowledgeExtractionResult(
            has_knowledge=False,
            remark="Case has no analyst verdict, skipping knowledge extraction.",
            reason="Case has no analyst verdict.",
        )

    case_payload = serialize_case_for_investigation(locked_case)
    extraction = generate_knowledge_extraction(case_payload, user_input=user_input)
    existing = Knowledge.objects.select_for_update().filter(case=locked_case).first()

    if not extraction.has_knowledge:
        if existing:
            existing.delete()
        return KnowledgeExtractionResult(
            has_knowledge=False,
            remark=f"No knowledge extracted: {extraction.reason}",
            reason=extraction.reason,
        )

    title = (extraction.title or "").strip()
    body = (extraction.body or "").strip()
    if not title or not body:
        raise ValueError("Knowledge extraction returned has_knowledge=true without title and body.")

    tags = normalize_knowledge_tags(extraction.tags)
    if existing is None:
        knowledge = Knowledge(case=locked_case)
    else:
        knowledge = existing
    knowledge.title = title
    knowledge.body = body
    knowledge.source = KnowledgeSource.CASE
    knowledge.tags = tags
    knowledge.full_clean()
    knowledge.save()
    return KnowledgeExtractionResult(
        has_knowledge=True,
        remark=f"Knowledge created: {title}. Reason: {extraction.reason}",
        knowledge=knowledge,
        reason=extraction.reason,
    )
