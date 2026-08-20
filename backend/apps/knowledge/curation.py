"""Turning investigations into knowledge worth retrieving later.

Capture is deliberately narrow. A record that names no entity cannot be matched
against a future case, and a record that states a conclusion without a reason
teaches an analyst nothing, so both are refused rather than stored. A knowledge
base that accumulates everything degrades every retrieval that follows.

Deduplication is by fingerprint over the kind and the entity set, so learning
the same lesson twice strengthens one record instead of adding a second.
"""

import hashlib
import logging

from django.db import transaction
from django.utils import timezone

from apps.agentic.triage.entities import ENTITY_PRIORITY
from apps.knowledge.models import Knowledge, KnowledgeKind, KnowledgeSource

logger = logging.getLogger(__name__)

MIN_BODY_LENGTH = 40
MAX_TITLE_LENGTH = 500
MAX_BODY_LENGTH = 20000

# Human judgement outranks model inference, and a human correcting the model is
# the most valuable signal available.
CONFIDENCE_BY_SOURCE = {
    KnowledgeSource.MANUAL: 1.0,
    KnowledgeSource.HUMAN_OVERRIDE: 0.95,
    KnowledgeSource.HUNT: 0.70,
    KnowledgeSource.CASE: 0.50,
    KnowledgeSource.TRIAGE: 0.45,
}


def normalise_entities(entities):
    """Keep only the typed entity kinds triage produces, lowercased and sorted."""
    source = (entities or {}).get("entities") if "entities" in (entities or {}) else entities
    cleaned = {}
    for kind in ENTITY_PRIORITY:
        values = []
        for value in (source or {}).get(kind) or []:
            text = str(value).strip().lower()
            if text and text not in values:
                values.append(text)
        if values:
            cleaned[kind] = sorted(values)
    return cleaned


def entity_pairs(entities):
    pairs = set()
    for kind, values in (entities or {}).items():
        for value in values or []:
            pairs.add(f"{kind}:{value}")
    return pairs


def fingerprint_for(kind, entities):
    pairs = sorted(entity_pairs(entities))
    digest = hashlib.sha256(f"{kind}|{'|'.join(pairs)}".encode("utf-8"))
    return digest.hexdigest()


def _accepts(kind, title, body, entities, tags):
    """Explain why a candidate is not worth storing, or return an empty string."""
    if kind not in KnowledgeKind.values:
        return f"unknown kind {kind!r}"
    if not str(title or "").strip():
        return "no title"
    if len(str(body or "").strip()) < MIN_BODY_LENGTH:
        return f"body shorter than {MIN_BODY_LENGTH} characters, so it states a conclusion without a reason"
    if not entities and not tags:
        return "no entity and no tag, so it can never be matched to a future case"
    return ""


@transaction.atomic
def capture(
    *,
    kind,
    title,
    body,
    entities=None,
    source=KnowledgeSource.TRIAGE,
    case=None,
    tags=None,
    expires_at=None,
    confidence=None,
):
    """Store one lesson, or merge it into the record that already carries it.

    Returns the Knowledge row, or None when the candidate was refused. Refusal
    is normal and is logged at debug level; callers treat it as a no-op.
    """
    entities = normalise_entities(entities)
    tags = [str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()]
    title = str(title or "").strip()[:MAX_TITLE_LENGTH]
    body = str(body or "").strip()[:MAX_BODY_LENGTH]

    refusal = _accepts(kind, title, body, entities, tags)
    if refusal:
        logger.debug("Knowledge capture refused (%s): %s", refusal, title[:80])
        return None

    if confidence is None:
        confidence = CONFIDENCE_BY_SOURCE.get(source, 0.4)

    fingerprint = fingerprint_for(kind, entities)
    existing = (
        Knowledge.objects.select_for_update()
        .filter(fingerprint=fingerprint, kind=kind)
        .order_by("created_at")
        .first()
    )

    if existing is None:
        record = Knowledge(
            title=title,
            body=body,
            kind=kind,
            entities=entities,
            tags=tags,
            source=source,
            case=case,
            fingerprint=fingerprint,
            confidence=confidence,
            expires_at=expires_at,
        )
        record.full_clean(exclude=["knowledge_id"])
        record.save()
        logger.info("Captured knowledge %s (%s)", record.knowledge_id, kind)
        return record

    # Same lesson, seen again. Strengthen rather than duplicate.
    changed = ["updated_at"]
    if confidence > existing.confidence:
        existing.confidence = confidence
        existing.source = source
        changed += ["confidence", "source"]
    merged_tags = sorted(set(existing.tags or []) | set(tags))
    if merged_tags != (existing.tags or []):
        existing.tags = merged_tags
        changed.append("tags")
    if body and body not in (existing.body or ""):
        existing.body = f"{existing.body}\n\n---\n{body}"[:MAX_BODY_LENGTH]
        changed.append("body")
    if expires_at and (existing.expires_at is None or expires_at > existing.expires_at):
        existing.expires_at = expires_at
        changed.append("expires_at")
    existing.save(update_fields=changed)
    logger.info("Merged knowledge into %s (%s)", existing.knowledge_id, kind)
    return existing


def record_usage(knowledge_ids):
    """Mark records as having been retrieved into an investigation.

    Retrieval count is what lets ranking prefer knowledge that keeps proving
    useful over knowledge that merely happens to be recent.
    """
    ids = [item for item in (knowledge_ids or []) if item]
    if not ids:
        return 0
    from django.db.models import F

    return Knowledge.objects.filter(knowledge_id__in=ids).update(
        hit_count=F("hit_count") + 1,
        last_used_at=timezone.now(),
    )


# A verdict only teaches something when it explains an outcome. "true positive"
# says the detection worked; it is the benign and false outcomes that carry the
# context a future investigation needs.
KIND_BY_VERDICT = {
    "false_positive": KnowledgeKind.FALSE_POSITIVE,
    "benign_true_positive": KnowledgeKind.BUSINESS_BEHAVIOUR,
}

# Below this, the model was guessing, and a guess stored as knowledge is worse
# than no knowledge at all.
MIN_AI_CONFIDENCE = 0.6


def _rule_tags(case):
    tags = []
    for alert in case.alerts.all()[:10]:
        for value in (alert.rule_name, alert.product_vendor):
            text = str(value or "").strip().lower()
            if text and text not in tags:
                tags.append(text)
    return tags


def _entity_label(entities):
    for kind in ENTITY_PRIORITY:
        values = (entities or {}).get(kind) or []
        if values:
            return values[0]
    return "unknown"


def capture_from_triage(result, *, source=KnowledgeSource.TRIAGE):
    """Learn from a triage outcome once it is settled.

    Only benign and false-positive outcomes are captured, and only when the
    verdict is confident or a human set it. A low-confidence guess recorded as
    knowledge would be retrieved into the next investigation as if it were
    established fact.
    """
    verdict = result.effective_verdict
    kind = KIND_BY_VERDICT.get(verdict)
    if kind is None:
        return None

    human_set = source == KnowledgeSource.HUMAN_OVERRIDE
    if not human_set and (result.confidence or 0) < MIN_AI_CONFIDENCE:
        logger.debug("Skipping knowledge capture for %s: confidence too low", result.case_id)
        return None

    entities = normalise_entities(result.entities)
    reasoning = (result.reasoning_vi or result.reasoning_en or "").strip()
    label = _entity_label(entities)

    lines = [reasoning] if reasoning else []
    if result.false_positive_class:
        lines.append(f"False positive class: {result.false_positive_class}.")
    if human_set and result.human_verdict_note:
        lines.append(f"Analyst note: {result.human_verdict_note}")
    if human_set and result.ai_was_overridden:
        lines.append(
            f"An analyst corrected the model here: it answered {result.verdict}, "
            f"the correct answer was {result.human_verdict}."
        )

    title = f"{verdict.replace('_', ' ')} on {label}"
    return capture(
        kind=kind,
        title=title,
        body="\n\n".join(lines),
        entities=entities,
        source=source,
        case=result.case,
        tags=_rule_tags(result.case) + [verdict],
    )


def capture_from_hunt(finding, *, cluster=None):
    """Record what a hunt settled, so the next hunt does not re-ask it."""
    hypothesis = finding.hypothesis
    if finding.conclusion not in {"confirmed", "refuted"}:
        # Inconclusive teaches nothing reusable; it only says the telemetry was
        # not enough on that day.
        return None

    cluster = cluster or hypothesis.plan.cluster
    entities = normalise_entities(cluster.primary_entities if cluster else {})
    label = _entity_label(entities)

    lines = [
        f"Hypothesis: {hypothesis.statement}",
        f"Conclusion: {finding.conclusion}.",
    ]
    if finding.summary:
        lines.append(finding.summary)
    executed = [q for q in hypothesis.queries.all() if q.status == "succeeded"]
    if executed:
        lines.append(
            "Settled by "
            + ", ".join(f"{q.target} query returning {q.row_count} rows" for q in executed[:5])
            + "."
        )

    tags = ["hunt", finding.conclusion]
    if hypothesis.mitre_technique:
        tags.append(hypothesis.mitre_technique.lower())

    return capture(
        kind=KnowledgeKind.HUNT_FINDING,
        title=f"Hunt {finding.conclusion}: {hypothesis.statement[:120]} ({label})",
        body="\n\n".join(lines),
        entities=entities,
        source=KnowledgeSource.HUNT,
        case=None,
        tags=tags,
    )
