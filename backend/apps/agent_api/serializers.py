import mimetypes

from django.urls import reverse


def dt(value):
    return value.isoformat() if value else None


def serialize_case(case, *, include_related=False):
    data = {
        "case_id": case.case_id,
        "title": case.title,
        "severity": case.severity,
        "confidence": case.confidence,
        "impact": case.impact,
        "priority": case.priority,
        "status": case.status,
        "verdict": case.verdict,
        "severity_ai": case.severity_ai,
        "confidence_ai": case.confidence_ai,
        "impact_ai": case.impact_ai,
        "priority_ai": case.priority_ai,
        "verdict_ai": case.verdict_ai,
        "summary": case.summary,
        "correlation_uid": case.correlation_uid,
        "tags": case.tags,
        "created_at": dt(case.created_at),
        "updated_at": dt(case.updated_at),
    }
    if include_related:
        data["alerts"] = [serialize_alert(alert, include_related=False) for alert in case.alerts.all()[:50]]
        data["relationships"] = [
            serialize_case_relationship(relationship, case)
            for relationship in _case_relationships(case)[:50]
        ]
    return data


def _case_relationships(case):
    from apps.cases.services import relationships_for_case

    return relationships_for_case(case)


def serialize_case_relationship(relationship, case):
    from apps.cases.services import relationship_for_case_payload

    return relationship_for_case_payload(relationship, case)


def serialize_alert(alert, *, include_related=False):
    data = {
        "alert_id": alert.alert_id,
        "case_id": alert.case.case_id if alert.case_id else "",
        "title": alert.title,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "impact": alert.impact,
        "status": alert.status,
        "correlation_uid": alert.correlation_uid,
        "source_uid": alert.source_uid,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "created_at": dt(alert.created_at),
        "updated_at": dt(alert.updated_at),
    }
    if include_related:
        data["artifacts"] = [serialize_artifact(artifact, include_related=False) for artifact in alert.artifacts.all()[:50]]
    return data


def serialize_artifact(artifact, *, include_related=False):
    data = {
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "type": artifact.type,
        "role": artifact.role,
        "value": artifact.value,
        "created_at": dt(artifact.created_at),
        "updated_at": dt(artifact.updated_at),
    }
    if include_related:
        data["alerts"] = [
            {
                "alert_id": alert.alert_id,
                "case_id": alert.case.case_id if alert.case_id else "",
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
            }
            for alert in artifact.alerts.select_related("case").all()[:50]
        ]
    return data


def serialize_knowledge(knowledge):
    return {
        "knowledge_id": knowledge.knowledge_id,
        "title": knowledge.title,
        "body": knowledge.body,
        "expires_at": dt(knowledge.expires_at),
        "source": knowledge.source,
        "tags": knowledge.tags,
        "case_id": knowledge.case.case_id if knowledge.case_id else "",
        "created_at": dt(knowledge.created_at),
        "updated_at": dt(knowledge.updated_at),
    }


def serialize_attachment(attachment, *, request=None):
    path = reverse("attachment-download", kwargs={"access_key": attachment.access_key})
    url = request.build_absolute_uri(path) if request is not None else path
    return {
        "file_key": str(attachment.access_key),
        "filename": attachment.filename,
        "size": attachment.size,
        "content_type": mimetypes.guess_type(attachment.filename)[0] or "application/octet-stream",
        "download_url": url,
        "uploaded_at": dt(attachment.uploaded_at),
    }


def serialize_comment(comment, *, request=None):
    return {
        "id": comment.id,
        "target": {
            "content_type": comment.content_type.model,
            "object_id": comment.object_id,
        },
        "body": comment.body,
        "author": comment.author.username if comment.author else "",
        "parent_id": comment.parent_id,
        "mentions": [user.username for user in comment.mentions.all()],
        "attachments": [serialize_attachment(item, request=request) for item in comment.attachments.all()],
        "created_at": dt(comment.created_at),
        "updated_at": dt(comment.updated_at),
    }


def serialize_enrichment(enrichment):
    target = ""
    if enrichment.case_id:
        target = enrichment.case.case_id
    elif enrichment.alert_id:
        target = enrichment.alert.alert_id
    elif enrichment.artifact_id:
        target = enrichment.artifact.artifact_id
    return {
        "enrichment_id": enrichment.enrichment_id,
        "target_id": target,
        "name": enrichment.name,
        "type": enrichment.type,
        "provider": enrichment.provider,
        "uid": enrichment.uid,
        "value": enrichment.value,
        "desc": enrichment.desc,
        "data": enrichment.data,
        "created_at": dt(enrichment.created_at),
        "updated_at": dt(enrichment.updated_at),
    }


def serialize_playbook(playbook, *, include_related=False):
    data = {
        "playbook_id": playbook.playbook_id,
        "case_id": playbook.case.case_id if playbook.case_id else "",
        "name": playbook.name,
        "user_input": playbook.user_input,
        "job_status": playbook.job_status,
        "job_id": playbook.job_id,
        "remark": playbook.remark,
        "created_at": dt(playbook.created_at),
        "updated_at": dt(playbook.updated_at),
    }
    if include_related and playbook.case_id:
        data["case"] = serialize_case(playbook.case, include_related=False)
    return data


def serialize_cluster(cluster, *, include_members=False):
    data = {
        "cluster_id": cluster.cluster_id,
        "id": str(cluster.id),
        "title": cluster.title,
        "status": cluster.status,
        "primary_entities": cluster.primary_entities or {},
        "window_start": dt(cluster.window_start),
        "window_end": dt(cluster.window_end),
        "link_score": cluster.link_score,
        "case_count": cluster.case_count,
        "alert_count": cluster.alert_count,
        "fingerprint": cluster.fingerprint,
        "merged_into": str(cluster.merged_into_id) if cluster.merged_into_id else None,
        "lifecycle_events": cluster.lifecycle_events or [],
        "created_at": dt(cluster.created_at),
        "updated_at": dt(cluster.updated_at),
    }
    if include_members:
        data["members"] = [
            {
                "case_id": member.case.case_id if member.case else None,
                "alert_id": member.alert.alert_id if member.alert else None,
                "contribution_score": member.contribution_score,
                "joined_at": dt(member.joined_at),
            }
            for member in cluster.members.select_related("case", "alert").all()
        ]
    return data


def serialize_hunt_query(query):
    return {
        "id": str(query.id),
        "target": query.target,
        "query_text": query.query_text,
        "purpose": query.purpose,
        "expected_evidence": query.expected_evidence,
        "negative_interpretation": query.negative_interpretation,
        "status": query.status,
        "row_count": query.row_count,
        "sample_rows": query.sample_rows or [],
        "duration_ms": query.duration_ms,
        "guard_rejection_reason": query.guard_rejection_reason,
        "executed_at": dt(query.executed_at),
        "error": query.error,
    }


def serialize_hunt_finding(finding):
    return {
        "id": str(finding.id),
        "conclusion": finding.conclusion,
        "summary": finding.summary,
        "evidence": finding.evidence or [],
        "created_at": dt(finding.created_at),
    }


def serialize_hunt_hypothesis(hypothesis, *, include_tree=True):
    data = {
        "id": str(hypothesis.id),
        "statement": hypothesis.statement,
        "mitre_technique": hypothesis.mitre_technique,
        "rationale": hypothesis.rationale,
        "status": hypothesis.status,
        "position": hypothesis.position,
    }
    if include_tree:
        data["queries"] = [serialize_hunt_query(query) for query in hypothesis.queries.all()]
        data["findings"] = [
            serialize_hunt_finding(finding) for finding in hypothesis.findings.all()
        ]
    return data


def serialize_hunt_plan(plan, *, include_tree=False):
    data = {
        "id": str(plan.id),
        "cluster_id": plan.cluster.cluster_id if plan.cluster_id else None,
        "status": plan.status,
        "mode": plan.mode,
        "hypotheses_count": plan.hypotheses_count,
        "stop_reason": plan.stop_reason,
        "error": plan.error,
        "started_at": dt(plan.started_at),
        "completed_at": dt(plan.completed_at),
        "created_at": dt(plan.created_at),
    }
    if include_tree:
        data["budget_snapshot"] = plan.budget_snapshot or {}
        data["hypotheses"] = [
            serialize_hunt_hypothesis(hypothesis)
            for hypothesis in plan.hypotheses.prefetch_related("queries", "findings").all()
        ]
    return data
