"""One clustering pass over the sliding window.

Idempotency is the hard requirement: running the worker twice over the same
window must produce the same clusters and no duplicates, and a cluster that
gains a Case must be extended rather than recreated. Lookup is therefore by
entity overlap against open clusters first, with the fingerprint as the identity
of record rather than the lookup key.
"""

import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.agentic.correlation.entities import (
    build_node,
    cluster_title,
    entity_pairs_from_primary,
    fingerprint_for,
    merge_entity_sets,
)
from apps.agentic.correlation.scoring import connected_components, score_edge
from apps.agentic.models import ClusterStatus, IncidentCluster, IncidentClusterMember
from apps.cases.models import Case
from apps.common.worker_runner import WorkerIterationResult
from apps.settings.runtime_config import get_clustering_config

logger = logging.getLogger(__name__)


def _load_nodes(window_start, limit):
    cases = (
        Case.objects.filter(created_at__gte=window_start)
        .prefetch_related("alerts__artifacts", "triage_results")
        .order_by("created_at")[:limit]
    )
    return [build_node(case) for case in cases]


def _candidate_clusters(pairs, window_start):
    """Open clusters in the window whose entity set intersects this group."""
    candidates = []
    open_clusters = IncidentCluster.objects.filter(
        status=ClusterStatus.OPEN, window_end__gte=window_start
    ).order_by("created_at")
    for cluster in open_clusters:
        if entity_pairs_from_primary(cluster.primary_entities) & pairs:
            candidates.append(cluster)
    return candidates


def _member_contribution(node, siblings, window_seconds, min_shared_entities):
    scores = [
        score_edge(
            node,
            other,
            window_seconds=window_seconds,
            min_shared_entities=min_shared_entities,
        )[0]
        for other in siblings
        if other is not node
    ]
    return round(max(scores), 4) if scores else 0.0


def _sync_members(cluster, nodes, window_seconds, min_shared_entities):
    added = 0
    for node in nodes:
        contribution = _member_contribution(node, nodes, window_seconds, min_shared_entities)
        member, created = IncidentClusterMember.objects.get_or_create(
            cluster=cluster,
            case=node["case"],
            defaults={"contribution_score": contribution},
        )
        if created:
            added += 1
        elif member.contribution_score != contribution:
            member.contribution_score = contribution
            member.save(update_fields=["contribution_score", "updated_at"])
    return added


def _apply_fingerprint(cluster, fingerprint):
    """Set the fingerprint, absorbing a collision as a merge rather than failing."""
    if cluster.fingerprint == fingerprint:
        return cluster
    clash = (
        IncidentCluster.objects.filter(fingerprint=fingerprint)
        .exclude(pk=cluster.pk)
        .first()
    )
    if clash is None:
        cluster.fingerprint = fingerprint
        return cluster

    # Two groups converged onto the same entity set. The older cluster survives.
    survivor, absorbed = sorted([cluster, clash], key=lambda item: item.created_at)
    IncidentClusterMember.objects.filter(cluster=absorbed).update(cluster=survivor)
    absorbed.status = ClusterStatus.MERGED
    absorbed.merged_into = survivor
    absorbed.lifecycle_events = (absorbed.lifecycle_events or []) + [
        {
            "event": "merged",
            "into": str(survivor.pk),
            "at": timezone.now().isoformat(),
        }
    ]
    absorbed.save(update_fields=["status", "merged_into", "lifecycle_events", "updated_at"])
    survivor.lifecycle_events = (survivor.lifecycle_events or []) + [
        {
            "event": "absorbed",
            "from": str(absorbed.pk),
            "at": timezone.now().isoformat(),
        }
    ]
    return survivor


@transaction.atomic
def _upsert_cluster(group_nodes, link_score, window_start, window_end, config):
    window_seconds = max(1, int((window_end - window_start).total_seconds()))
    min_shared = config["min_shared_entities"]

    primary_entities = merge_entity_sets(group_nodes)
    pairs = entity_pairs_from_primary(primary_entities)
    fingerprint = fingerprint_for(primary_entities)

    candidates = _candidate_clusters(pairs, window_start)

    if not candidates:
        cluster = IncidentCluster(
            primary_entities=primary_entities,
            window_start=window_start,
            window_end=window_end,
            link_score=link_score,
            fingerprint=fingerprint,
            title=cluster_title(primary_entities, len(group_nodes)),
        )
        cluster.save()
        created = True
    else:
        cluster = candidates[0]
        created = False
        for extra in candidates[1:]:
            IncidentClusterMember.objects.filter(cluster=extra).update(cluster=cluster)
            extra.status = ClusterStatus.MERGED
            extra.merged_into = cluster
            extra.lifecycle_events = (extra.lifecycle_events or []) + [
                {"event": "merged", "into": str(cluster.pk), "at": timezone.now().isoformat()}
            ]
            extra.save(
                update_fields=["status", "merged_into", "lifecycle_events", "updated_at"]
            )

        existing_pairs = entity_pairs_from_primary(cluster.primary_entities)
        if pairs - existing_pairs:
            cluster.lifecycle_events = (cluster.lifecycle_events or []) + [
                {
                    "event": "extended",
                    "added_entities": sorted(pairs - existing_pairs),
                    "at": timezone.now().isoformat(),
                }
            ]
            merged_primary = dict(cluster.primary_entities or {})
            for kind, values in primary_entities.items():
                combined = set(merged_primary.get(kind) or []) | set(values)
                merged_primary[kind] = sorted(combined)
            cluster.primary_entities = merged_primary
            cluster = _apply_fingerprint(cluster, fingerprint_for(merged_primary))

        cluster.window_start = min(cluster.window_start, window_start)
        cluster.window_end = max(cluster.window_end, window_end)
        cluster.link_score = link_score

    _sync_members(cluster, group_nodes, window_seconds, min_shared)

    members = IncidentClusterMember.objects.filter(cluster=cluster)
    cluster.case_count = members.exclude(case__isnull=True).count()
    cluster.alert_count = sum(
        member.case.alerts.count() for member in members.select_related("case") if member.case
    )
    cluster.title = cluster_title(cluster.primary_entities, cluster.case_count)
    cluster.save()
    return cluster, created


def run_correlation_once():
    config = get_clustering_config()
    if not config["enabled"]:
        return WorkerIterationResult(processed=False, message="Clustering is disabled.")

    window_end = timezone.now()
    window_start = window_end - timedelta(hours=config["window_hours"])
    window_seconds = max(1, int((window_end - window_start).total_seconds()))

    nodes = _load_nodes(window_start, config["max_cases_per_run"])
    if len(nodes) < 2:
        return WorkerIterationResult(
            processed=False, message=f"Only {len(nodes)} case(s) in window; nothing to cluster."
        )

    groups = connected_components(
        nodes,
        window_seconds=window_seconds,
        min_shared_entities=config["min_shared_entities"],
        threshold=config["link_threshold"],
    )
    if not groups:
        return WorkerIterationResult(
            processed=False, message=f"No linked group among {len(nodes)} cases."
        )

    created_count = 0
    updated_count = 0
    for group in groups:
        group_nodes = [nodes[index] for index in group["indexes"]]
        _cluster, created = _upsert_cluster(
            group_nodes, group["link_score"], window_start, window_end, config
        )
        if created:
            created_count += 1
        else:
            updated_count += 1

    message = (
        f"Clustered {len(nodes)} cases into {len(groups)} group(s): "
        f"{created_count} created, {updated_count} updated."
    )
    logger.info(message)
    return WorkerIterationResult(processed=True, message=message)
