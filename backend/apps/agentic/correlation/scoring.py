"""Edge scoring between two Cases.

Three signals, combined into one score between 0 and 1: shared entities, time
proximity inside the window, and MITRE tactic overlap. Entity overlap dominates
because it is the only one of the three that is evidence on its own; time and
tactic can only reinforce or weaken a link that entities already suggest.
"""

from apps.agentic.correlation.entities import ENTITY_WEIGHTS

ENTITY_SIGNAL_WEIGHT = 0.70
TIME_SIGNAL_WEIGHT = 0.15
TACTIC_SIGNAL_WEIGHT = 0.15


def shared_pairs(left, right):
    return left["pairs"] & right["pairs"]


def _entity_signal(shared):
    """Weighted strength of the shared entity set, saturating at 1.0.

    A single shared hostname is already a strong link; three shared low-weight
    values such as gateway IPs are not.
    """
    if not shared:
        return 0.0
    total = 0.0
    for pair in shared:
        kind = pair.split(":", 1)[0]
        total += ENTITY_WEIGHTS.get(kind, 0.3)
    return min(1.0, total)


def _time_signal(left, right, window_seconds):
    if not window_seconds:
        return 0.0
    delta = abs((left["timestamp"] - right["timestamp"]).total_seconds())
    if delta >= window_seconds:
        return 0.0
    return 1.0 - (delta / window_seconds)


def _tactic_signal(left, right):
    if not left["tactics"] or not right["tactics"]:
        return 0.0
    overlap = left["tactics"] & right["tactics"]
    if not overlap:
        return 0.0
    union = left["tactics"] | right["tactics"]
    return len(overlap) / len(union)


def score_edge(left, right, *, window_seconds, min_shared_entities):
    """Return (score, shared_entities). Score is 0 when the entity floor is unmet."""
    shared = shared_pairs(left, right)
    if len(shared) < max(1, min_shared_entities):
        return 0.0, shared

    score = (
        ENTITY_SIGNAL_WEIGHT * _entity_signal(shared)
        + TIME_SIGNAL_WEIGHT * _time_signal(left, right, window_seconds)
        + TACTIC_SIGNAL_WEIGHT * _tactic_signal(left, right)
    )
    return round(min(1.0, score), 4), shared


def connected_components(nodes, *, window_seconds, min_shared_entities, threshold):
    """Group nodes whose pairwise score reaches the threshold.

    Union-find over the edges rather than transitive closure of raw entity
    sharing, so a weak link cannot silently merge two unrelated groups.
    """
    parent = list(range(len(nodes)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(a, b):
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            parent[max(root_a, root_b)] = min(root_a, root_b)

    edge_scores = {}
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            score, _shared = score_edge(
                nodes[i],
                nodes[j],
                window_seconds=window_seconds,
                min_shared_entities=min_shared_entities,
            )
            if score >= threshold:
                union(i, j)
                edge_scores[(i, j)] = score

    groups = {}
    for index in range(len(nodes)):
        groups.setdefault(find(index), []).append(index)

    result = []
    for root, indexes in groups.items():
        if len(indexes) < 2:
            # A single Case is not a cluster; it is just a Case.
            continue
        member_scores = [
            score for (i, j), score in edge_scores.items() if i in indexes and j in indexes
        ]
        link_score = round(sum(member_scores) / len(member_scores), 4) if member_scores else 0.0
        result.append({"indexes": sorted(indexes), "link_score": link_score})
    return sorted(result, key=lambda group: group["indexes"])
