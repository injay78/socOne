from django.urls import include, path
from rest_framework.routers import DefaultRouter

from apps.agentic.views import (
    HuntPlanViewSet,
    IncidentClusterViewSet,
    TriageResultViewSet,
    TriageSuppressionViewSet,
)

router = DefaultRouter()
router.register("triage-results", TriageResultViewSet, basename="triage-result")
router.register("triage-suppressions", TriageSuppressionViewSet, basename="triage-suppression")
router.register("clusters", IncidentClusterViewSet, basename="incident-cluster")
router.register("hunt-plans", HuntPlanViewSet, basename="hunt-plan")

urlpatterns = [
    path(
        "triage-results/<uuid:pk>/override/",
        TriageResultViewSet.as_view({"post": "create_override"}),
        name="triage-result-override",
    ),
    path(
        "hunt-plans/generate/",
        HuntPlanViewSet.as_view({"post": "create_plan"}),
        name="hunt-plan-generate",
    ),
    path(
        "hunt-plans/<uuid:pk>/queries/<uuid:query_pk>/run/",
        HuntPlanViewSet.as_view({"post": "run_query"}),
        name="hunt-plan-query-run",
    ),
    path("", include(router.urls)),
]
