from django.urls import include, path
from rest_framework.routers import DefaultRouter

from apps.agentic.views import TriageResultViewSet, TriageSuppressionViewSet

router = DefaultRouter()
router.register("triage-results", TriageResultViewSet, basename="triage-result")
router.register("triage-suppressions", TriageSuppressionViewSet, basename="triage-suppression")

urlpatterns = [
    path(
        "triage-results/<uuid:pk>/override/",
        TriageResultViewSet.as_view({"post": "create_override"}),
        name="triage-result-override",
    ),
    path("", include(router.urls)),
]
