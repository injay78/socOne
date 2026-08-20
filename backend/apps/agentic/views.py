from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, status, viewsets
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response

from apps.accounts.permissions import IsAdmin, IsBusinessWriterOrReadOnly
from apps.agentic.hunting.service import HuntBudgetExceeded, execute_query, generate_plan
from apps.agentic.models import (
    HuntPlan,
    HuntQuery,
    IncidentCluster,
    TriageResult,
    TriageSuppression,
)
from apps.agentic.serializers import (
    HuntPlanSerializer,
    HuntQuerySerializer,
    IncidentClusterSerializer,
    TriageOverrideSerializer,
    TriageResultSerializer,
    TriageSuppressionSerializer,
)
from apps.agentic.triage.service import apply_human_verdict
from apps.common.advanced_filters import AdvancedFilterBackend


class TriageResultViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = TriageResult.objects.select_related("case", "llm_call", "human_verdict_by").all()
    serializer_class = TriageResultSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    filterset_fields = ("verdict", "needs_human", "case")
    search_fields = ("case__case_id", "case__title", "reasoning_en", "reasoning_vi")
    ordering_fields = ("created_at", "confidence", "verdict")
    advanced_filter_fields = {
        "verdict": "select",
        "needs_human": "select",
        "confidence": "number",
        "prompt_family": "text",
        "created_at": "date",
    }

    @transaction.atomic
    def create_override(self, request, pk=None):
        result = self.get_object()
        serializer = TriageOverrideSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        updated = apply_human_verdict(
            result,
            verdict=serializer.validated_data["verdict"],
            user=request.user,
            note=serializer.validated_data.get("note", ""),
        )
        return Response(TriageResultSerializer(updated).data, status=status.HTTP_200_OK)


class TriageSuppressionViewSet(viewsets.ModelViewSet):
    queryset = TriageSuppression.objects.select_related("created_by").all()
    serializer_class = TriageSuppressionSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    filterset_fields = ("match_type", "enabled")
    search_fields = ("pattern", "reason")
    ordering_fields = ("created_at", "expires_at", "match_type")
    advanced_filter_fields = {
        "match_type": "select",
        "pattern": "text",
        "enabled": "select",
        "expires_at": "date",
    }

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user if self.request.user.is_authenticated else None)


class IncidentClusterViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = IncidentCluster.objects.prefetch_related("members__case", "members__alert").all()
    serializer_class = IncidentClusterSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    filterset_fields = ("status",)
    search_fields = ("cluster_id", "title")
    ordering_fields = ("created_at", "window_end", "link_score", "case_count", "alert_count")
    advanced_filter_fields = {
        "status": "select",
        "link_score": "number",
        "case_count": "number",
        "alert_count": "number",
        "created_at": "date",
    }


class HuntPlanViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = HuntPlan.objects.select_related("cluster", "created_by", "llm_call").prefetch_related(
        "hypotheses__queries", "hypotheses__findings"
    )
    serializer_class = HuntPlanSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    filterset_fields = ("status", "mode", "cluster")
    search_fields = ("cluster__cluster_id", "cluster__title", "stop_reason")
    ordering_fields = ("created_at", "status", "mode")
    advanced_filter_fields = {
        "status": "select",
        "mode": "select",
        "created_at": "date",
    }

    def create_plan(self, request):
        cluster_id = (request.data or {}).get("cluster_id")
        if not cluster_id:
            return Response(
                {"detail": "cluster_id is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        cluster = (
            IncidentCluster.objects.filter(cluster_id=cluster_id).first()
            or IncidentCluster.objects.filter(pk=cluster_id).first()
        )
        if cluster is None:
            return Response(
                {"detail": f"Cluster {cluster_id} was not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        try:
            plan = generate_plan(cluster, mode=(request.data or {}).get("mode"), user=request.user)
        except HuntBudgetExceeded as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        return Response(HuntPlanSerializer(plan).data, status=status.HTTP_201_CREATED)

    def run_query(self, request, pk=None, query_pk=None):
        """Run one query of this plan. The UI asks for confirmation first."""
        query = HuntQuery.objects.filter(pk=query_pk, hypothesis__plan_id=pk).first()
        if query is None:
            return Response(
                {"detail": "Hunt query was not found on this plan."},
                status=status.HTTP_404_NOT_FOUND,
            )
        query = execute_query(query, user=request.user)
        return Response(HuntQuerySerializer(query).data, status=status.HTTP_200_OK)
