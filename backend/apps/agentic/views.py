from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, status, viewsets
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response

from apps.accounts.permissions import IsAdmin, IsBusinessWriterOrReadOnly
from apps.agentic.models import TriageResult, TriageSuppression
from apps.agentic.serializers import (
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
