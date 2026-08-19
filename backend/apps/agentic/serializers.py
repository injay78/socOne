from rest_framework import serializers

from apps.agentic.models import TriageResult, TriageSuppression


class TriageResultSerializer(serializers.ModelSerializer):
    case_readable_id = serializers.CharField(source="case.case_id", read_only=True)
    case_title = serializers.CharField(source="case.title", read_only=True)
    effective_verdict = serializers.CharField(read_only=True)
    ai_was_overridden = serializers.BooleanField(read_only=True)
    human_verdict_by_name = serializers.CharField(
        source="human_verdict_by.username", read_only=True, default=""
    )
    model_name = serializers.CharField(source="llm_call.model_name", read_only=True, default="")
    prompt_hash = serializers.CharField(source="llm_call.prompt_hash", read_only=True, default="")
    tokens_in = serializers.IntegerField(source="llm_call.tokens_in", read_only=True, default=None)
    tokens_out = serializers.IntegerField(source="llm_call.tokens_out", read_only=True, default=None)
    latency_ms = serializers.IntegerField(source="llm_call.latency_ms", read_only=True, default=None)

    class Meta:
        model = TriageResult
        fields = (
            "id",
            "case",
            "case_readable_id",
            "case_title",
            "verdict",
            "effective_verdict",
            "false_positive_class",
            "severity_ai",
            "impact_ai",
            "priority_ai",
            "confidence",
            "needs_human",
            "mitre_tactics",
            "mitre_techniques",
            "kill_chain_phase",
            "evidence",
            "recommended_actions",
            "reasoning_vi",
            "reasoning_en",
            "prompt_family",
            "facts",
            "entities",
            "asset_context",
            "missing_context",
            "quality_flags",
            "error",
            "suppressed_by",
            "human_verdict",
            "human_verdict_by",
            "human_verdict_by_name",
            "human_verdict_at",
            "human_verdict_note",
            "ai_was_overridden",
            "model_name",
            "prompt_hash",
            "tokens_in",
            "tokens_out",
            "latency_ms",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class TriageOverrideSerializer(serializers.Serializer):
    verdict = serializers.ChoiceField(choices=TriageResult._meta.get_field("verdict").choices)
    note = serializers.CharField(required=False, allow_blank=True, max_length=2000)


class TriageSuppressionSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source="created_by.username", read_only=True, default="")
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = TriageSuppression
        fields = (
            "id",
            "match_type",
            "pattern",
            "reason",
            "created_by",
            "created_by_name",
            "expires_at",
            "enabled",
            "is_active",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_by", "created_by_name", "is_active", "created_at", "updated_at")

    def validate_reason(self, value):
        if not str(value or "").strip():
            raise serializers.ValidationError("A suppression must state why it exists.")
        return value

    def validate_expires_at(self, value):
        from django.utils import timezone

        if value <= timezone.now():
            raise serializers.ValidationError("Expiry must be in the future. Suppressions cannot be permanent.")
        return value
