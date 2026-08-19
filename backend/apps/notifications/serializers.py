from rest_framework import serializers

from apps.notifications.events import NotificationEvent
from apps.notifications.models import NotificationDestination, NotificationOutbox

VALID_EVENTS = {choice.value for choice in NotificationEvent}


class NotificationDestinationSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationDestination
        fields = (
            "id",
            "name",
            "channel",
            "chat_id",
            "message_thread_id",
            "language",
            "enabled",
            "event_types",
            "min_severity",
            "min_confidence",
            "verdict_filter",
            "source_filter",
            "min_asset_criticality",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")

    def validate_event_types(self, value):
        if value in (None, ""):
            return []
        if not isinstance(value, list):
            raise serializers.ValidationError("Event types must be a list.")
        unknown = [item for item in value if item not in VALID_EVENTS]
        if unknown:
            raise serializers.ValidationError(f"Unknown event types: {', '.join(unknown)}")
        return value

    def validate_min_confidence(self, value):
        if value < 0 or value > 1:
            raise serializers.ValidationError("Minimum confidence must be between 0 and 1.")
        return value


class NotificationOutboxSerializer(serializers.ModelSerializer):
    destination_name = serializers.CharField(source="destination.name", read_only=True, default="")

    class Meta:
        model = NotificationOutbox
        fields = (
            "id",
            "event_type",
            "destination",
            "destination_name",
            "status",
            "attempts",
            "aggregated_count",
            "last_error",
            "rendered_text",
            "scheduled_for",
            "sent_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class NotificationTestSerializer(serializers.Serializer):
    destination = serializers.UUIDField(required=False)
    chat_id = serializers.CharField(required=False, allow_blank=True)
    message_thread_id = serializers.CharField(required=False, allow_blank=True)
    text = serializers.CharField(required=False, allow_blank=True, max_length=2000)

    def validate(self, attrs):
        if not attrs.get("destination") and not attrs.get("chat_id"):
            raise serializers.ValidationError("Provide a destination id or a chat_id.")
        return attrs


class NotificationSendSerializer(serializers.Serializer):
    event_type = serializers.ChoiceField(choices=sorted(VALID_EVENTS))
    payload = serializers.DictField(required=False, default=dict)
