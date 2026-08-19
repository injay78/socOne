import logging

from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, status, views, viewsets
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.response import Response

from apps.accounts.permissions import IsAdmin
from apps.common.advanced_filters import AdvancedFilterBackend
from apps.notifications.models import (
    NotificationDestination,
    NotificationOutbox,
    OutboxStatus,
)
from apps.notifications.rendering import render_message
from apps.notifications.serializers import (
    NotificationDestinationSerializer,
    NotificationOutboxSerializer,
    NotificationSendSerializer,
    NotificationTestSerializer,
)
from apps.notifications.service import emit
from apps.notifications.telegram import TelegramError, describe_error, send_message
from apps.settings.runtime_config import get_telegram_config, invalidate

logger = logging.getLogger(__name__)


class NotificationDestinationViewSet(viewsets.ModelViewSet):
    queryset = NotificationDestination.objects.all()
    serializer_class = NotificationDestinationSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    filterset_fields = ("enabled", "channel")
    search_fields = ("name", "chat_id")
    ordering_fields = ("name", "created_at")
    advanced_filter_fields = {
        "name": "text",
        "chat_id": "text",
        "enabled": "select",
        "language": "select",
    }

    @transaction.atomic
    def perform_create(self, serializer):
        serializer.save()
        transaction.on_commit(lambda: invalidate("notifications"))

    @transaction.atomic
    def perform_update(self, serializer):
        serializer.save()
        transaction.on_commit(lambda: invalidate("notifications"))


class NotificationOutboxViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = NotificationOutbox.objects.select_related("destination").all()
    serializer_class = NotificationOutboxSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdmin]
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    filterset_fields = ("status", "event_type", "destination")
    search_fields = ("event_type", "last_error")
    ordering_fields = ("created_at", "sent_at", "status")
    advanced_filter_fields = {
        "event_type": "select",
        "status": "select",
        "created_at": "date",
    }

    def retry(self, request, pk=None):
        message = self.get_object()
        if message.status != OutboxStatus.FAILED:
            return Response(
                {"detail": "Only failed messages can be retried."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        message.status = OutboxStatus.PENDING
        message.attempts = 0
        message.last_error = ""
        message.scheduled_for = None
        message.save(update_fields=["status", "attempts", "last_error", "scheduled_for", "updated_at"])
        return Response(NotificationOutboxSerializer(message).data)


class NotificationTestView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = NotificationTestSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        config = get_telegram_config()

        if not config["bot_token"]:
            return Response(
                {"success": False, "detail": "Telegram bot token is not configured."},
                status=status.HTTP_200_OK,
            )

        destination = None
        destination_id = serializer.validated_data.get("destination")
        if destination_id:
            destination = NotificationDestination.objects.filter(pk=destination_id).first()
            if destination is None:
                return Response(
                    {"success": False, "detail": "Destination not found."},
                    status=status.HTTP_200_OK,
                )

        chat_id = serializer.validated_data.get("chat_id") or (destination.chat_id if destination else "")
        thread_id = serializer.validated_data.get("message_thread_id") or (
            destination.message_thread_id if destination else ""
        )
        text = serializer.validated_data.get("text") or "<b>ASP test message</b>\nNotification channel is working."

        try:
            send_message(
                bot_token=config["bot_token"],
                chat_id=chat_id,
                text=text,
                message_thread_id=thread_id,
            )
        except TelegramError as exc:
            # Surface the real Telegram error: this is where misconfiguration concentrates.
            return Response(
                {"success": False, "detail": describe_error(exc), "raw": str(exc)[:300]},
                status=status.HTTP_200_OK,
            )

        return Response({"success": True, "detail": f"Test message delivered to {chat_id}."})


class NotificationSendView(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = NotificationSendSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        queued = emit(
            serializer.validated_data["event_type"],
            serializer.validated_data.get("payload") or {},
        )
        return Response(
            {
                "queued": len(queued),
                "message_ids": [str(item.pk) for item in queued],
            },
            status=status.HTTP_202_ACCEPTED,
        )


class NotificationPreviewView(views.APIView):
    """Render a template without sending, so operators can check formatting."""

    permission_classes = [permissions.IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = NotificationSendSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        language = str((request.data or {}).get("language") or "vi")
        text = render_message(
            serializer.validated_data["event_type"],
            serializer.validated_data.get("payload") or {},
            language=language,
        )
        return Response({"text": text, "length": len(text)})
