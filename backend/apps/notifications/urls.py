from django.urls import include, path
from rest_framework.routers import DefaultRouter

from apps.notifications.views import (
    NotificationDestinationViewSet,
    NotificationOutboxViewSet,
    NotificationPreviewView,
    NotificationSendView,
    NotificationTestView,
)

router = DefaultRouter()
router.register("notification-destinations", NotificationDestinationViewSet, basename="notification-destination")
router.register("notification-messages", NotificationOutboxViewSet, basename="notification-message")

urlpatterns = [
    path("notifications/test/", NotificationTestView.as_view(), name="notification-test"),
    path("notifications/send/", NotificationSendView.as_view(), name="notification-send"),
    path("notifications/preview/", NotificationPreviewView.as_view(), name="notification-preview"),
    path(
        "notification-messages/<uuid:pk>/retry/",
        NotificationOutboxViewSet.as_view({"post": "retry"}),
        name="notification-message-retry",
    ),
    path("", include(router.urls)),
]
