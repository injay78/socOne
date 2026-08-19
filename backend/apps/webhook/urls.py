from django.urls import path

from apps.webhook.views import KibanaWebhookView, QRadarWebhookView, SplunkWebhookView

urlpatterns = [
    path("webhook/splunk/", SplunkWebhookView.as_view(), name="webhook-splunk"),
    path("webhook/kibana/", KibanaWebhookView.as_view(), name="webhook-kibana"),
    path("webhook/qradar/", QRadarWebhookView.as_view(), name="webhook-qradar"),
]
