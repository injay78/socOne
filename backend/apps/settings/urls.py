from django.urls import include, path
from rest_framework.routers import DefaultRouter

from apps.audit.views import AdminAuditLogViewSet
from .custom_views import (
    CustomDefinitionsModuleView,
    CustomDefinitionsPlaybookView,
    CustomDefinitionsSiemView,
    CustomModuleStreamMessageView,
    CustomModuleStreamMessagesView,
)
from .views import (
    BrandingConfigView,
    CustomVariableViewSet,
    IocVerificationConfigView,
    McpServerConfigViewSet,
    EdrTrellixConfigView,
    EdrTrellixTestView,
    LLMProviderConfigViewSet,
    LdapConfigView,
    LdapTestView,
    RuntimeConfigView,
    SiemElkConfigView,
    SiemElkTestView,
    SiemQRadarConfigView,
    SiemQRadarTestView,
    TelegramNotificationConfigView,
    SiemSplunkConfigView,
    SiemSplunkTestView,
    PlaybookAutomationConfigView,
    PlaybookAutomationRuleViewSet,
    ThreatIntelAlienVaultOTXConfigView,
    ThreatIntelAlienVaultOTXTestView,
    ThreatIntelOpenCTIConfigView,
    ThreatIntelOpenCTITestView,
    ThreatIntelVirusTotalConfigView,
    ThreatIntelVirusTotalTestView,
    WorkerHealthView,
)


router = DefaultRouter()
router.register("llm-providers", LLMProviderConfigViewSet, basename="llm-provider")
router.register("mcp-servers", McpServerConfigViewSet, basename="mcp-server")
router.register("playbook-automation/rules", PlaybookAutomationRuleViewSet, basename="playbook-automation-rule")
router.register("audit-logs", AdminAuditLogViewSet, basename="settings-audit-log")

custom_router = DefaultRouter()
custom_router.register("variables", CustomVariableViewSet, basename="custom-variable")

urlpatterns = [
    path("settings/threat-intel/otx/", ThreatIntelAlienVaultOTXConfigView.as_view(), name="threat-intel-otx-config"),
    path("settings/threat-intel/otx/test/", ThreatIntelAlienVaultOTXTestView.as_view(), name="threat-intel-otx-test"),
    path("settings/threat-intel/opencti/", ThreatIntelOpenCTIConfigView.as_view(), name="threat-intel-opencti-config"),
    path("settings/threat-intel/opencti/test/", ThreatIntelOpenCTITestView.as_view(), name="threat-intel-opencti-test"),
    path("settings/threat-intel/virustotal/", ThreatIntelVirusTotalConfigView.as_view(), name="threat-intel-virustotal-config"),
    path("settings/threat-intel/virustotal/test/", ThreatIntelVirusTotalTestView.as_view(), name="threat-intel-virustotal-test"),
    path("settings/playbook-automation/", PlaybookAutomationConfigView.as_view(), name="playbook-automation-config"),
    path("settings/siem/splunk/", SiemSplunkConfigView.as_view(), name="siem-splunk-config"),
    path("settings/siem/splunk/test/", SiemSplunkTestView.as_view(), name="siem-splunk-test"),
    path("settings/siem/elk/", SiemElkConfigView.as_view(), name="siem-elk-config"),
    path("settings/siem/elk/test/", SiemElkTestView.as_view(), name="siem-elk-test"),
    path("settings/siem/qradar/", SiemQRadarConfigView.as_view(), name="siem-qradar-config"),
    path("settings/siem/qradar/test/", SiemQRadarTestView.as_view(), name="siem-qradar-test"),
    path("settings/edr/trellix/", EdrTrellixConfigView.as_view(), name="edr-trellix-config"),
    path("settings/edr/trellix/test/", EdrTrellixTestView.as_view(), name="edr-trellix-test"),
    path("settings/notifications/telegram/", TelegramNotificationConfigView.as_view(), name="telegram-config"),
    path("settings/ioc-verification/", IocVerificationConfigView.as_view(), name="ioc-verification-config"),
    path("branding/", BrandingConfigView.as_view(), name="branding-config"),
    path("settings/branding/", BrandingConfigView.as_view(), name="branding-config-settings"),
    path("settings/ldap/", LdapConfigView.as_view(), name="ldap-config"),
    path("settings/ldap/test/", LdapTestView.as_view(), name="ldap-test"),
    path("settings/runtime/", RuntimeConfigView.as_view(), name="runtime-config"),
    path("settings/workers/", WorkerHealthView.as_view(), name="worker-health"),
    path("custom/modules/", CustomDefinitionsModuleView.as_view(), name="custom-definitions-modules"),
    path("custom/modules/stream/messages/", CustomModuleStreamMessagesView.as_view(), name="custom-module-stream-messages"),
    path("custom/modules/stream/message/", CustomModuleStreamMessageView.as_view(), name="custom-module-stream-message"),
    path("custom/playbooks/", CustomDefinitionsPlaybookView.as_view(), name="custom-definitions-playbooks"),
    path("custom/siem/", CustomDefinitionsSiemView.as_view(), name="custom-definitions-siem"),
    path("custom/", include(custom_router.urls)),
    path("settings/", include(router.urls)),
]
