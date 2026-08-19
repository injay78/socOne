from django.core.management.base import BaseCommand
from django.db import transaction

from apps.settings.models import PlaybookAutomationConfig, PlaybookAutomationRule
from apps.settings.runtime_config import invalidate

# Deterministic keyword routing derived from playbook/classify_alert.md.
# Substrings are matched case-insensitively over case title + alert rule names.
DEFAULT_RULES = [
    {
        "name": "Email Phishing/SPAM",
        "keywords": ["phish", "spam", "mail", "sender", "mailbox", "zap", "mdo"],
        "playbook_name": "SOC - Phân tích Email Phishing/SPAM",
        "priority": 100,
    },
    {
        "name": "Kết nối Domain độc",
        "keywords": ["malicious domain", "dns", "dga", "c2", "command and control", "url filtering", "domain"],
        "playbook_name": "SOC - Phân tích Kết nối Domain độc",
        "priority": 110,
    },
    {
        "name": "Kết nối IP độc",
        "keywords": ["malicious ip", "blacklist", "threat intel", "ip reputation", "tor exit", "bad ip"],
        "playbook_name": "SOC - Phân tích Kết nối IP độc",
        "priority": 120,
    },
    {
        "name": "Tấn công Web",
        "keywords": ["sql injection", "sqli", "xss", "webshell", "web shell", "web attack", "waf", "directory traversal", "path traversal"],
        "playbook_name": "SOC - Phân tích Tấn công Web",
        "priority": 130,
    },
    {
        "name": "Bruteforce nội bộ",
        "keywords": ["brute", "password spray", "failed login", "multiple failed", "4625", "ssh brute"],
        "playbook_name": "SOC - Phân tích Bruteforce nội bộ",
        "priority": 140,
    },
    {
        "name": "Xác thực bất thường từ Public",
        "keywords": ["impossible travel", "unusual location", "foreign ip", "sign-in", "signin", "vpn login", "mfa", "unusual user"],
        "playbook_name": "SOC - Phân tích Xác thực bất thường từ Public",
        "priority": 150,
    },
    {
        "name": "Thay đổi quyền hạn",
        "keywords": ["privilege", "admin group", "added to group", "4720", "4728", "4732", "group policy", "transport rule", "permission change"],
        "playbook_name": "SOC - Phân tích Thay đổi quyền hạn",
        "priority": 160,
    },
    {
        "name": "MultiCloud",
        "keywords": ["aws", "azure", "gcp", "cloudtrail", "s3 bucket", "iam policy", "access key"],
        "playbook_name": "SOC - Phân tích Cảnh báo MultiCloud",
        "priority": 170,
    },
    {
        "name": "File bất thường",
        "keywords": ["malware", "virus", "trojan", "ransom", "quarantine", "file hash", "malicious file", "mcscript", "amsi"],
        "playbook_name": "SOC - Phân tích File bất thường",
        "priority": 180,
    },
    {
        "name": "Tấn công lớp Network",
        "keywords": ["port scan", "scan detected", "lateral", "smb", "rdp from", "network attack", "recon"],
        "playbook_name": "SOC - Phân tích Tấn công lớp Network",
        "priority": 190,
    },
    {
        "name": "Process bất thường",
        "keywords": ["process", "command line", "powershell", "cmd.exe", "regsvr32", "rundll32", "mshta", "wmic", "script execution", "explorer.exe", "bash"],
        "playbook_name": "SOC - Phân tích Process bất thường",
        "priority": 200,
    },
    {
        "name": "Attack Hunter (High+)",
        "keywords": [],
        "min_severity": "High",
        "playbook_name": "SOC - Attack Hunter",
        "priority": 500,
    },
    {
        "name": "Freestyle (catch-all)",
        "keywords": [],
        "playbook_name": "SOC - Phân tích Freestyle",
        "priority": 900,
        "fallback": True,
    },
]


class Command(BaseCommand):
    help = "Seed default SOC playbook automation rules and enable automation."

    def add_arguments(self, parser):
        parser.add_argument("--disable", action="store_true", help="Seed rules but leave automation disabled.")

    @transaction.atomic
    def handle(self, *args, **options):
        created, updated = 0, 0
        for spec in DEFAULT_RULES:
            defaults = {
                "keywords": spec["keywords"],
                "min_severity": spec.get("min_severity", ""),
                "playbook_name": spec["playbook_name"],
                "priority": spec["priority"],
                "fallback": spec.get("fallback", False),
            }
            _, was_created = PlaybookAutomationRule.objects.update_or_create(
                name=spec["name"], defaults=defaults
            )
            if was_created:
                created += 1
            else:
                updated += 1

        config = PlaybookAutomationConfig.get_current()
        config.enabled = not options["disable"]
        config.save(update_fields=["enabled", "updated_at"])
        invalidate("playbook_automation")

        self.stdout.write(self.style.SUCCESS(
            f"Seeded {created} new + {updated} updated automation rules. "
            f"Automation enabled={config.enabled}."
        ))
