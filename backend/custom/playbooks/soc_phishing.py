from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích Email Phishing/SPAM"
    DESC = "Phân tích cảnh báo email phishing/SPAM theo playbook SOC 9 bước."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_phishing"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích Email Phishing/SPAM requires a linked case.")
        return run_case_playbook(self)
