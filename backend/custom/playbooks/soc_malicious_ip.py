from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích Kết nối IP độc"
    DESC = "Phân tích cảnh báo kết nối tới IP độc theo playbook SOC."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_malicious_ip"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích Kết nối IP độc requires a linked case.")
        return run_case_playbook(self)
