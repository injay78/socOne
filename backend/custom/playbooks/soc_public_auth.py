from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích Xác thực bất thường từ Public"
    DESC = "Phân tích cảnh báo xác thực bất thường từ IP public theo playbook SOC."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_public_auth"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích Xác thực bất thường từ Public requires a linked case.")
        return run_case_playbook(self)
