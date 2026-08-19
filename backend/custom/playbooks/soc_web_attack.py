from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích Tấn công Web"
    DESC = "Phân tích cảnh báo tấn công web theo playbook SOC."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_web_attack"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích Tấn công Web requires a linked case.")
        return run_case_playbook(self)
