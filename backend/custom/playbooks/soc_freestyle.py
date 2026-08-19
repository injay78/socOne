from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích Freestyle"
    DESC = "Phân tích cảnh báo không map được category theo playbook SOC freestyle."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_freestyle"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích Freestyle requires a linked case.")
        return run_case_playbook(self)
