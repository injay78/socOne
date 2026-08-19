from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích File bất thường"
    DESC = "Phân tích cảnh báo file bất thường theo playbook SOC."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_abnormal_file"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích File bất thường requires a linked case.")
        return run_case_playbook(self)
