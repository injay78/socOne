from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích Process bất thường"
    DESC = "Phân tích cảnh báo process bất thường theo playbook SOC."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_abnormal_process"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích Process bất thường requires a linked case.")
        return run_case_playbook(self)
