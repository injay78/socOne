from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích Cảnh báo MultiCloud"
    DESC = "Phân tích cảnh báo bất thường trên AWS/Azure/GCP theo playbook SOC."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_multicloud"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích Cảnh báo MultiCloud requires a linked case.")
        return run_case_playbook(self)
