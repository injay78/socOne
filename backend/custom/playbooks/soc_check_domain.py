from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_ioc_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Kiểm tra Domain (IOC)"
    DESC = "Kiểm tra từng domain artifact của case theo playbook phân tích domain."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_check_domain"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Kiểm tra Domain (IOC) requires a linked case.")
        return run_ioc_playbook(self, artifact_types=("Hostname", ))
