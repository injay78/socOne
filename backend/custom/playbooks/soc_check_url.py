from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_ioc_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Kiểm tra URL (IOC)"
    DESC = "Kiểm tra từng URL artifact của case theo playbook phân tích URL."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_check_url"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Kiểm tra URL (IOC) requires a linked case.")
        return run_ioc_playbook(self, artifact_types=("URL String", "Uniform Resource Locator", ))
