from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_ioc_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Kiểm tra File (IOC)"
    DESC = "Kiểm tra từng file/hash artifact của case theo playbook phân tích file."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_check_file"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Kiểm tra File (IOC) requires a linked case.")
        return run_ioc_playbook(self, artifact_types=("Hash", "File Name", "File", ))
