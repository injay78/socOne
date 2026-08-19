from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_ioc_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Kiểm tra Hash VirusTotal (IOC)"
    DESC = "Kiểm tra từng hash artifact của case trên VirusTotal theo playbook."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_check_hash"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Kiểm tra Hash VirusTotal (IOC) requires a linked case.")
        return run_ioc_playbook(self, artifact_types=("Hash", ))
