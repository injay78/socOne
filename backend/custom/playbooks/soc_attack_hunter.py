from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Attack Hunter"
    DESC = "Săn tấn công độc lập: adversarial pass trên toàn bộ evidence của case."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_attack_hunter"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Attack Hunter requires a linked case.")
        return run_case_playbook(self)
