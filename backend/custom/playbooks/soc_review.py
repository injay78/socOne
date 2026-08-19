from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - QA Review"
    DESC = "Senior SOC QA review lại chất lượng phân tích của case."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_review"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - QA Review requires a linked case.")
        return run_case_playbook(self, enrich_ti=False)
