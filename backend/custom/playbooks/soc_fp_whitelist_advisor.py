from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - FP Whitelist Advisor"
    DESC = "Đề xuất luật whitelist phạm vi hẹp cho cảnh báo false positive."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_fp_whitelist_advisor"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - FP Whitelist Advisor requires a linked case.")
        return run_case_playbook(self, enrich_ti=False)
