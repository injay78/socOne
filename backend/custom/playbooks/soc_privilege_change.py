from apps.agentic.runtime.base import BasePlaybook
from apps.agentic.services.soc_playbook import run_case_playbook


class Playbook(BasePlaybook):
    NAME = "SOC - Phân tích Thay đổi quyền hạn"
    DESC = "Phân tích cảnh báo thay đổi quyền hạn/cấu hình theo playbook SOC."
    TAGS = ["Custom", "LLM", "SOC"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "soc_privilege_change"

    def run(self):
        if self.case is None:
            raise ValueError("SOC - Phân tích Thay đổi quyền hạn requires a linked case.")
        return run_case_playbook(self)
