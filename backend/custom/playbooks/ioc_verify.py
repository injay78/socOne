from apps.agentic.ioc.service import verify_for_case
from apps.agentic.runtime.base import BasePlaybook


class Playbook(BasePlaybook):
    NAME = "IOC Verify"
    DESC = "Verify the indicators on this Case against threat intelligence and web sources, with citations."
    TAGS = ["Custom", "LLM", "Threat Intel"]
    RISK_LEVEL = "Low"
    PROMPT_SLUG = "ioc_verify"

    def run(self):
        if self.case is None:
            raise ValueError("IOC Verify playbook requires a linked case.")

        self.add_run_message(f"Verifying indicators for {self.case.case_id.upper()}.")
        records = verify_for_case(self.case)

        if not records:
            self.add_run_message("No verifiable indicators found on this case.")
            return "IOC verification finished: no verifiable indicators."

        summary = {}
        for record in records:
            summary[record.verdict] = summary.get(record.verdict, 0) + 1
            self.add_run_message(
                f"{record.indicator_type}:{record.indicator_value} -> {record.verdict} "
                f"({len(record.references)} reference(s))"
            )

        write_enrichments(self.case, records)
        breakdown = ", ".join(f"{count} {verdict}" for verdict, count in sorted(summary.items()))
        return f"IOC verification completed for {len(records)} indicator(s): {breakdown}."


def write_enrichments(case, records):
    """Persist verification output as Enrichment records on the Case."""
    from apps.enrichments.models import Enrichment, EnrichmentProvider, EnrichmentType

    for record in records:
        Enrichment.objects.create(
            case=case,
            type=EnrichmentType.THREAT_INTELLIGENCE,
            provider=EnrichmentProvider.ASP_IOC_VERIFY,
            name=f"{record.indicator_type}:{record.indicator_value} — {record.verdict}",
            uid=f"ioc-verify:{record.indicator_type}:{record.indicator_value}",
            value=record.indicator_value[:500],
            desc=record.notes_vi or record.notes_en,
            data={
                "indicator_type": record.indicator_type,
                "indicator_value": record.indicator_value,
                "verdict": record.verdict,
                "confidence": record.confidence,
                "categories": record.categories,
                "references": record.references,
                "sources_used": record.sources_used,
                "injection_flags": record.injection_flags,
                "rejected_references": len(record.rejected_references or []),
            },
        )
