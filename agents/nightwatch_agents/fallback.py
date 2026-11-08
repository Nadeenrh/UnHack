"""Deterministic fallback results and request-local stage progress."""

from datetime import datetime, timezone

from .context import build_context, evidence_from_quotes
from .contracts import RESULT_VALIDATOR

STAGES = ("triage", "intel", "investigator")
REASONS = {
    "live_calls_disabled": "Live calls are disabled; no model or provider requests were made.",
    "configuration_unavailable": "The live workflow could not start with the available configuration.",
    "analysis_failed": "AI analysis was unavailable or did not pass validation.",
    "workflow_deadline": "The investigation reached its workflow deadline.",
    "service_deadline": "The investigation reached its service deadline; detailed stage progress is unavailable.",
    "invalid_service_result": "The investigation result was discarded because it failed internal validation.",
}


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_record(stage, start, model, summary, status="succeeded"):
    return {"agent": stage, "status": status, "model": model,
            "started_at": start, "finished_at": now(), "output_summary": summary}


class Progress:
    """Only validated evidence is retained; never retain model prose or errors."""

    def __init__(self, context):
        self.context = context
        self.runs = []
        self.active = None
        self.log_evidence = []
        self.intel_evidence = []

    def start(self, stage, model=None):
        self.active = (stage, now(), model)

    def finish(self, summary, status="succeeded"):
        if self.active is None:
            raise RuntimeError("Cannot finish a stage that has not been started")
        stage, start, model = self.active
        self.runs.append(run_record(stage, start, model, summary, status))
        self.active = None


def provisional_severity(request):
    levels = []
    for event in [request["alert"], *request["related_events"]]:
        rule = event.get("rule")
        level = rule.get("level") if isinstance(rule, dict) else None
        if type(level) is int:
            levels.append(level)
    level = max(levels, default=0)
    return "critical" if level >= 12 else "high" if level >= 10 else "medium" if level >= 7 else "low"


def fallback_result(request, reason, progress=None):
    reason_text = REASONS[reason]  # Only code-owned messages, never exception text.
    unknown_progress = progress is None and reason in ("service_deadline", "invalid_service_result")
    progress = progress or Progress(build_context(request))
    context = progress.context
    if progress.active:
        progress.finish("Failed: " + reason_text + " Rule-based fallback returned.", "failed")
    runs = list(progress.runs)
    recorded = {run["agent"] for run in runs}
    for stage in STAGES:
        if stage not in recorded and not unknown_progress:
            runs.append(run_record(stage, now(), None,
                                   "Skipped: " + reason_text + " Rule-based fallback returned.", "skipped"))
    runs.sort(key=lambda run: STAGES.index(run["agent"]))
    # Observations are exact quotations, not interpretations of attacker text.
    observations = []
    for field in context["records"]:
        if field["observed_at"] and field["text"].strip() and field["ref"].endswith((
                "/rule/description", "/data/win/system/eventID", "/data/win/eventdata/commandLine")):
            observations.append({"ref": field["ref"], "quote": field["text"][:300]})
        if len(observations) == 6:
            break
    evidence = []
    for item in [*progress.log_evidence, *evidence_from_quotes(observations, context), *progress.intel_evidence]:
        if item not in evidence:
            evidence.append(item)
    notes = [
        "Fallback analysis (rule-based). " + reason_text,
        "Severity reflects supplied Wazuh rule levels only; compromise is undetermined.",
        "No AI conclusion or action recommendation is retained. Ask your security contact to review the original alerts.",
    ]
    if unknown_progress:
        notes.append("Detailed stage progress is unavailable; no stage outcome is asserted.")
    if progress.intel_evidence:
        notes.append("Previously validated historical provider reports are retained as evidence; they do not establish compromise or safety.")
    else:
        notes.append("External threat intelligence unavailable; no reputation result was verified.")
    if not evidence:
        notes.append("No timestamped evidence could be retained.")
    if context["truncated"]:
        notes.append("Some events or fields were omitted from the bounded evidence context.")
    result = {
        "contract_version": "0.1", "incident_id": request["incident_id"],
        "title": "Fallback analysis — investigation needs human review",
        "summary": " ".join(notes), "severity": provisional_severity(request),
        "verdict": "undetermined", "confidence": 0, "mitre": [], "evidence": evidence,
        "injection_detected": context["injection_detected"],
        "injection_notes": ("Instruction-like text detected by a best-effort heuristic; treated as data."
                            if context["injection_detected"] else
                            "No known instruction pattern detected; this does not prove logs are safe."),
        "recommended_actions": [], "agent_runs": runs,
    }
    RESULT_VALIDATOR.validate(result)
    return result
