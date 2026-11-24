"""Checking the model's reply before an analyst sees it. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

from dataclasses import dataclass, field
import html
import json
import re
from urllib.parse import urlsplit

from .normalize import detect_injection  # noqa: F401  (used by triage)

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
NEXT_STEPS = {"escalate_to_analyst", "request_more_context", "monitor", "open_incident"}
ALLOWED_LINK_HOSTS = {"attack.mitre.org", "hisn.local"}


class Rejected(Exception):
    """Raised by parse_model_output / triage when the reply cannot be accepted. Keeps .reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class TriageResult:
    severity: str
    summary_html: str
    next_step: str
    related_alert_ids: list[str]
    flags: list[str] = field(default_factory=list)


def parse_model_output(raw: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Parse, validate and clean one model reply. See README.md for the exact seven-step order."""
    text = raw.strip()
    lines = text.splitlines()
    if len(lines) >= 2 and re.fullmatch(r"```(?:json)?", lines[0].strip(), flags=re.IGNORECASE) and lines[-1].strip() == "```":
        text = "\\n".join(lines[1:-1]).strip()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        raise Rejected("not_json")
    if not isinstance(data, dict):
        raise Rejected("not_json")

    forbidden_keys = {"action", "actions", "tool_call", "tool_calls", "function_call"}

    def contains_forbidden_key(value):
        if isinstance(value, dict):
            return any(
                key in forbidden_keys or contains_forbidden_key(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(contains_forbidden_key(item) for item in value)
        return False

    if contains_forbidden_key(data) or (
        isinstance(data.get("next_step"), str) and "close" in data["next_step"].casefold()
    ):
        raise Rejected("forbidden_action")

    severity = data.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise Rejected("bad_severity")
    next_step = data.get("next_step")
    if not isinstance(next_step, str) or next_step not in NEXT_STEPS:
        raise Rejected("bad_next_step")
    summary_value = data.get("summary")
    if not isinstance(summary_value, str) or not summary_value.strip() or len(summary_value.strip()) > 600:
        raise Rejected("bad_summary")
    summary = summary_value.strip()
    related = data.get("related_alert_ids", [])
    if not isinstance(related, list) or any(not isinstance(item, str) for item in related):
        raise Rejected("bad_related_alert_ids")

    if any(match != tenant_id for match in re.findall(r"\bTEN-\d{3}\b", summary)):
        raise Rejected("cross_tenant_reference")

    flags = set()
    clean_ids = []
    seen = set()
    unknown = False
    for alert_id in related:
        if alert_id in seen:
            continue
        seen.add(alert_id)
        if alert_id not in known_alert_ids:
            unknown = True
            continue
        clean_ids.append(alert_id)
    if unknown:
        flags.add("unknown_alert_id")

    image_pattern = re.compile(r"!\[[^\]]*\]\([^)]*\)")
    summary, image_count = image_pattern.subn("[image removed]", summary)
    if image_count:
        flags.add("image_removed")

    # Protect approved markdown links while sanitising bare URLs.
    link_pattern = re.compile(r"\[([^\]]+)\]\(((?:[^()]|\([^()]*\))*)\)")
    protected = []
    def clean_link(match):
        label, url = match.group(1), match.group(2).strip()
        try:
            parsed = urlsplit(url)
            allowed = parsed.scheme.lower() in {"http", "https"} and parsed.hostname in ALLOWED_LINK_HOSTS
        except ValueError:
            allowed = False
        if allowed:
            token = f"ZZZKEPTLINK{len(protected)}ZZZ"
            protected.append((token, match.group(0)))
            return token
        flags.add("link_removed")
        return label

    summary = link_pattern.sub(clean_link, summary)
    bare_url = re.compile(r"https?://[^\s<>\]\[)]+", re.IGNORECASE)
    def clean_bare(match):
        url = match.group(0).rstrip(".,;:!?")
        suffix = match.group(0)[len(url):]
        try:
            parsed = urlsplit(url)
            allowed = parsed.scheme.lower() in {"http", "https"} and parsed.hostname in ALLOWED_LINK_HOSTS
        except ValueError:
            allowed = False
        if allowed:
            return match.group(0)
        flags.add("link_removed")
        return "[link removed]" + suffix

    summary = bare_url.sub(clean_bare, summary)
    for token, original in protected:
        summary = summary.replace(token, original)

    return TriageResult(
        severity=severity,
        summary_html=html.escape(summary, quote=True),
        next_step=next_step,
        related_alert_ids=clean_ids,
        flags=sorted(flags),
    )


def triage(alert: dict, raw_output: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Run detect_injection over every string in `alert`, then parse_model_output; if any signal
    fired, add flags and never let the result end up quieter than it would otherwise be."""
    signals = set()

    def scan(value):
        if isinstance(value, str):
            signals.update(detect_injection(value))
        elif isinstance(value, dict):
            for key, item in value.items():
                scan(key)
                scan(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                scan(item)

    scan(alert)
    result = parse_model_output(
        raw_output, tenant_id=tenant_id, known_alert_ids=known_alert_ids
    )
    if signals:
        flags = set(result.flags)
        flags.add("possible_injection")
        flags.update(f"signal:{signal}" for signal in signals)
        result.flags = sorted(flags)
        if SEVERITIES.index(result.severity) < SEVERITIES.index("high"):
            result.severity = "high"
        if result.next_step == "monitor":
            result.next_step = "escalate_to_analyst"
    return result
