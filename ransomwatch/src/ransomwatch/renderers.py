"""Render Alert objects as text or JSON."""

from __future__ import annotations

import json

from .detector import Alert

_SEVERITY_LABEL = {"medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL", None: "-"}

_DISCLAIMER = (
    "This alert identifies behavior consistent with destructive bulk file "
    "transformation. It does not establish malicious intent or identify a "
    "malware family."
)


def render_text(alert: Alert) -> str:
    severity = _SEVERITY_LABEL[alert.severity]
    lines = [f"[{alert.status.upper()}] {severity} {alert.classification} (actor={alert.actor})"]

    if not alert.telemetry_quality.get("process_attribution", False):
        lines.append(
            "  note: no process attribution for this source -- actor is a host-wide pool, "
            "not a verified single process"
        )

    for rule in alert.rules_fired:
        evidence = alert.evidence.get(rule, {})
        detail = " ".join(f"{k}={v}" for k, v in evidence.items())
        lines.append(f"  - {rule}: {detail}")

    if alert.status != "recovered":
        lines.append(f"  {_DISCLAIMER}")

    return "\n".join(lines)


def render_json(alert: Alert) -> str:
    return json.dumps(alert.as_dict(), sort_keys=True)
