"""Transparent, non-probabilistic score calculation from rule-based alerts."""
from collections import Counter


def score_alerts(alerts: list[dict]) -> tuple[int, str, list[str]]:
    """Sum one maximum contribution per rule type to avoid repeated-window inflation."""
    contributions = {}
    for alert in alerts:
        alert_type = alert["alert_type"]
        contributions[alert_type] = max(contributions.get(alert_type, 0), alert["score"])
    score = min(100, sum(contributions.values()))
    if score >= 80:
        severity = "Critical"
    elif score >= 60:
        severity = "High"
    elif score >= 30:
        severity = "Medium"
    else:
        severity = "Low"
    reasons = list(Counter(contributions).keys())
    return score, severity, reasons
