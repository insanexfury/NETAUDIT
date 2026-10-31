"""Create a compact PDF security report from persisted SQLite analysis results."""
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from app.config import REPORT_DIR


def generate_report(analysis, alerts, statistics) -> Path:
    """Write an exportable report containing the analysis summary and alert evidence."""
    output = REPORT_DIR / f"netaudit_report_{analysis.id}.pdf"
    document = SimpleDocTemplate(str(output), pagesize=A4, rightMargin=36, leftMargin=36)
    styles = getSampleStyleSheet()
    story = [Paragraph("NetAudit Security Report", styles["Title"]), Spacer(1, 10)]
    story.append(Paragraph(f"PCAP: {escape(analysis.filename)}<br/>Status: {escape(analysis.status)}<br/>Threat score: {analysis.threat_score}/100 ({escape(analysis.severity)})", styles["BodyText"]))
    summary = [["Metric", "Value"], ["Packets", str(statistics.get("total_packets", 0))], ["Duration", f"{statistics.get('duration', 0)} seconds"], ["Total bytes", str(statistics.get("total_bytes", 0))], ["Unique source IPs", str(statistics.get("unique_source_ips", 0))]]
    story.extend([Spacer(1, 12), Paragraph("Traffic Summary", styles["Heading2"]), _table(summary), Spacer(1, 12), Paragraph("Security Findings", styles["Heading2"])])
    findings = [["Severity", "Finding", "Evidence"]] + [
        [escape(alert.severity), escape(alert.alert_type), escape(alert.evidence)]
        for alert in alerts
    ]
    story.append(_table(findings if len(findings) > 1 else [["Result", "No suspicious patterns triggered the configured rules."]]))
    document.build(story)
    return output


def _table(rows):
    table = Table(rows, repeatRows=1, colWidths=[100, 150, 250] if len(rows[0]) == 3 else [180, 320])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return table
