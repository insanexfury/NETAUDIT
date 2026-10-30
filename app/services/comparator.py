"""Reusable PCAP-to-PCAP comparison logic for NetAudit."""
from collections import Counter
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from app.services.analyzer import analyze_packets
from app.services.pcap_parser import parse_pcap


def _packet_objects_from_capture(path: Path):
    """Convert parser output into objects that the existing analyzer understands."""
    packets = []
    for telemetry in parse_pcap(path):
        packet = SimpleNamespace(**telemetry)
        if getattr(packet, "timestamp", None) is not None and not isinstance(packet.timestamp, datetime):
            packet.timestamp = None
        packets.append(packet)
    return packets


def _iso_or_none(value):
    return value.isoformat() if value is not None else None


def _protocol_rows(protocol_distribution):
    ordered = ["TCP", "UDP", "DNS", "HTTP", "TLS", "ICMP", "OTHER"]
    labels = sorted({*ordered, *protocol_distribution.keys()})
    rows = []
    for protocol in labels:
        count = protocol_distribution.get(protocol, 0)
        rows.append({"label": protocol, "count": count, "percentage": round((count / sum(protocol_distribution.values())) * 100, 2) if sum(protocol_distribution.values()) else 0})
    return rows


def _capture_summary(path: Path):
    packets = _packet_objects_from_capture(path)
    statistics, alerts, score, severity, reasons = analyze_packets(packets)
    timestamps = [packet.timestamp for packet in packets if getattr(packet, "timestamp", None) is not None]
    total_bytes = sum(getattr(packet, "packet_length", 0) for packet in packets)
    total_packets = len(packets)
    duration = statistics.get("duration", 0) or 0
    average_packet_size = round(total_bytes / total_packets, 2) if total_packets else 0
    bytes_per_second = round(total_bytes / duration, 2) if duration else 0
    packets_per_second = statistics.get("packets_per_second", 0)
    source_ip_counts = dict(Counter(packet.src_ip for packet in packets if getattr(packet, "src_ip", None)))
    destination_ip_counts = dict(Counter(packet.dst_ip for packet in packets if getattr(packet, "dst_ip", None)))
    source_ports = Counter(packet.dst_port for packet in packets if getattr(packet, "protocol", "OTHER") in {"TCP", "UDP"} and packet.dst_port is not None)
    tcp_ports = sorted({packet.dst_port for packet in packets if getattr(packet, "protocol", "OTHER") == "TCP" and packet.dst_port is not None})
    udp_ports = sorted({packet.dst_port for packet in packets if getattr(packet, "protocol", "OTHER") == "UDP" and packet.dst_port is not None})
    return {
        "filename": path.name,
        "packet_count": total_packets,
        "total_bytes": total_bytes,
        "capture_start": _iso_or_none(min(timestamps)) if timestamps else None,
        "capture_end": _iso_or_none(max(timestamps)) if timestamps else None,
        "duration": duration,
        "average_packet_size": average_packet_size,
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "protocol_distribution": statistics.get("protocol_distribution", {}),
        "protocol_rows": _protocol_rows(statistics.get("protocol_distribution", {})),
        "source_ip_counts": source_ip_counts,
        "destination_ip_counts": destination_ip_counts,
        "source_ips": sorted(source_ip_counts.keys()),
        "destination_ips": sorted(destination_ip_counts.keys()),
        "unique_tcp_destination_ports": len(tcp_ports),
        "unique_udp_destination_ports": len(udp_ports),
        "destination_port_counts": {str(port): count for port, count in source_ports.most_common(12)},
        "alerts": alerts,
        "alert_counts": dict(Counter(alert["alert_type"] for alert in alerts)),
        "threat_score": score,
        "severity": severity,
        "reasons": reasons,
        "statistics": statistics,
    }


def compare_capture_files(path_a: Path, path_b: Path):
    """Compare two captures with the same metrics used by the existing dashboard."""
    capture_a = _capture_summary(path_a)
    capture_b = _capture_summary(path_b)
    protocol_labels = sorted(set(capture_a["protocol_distribution"]) | set(capture_b["protocol_distribution"]))
    protocol_comparison = []
    for label in protocol_labels:
        count_a = capture_a["protocol_distribution"].get(label, 0)
        count_b = capture_b["protocol_distribution"].get(label, 0)
        total_a = capture_a["packet_count"]
        total_b = capture_b["packet_count"]
        protocol_comparison.append({
            "label": label,
            "a_count": count_a,
            "b_count": count_b,
            "a_percent": round((count_a / total_a) * 100, 2) if total_a else 0,
            "b_percent": round((count_b / total_b) * 100, 2) if total_b else 0,
            "difference": count_b - count_a,
        })

    source_ips_a = set(capture_a["source_ip_counts"])
    source_ips_b = set(capture_b["source_ip_counts"])
    destination_ips_a = set(capture_a["destination_ip_counts"])
    destination_ips_b = set(capture_b["destination_ip_counts"])

    aggregated_alert_types = set(capture_a["alert_counts"]) | set(capture_b["alert_counts"])
    alert_summary = {
        "shared_types": sorted(aggregated_alert_types & set(capture_a["alert_counts"]) & set(capture_b["alert_counts"])),
        "only_in_a": sorted(set(capture_a["alert_counts"]) - set(capture_b["alert_counts"])),
        "only_in_b": sorted(set(capture_b["alert_counts"]) - set(capture_a["alert_counts"])),
        "counts": {alert_type: {"a": capture_a["alert_counts"].get(alert_type, 0), "b": capture_b["alert_counts"].get(alert_type, 0)} for alert_type in sorted(aggregated_alert_types)},
    }

    return {
        "capture_a": capture_a,
        "capture_b": capture_b,
        "comparison": {
            "protocols": protocol_comparison,
            "source_ips": {
                "common": sorted(source_ips_a & source_ips_b),
                "only_in_a": sorted(source_ips_a - source_ips_b),
                "only_in_b": sorted(source_ips_b - source_ips_a),
            },
            "destination_ips": {
                "common": sorted(destination_ips_a & destination_ips_b),
                "only_in_a": sorted(destination_ips_a - destination_ips_b),
                "only_in_b": sorted(destination_ips_b - destination_ips_a),
            },
            "port_summary": {
                "common_destination_ports": sorted({*capture_a["destination_port_counts"], *capture_b["destination_port_counts"]} & set(capture_a["destination_port_counts"]) & set(capture_b["destination_port_counts"])),
                "only_in_a": sorted(set(capture_a["destination_port_counts"]) - set(capture_b["destination_port_counts"])),
                "only_in_b": sorted(set(capture_b["destination_port_counts"]) - set(capture_a["destination_port_counts"])),
                "tcp_unique_ports": {"a": capture_a["unique_tcp_destination_ports"], "b": capture_b["unique_tcp_destination_ports"]},
                "udp_unique_ports": {"a": capture_a["unique_udp_destination_ports"], "b": capture_b["unique_udp_destination_ports"]},
            },
            "alerts": alert_summary,
            "score_delta": capture_b["threat_score"] - capture_a["threat_score"],
            "severity_shift": capture_b["severity"],
        },
    }
