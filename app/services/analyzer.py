"""Explainable time-window traffic statistics and anomaly rules for NetAudit."""
from collections import Counter, defaultdict
from datetime import timedelta
from statistics import median
from app.config import AUTHENTICATION_PORTS, BRUTE_FORCE_ATTEMPTS, PORT_SCAN_UNIQUE_PORTS, TIME_WINDOW_SECONDS, VOLUME_MULTIPLIER
from app.services.threat_scoring import score_alerts


def _value(policy, name, default):
    return policy.get(name, default) if policy else default


def _windowed_packets(packets, window_seconds=TIME_WINDOW_SECONDS):
    """Group timestamped packets into fixed investigation windows."""
    valid = [packet for packet in packets if packet.timestamp]
    if not valid:
        return []
    start = min(packet.timestamp for packet in valid)
    windows = defaultdict(list)
    for packet in valid:
        index = int((packet.timestamp - start).total_seconds() // window_seconds)
        windows[index].append(packet)
    return [(start + timedelta(seconds=index * window_seconds), values) for index, values in sorted(windows.items())]


def _alert(alert_type, severity, source, destination, timestamp, evidence, score):
    return {"alert_type": alert_type, "severity": severity, "src_ip": source, "dst_ip": destination,
            "timestamp": timestamp, "description": f"{alert_type}: {evidence}", "evidence": evidence, "score": score}


def detect_port_scans(windows, policy=None):
    """Flag a source that contacts unusually many destination ports in one window."""
    threshold = _value(policy, "port_scan_unique_ports", PORT_SCAN_UNIQUE_PORTS)
    window_seconds = _value(policy, "time_window_seconds", TIME_WINDOW_SECONDS)
    score = _value(policy, "score_port_scan", 40)
    alerts = []
    for timestamp, packets in windows:
        port_sets = defaultdict(set)
        for packet in packets:
            if packet.src_ip and packet.dst_port is not None:
                port_sets[packet.src_ip].add(packet.dst_port)
        for source, ports in port_sets.items():
            if len(ports) >= threshold:
                evidence = f"{len(ports)} distinct destination ports contacted within {window_seconds} seconds (threshold: {threshold})."
                alerts.append(_alert("Possible Port Scan", "High", source, None, timestamp, evidence, score))
    return alerts


def detect_brute_force(windows, policy=None):
    """Flag repeated TCP connection attempts to common authentication service ports."""
    threshold = _value(policy, "brute_force_attempts", BRUTE_FORCE_ATTEMPTS)
    window_seconds = _value(policy, "time_window_seconds", TIME_WINDOW_SECONDS)
    score = _value(policy, "score_brute_force", 40)
    alerts = []
    for timestamp, packets in windows:
        attempts = Counter((packet.src_ip, packet.dst_ip, packet.dst_port) for packet in packets
                           if packet.protocol == "TCP" and packet.src_ip and packet.dst_ip and packet.dst_port in AUTHENTICATION_PORTS)
        for (source, destination, port), count in attempts.items():
            if count >= threshold:
                evidence = f"{count} TCP attempts to {destination}:{port} within {window_seconds} seconds (threshold: {threshold})."
                alerts.append(_alert("Possible Brute-Force Activity", "High", source, destination, timestamp, evidence, score))
    return alerts


def detect_abnormal_volume(windows, policy=None):
    """Compare each window's byte count against a simple median-based baseline."""
    if len(windows) < 3:
        return []
    bytes_per_window = [sum(packet.packet_length for packet in packets) for _, packets in windows]
    baseline = median(bytes_per_window)
    if baseline <= 0:
        return []
    multiplier = _value(policy, "volume_multiplier", VOLUME_MULTIPLIER)
    window_seconds = _value(policy, "time_window_seconds", TIME_WINDOW_SECONDS)
    score = _value(policy, "score_abnormal_volume", 30)
    alerts = []
    for (timestamp, packets), byte_count in zip(windows, bytes_per_window):
        if byte_count > baseline * multiplier:
            evidence = f"{byte_count} bytes in {window_seconds} seconds versus {baseline:.0f}-byte median baseline (multiplier: {multiplier:g}x)."
            alerts.append(_alert("Abnormal Traffic Volume", "Medium", None, None, timestamp, evidence, score))
    return alerts


def _tcp_flag_bits(value):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        labels = {part.strip().upper() for part in str(value or "").replace(",", " ").split()}
        return (0x02 if "SYN" in labels else 0) | (0x10 if "ACK" in labels else 0)


def detect_ddos_activity(windows, policy=None):
    """Detect possible distributed floods using volume, source diversity, and target concentration."""
    min_packets = _value(policy, "ddos_min_packets", 100)
    min_bytes = _value(policy, "ddos_min_bytes", 100_000)
    min_sources = _value(policy, "ddos_min_unique_sources", 10)
    min_share = _value(policy, "ddos_destination_share", 0.6)
    window_seconds = _value(policy, "time_window_seconds", TIME_WINDOW_SECONDS)
    score = _value(policy, "score_ddos", 45)
    alerts = []
    for timestamp, packets in windows:
        destinations = defaultdict(list)
        for packet in packets:
            if packet.dst_ip:
                destinations[packet.dst_ip].append(packet)
        for destination, targeted in destinations.items():
            sources = {packet.src_ip for packet in targeted if packet.src_ip}
            total_bytes = sum(packet.packet_length for packet in targeted)
            share = len(targeted) / len(packets) if packets else 0
            if (
                len(targeted) >= min_packets
                and total_bytes >= min_bytes
                and len(sources) >= min_sources
                and share >= min_share
            ):
                evidence = (
                    f"{len(targeted)} packets and {total_bytes} bytes to one destination in "
                    f"{window_seconds} seconds; {len(sources)} distinct sources; "
                    f"{share:.0%} destination concentration (minimums: {min_packets} packets, "
                    f"{min_bytes} bytes, {min_sources} sources, {min_share:.0%} concentration). "
                    "This is a heuristic indicator, not confirmation of a denial-of-service attack."
                )
                alerts.append(_alert("Possible DDoS Activity", "High", None, destination, timestamp, evidence, score))
    return alerts


def detect_syn_flood(windows, policy=None):
    """Estimate possible SYN floods from SYN-only counts and aggregate handshake response ratios."""
    min_syn = _value(policy, "syn_flood_min_packets", 100)
    min_sources = _value(policy, "syn_flood_min_unique_sources", 5)
    min_incomplete = _value(policy, "syn_flood_incomplete_ratio", 0.8)
    window_seconds = _value(policy, "time_window_seconds", TIME_WINDOW_SECONDS)
    score = _value(policy, "score_syn_flood", 45)
    alerts = []
    for timestamp, packets in windows:
        tcp_packets = [packet for packet in packets if packet.protocol == "TCP" and packet.dst_ip]
        for destination in {packet.dst_ip for packet in tcp_packets}:
            targeted = [packet for packet in tcp_packets if packet.dst_ip == destination]
            syn_only = [
                packet for packet in targeted
                if _tcp_flag_bits(getattr(packet, "tcp_flags", None)) & 0x02
                and not _tcp_flag_bits(getattr(packet, "tcp_flags", None)) & 0x10
            ]
            if not syn_only:
                continue
            sources = {packet.src_ip for packet in syn_only if packet.src_ip}
            syn_ack = sum(
                bool(_tcp_flag_bits(getattr(packet, "tcp_flags", None)) & 0x02 and _tcp_flag_bits(getattr(packet, "tcp_flags", None)) & 0x10)
                for packet in targeted
            )
            acknowledgements = sum(
                bool(_tcp_flag_bits(getattr(packet, "tcp_flags", None)) & 0x10 and not _tcp_flag_bits(getattr(packet, "tcp_flags", None)) & 0x02)
                for packet in targeted
            )
            estimated_completions = min(len(syn_only), max(syn_ack, acknowledgements))
            incomplete_ratio = (len(syn_only) - estimated_completions) / len(syn_only)
            if len(syn_only) >= min_syn and len(sources) >= min_sources and incomplete_ratio >= min_incomplete:
                evidence = (
                    f"{len(syn_only)} initial SYN packets to {destination} in {window_seconds} seconds "
                    f"from {len(sources)} sources; aggregate unmatched-handshake estimate "
                    f"{incomplete_ratio:.0%} (thresholds: {min_syn} SYNs, {min_sources} sources, "
                    f"{min_incomplete:.0%} incomplete). Packet captures can omit handshake responses, "
                    "so this is not proof of a SYN flood."
                )
                alerts.append(_alert("Possible SYN Flood", "High", None, destination, timestamp, evidence, score))
    return alerts


def traffic_statistics(packets, window_seconds=TIME_WINDOW_SECONDS):
    """Produce dashboard-ready traffic counts from the SQLite packet records."""
    total_bytes = sum(packet.packet_length for packet in packets)
    timestamps = [packet.timestamp for packet in packets if packet.timestamp]
    duration = max((max(timestamps) - min(timestamps)).total_seconds(), 0) if len(timestamps) > 1 else 0
    protocol_counts = Counter(packet.protocol for packet in packets)
    time_windows = _windowed_packets(packets, window_seconds)
    traffic_over_time = [(timestamp.isoformat(), len(window_packets)) for timestamp, window_packets in time_windows]
    window_statistics = [{
        "start": timestamp.isoformat(), "total_packets": len(window_packets),
        "total_bytes": sum(packet.packet_length for packet in window_packets),
        "tcp_packets": sum(packet.protocol == "TCP" for packet in window_packets),
        "udp_packets": sum(packet.protocol == "UDP" for packet in window_packets),
        "icmp_packets": sum(packet.protocol == "ICMP" for packet in window_packets),
        "unique_source_ips": len({packet.src_ip for packet in window_packets if packet.src_ip}),
        "unique_destination_ips": len({packet.dst_ip for packet in window_packets if packet.dst_ip}),
        "unique_destination_ports": len({packet.dst_port for packet in window_packets if packet.dst_port is not None}),
    } for timestamp, window_packets in time_windows]
    return {
        "total_packets": len(packets), "total_bytes": total_bytes, "duration": round(duration, 3),
        "packets_per_second": round(len(packets) / duration, 2) if duration else 0,
        "protocol_distribution": dict(protocol_counts),
        "top_sources": Counter(packet.src_ip for packet in packets if packet.src_ip).most_common(10),
        "top_destinations": Counter(packet.dst_ip for packet in packets if packet.dst_ip).most_common(10),
        "top_ports": [(str(port), count) for port, count in Counter(packet.dst_port for packet in packets if packet.dst_port is not None).most_common(10)],
        "traffic_over_time": traffic_over_time, "window_statistics": window_statistics,
        "tcp_count": protocol_counts["TCP"], "udp_count": protocol_counts["UDP"], "icmp_count": protocol_counts["ICMP"],
        "dns_query_count": sum(bool(getattr(packet, "dns_query", None)) for packet in packets),
        "http_request_count": sum(bool(getattr(packet, "http_method", None)) for packet in packets),
        "unique_source_ips": len({packet.src_ip for packet in packets if packet.src_ip}),
        "unique_destination_ips": len({packet.dst_ip for packet in packets if packet.dst_ip}),
        "unique_destination_ports": len({packet.dst_port for packet in packets if packet.dst_port is not None}),
    }


def analyze_packets(packets, policy=None):
    """Run all required rules and return stats, alerts, score, and severity."""
    window_seconds = _value(policy, "time_window_seconds", TIME_WINDOW_SECONDS)
    windows = _windowed_packets(packets, window_seconds)
    alerts = (
        detect_port_scans(windows, policy)
        + detect_brute_force(windows, policy)
        + detect_abnormal_volume(windows, policy)
        + detect_ddos_activity(windows, policy)
        + detect_syn_flood(windows, policy)
    )
    score, severity, reasons = score_alerts(alerts)
    return traffic_statistics(packets, window_seconds), alerts, score, severity, reasons
