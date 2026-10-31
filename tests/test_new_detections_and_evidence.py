"""Heuristic DDoS/SYN detection and cryptographic evidence primitives."""
import base64
import os
from datetime import datetime
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.services import evidence
from app.services.analyzer import analyze_packets
from app.services.evidence import EvidenceError
from app.services.threat_scoring import score_alerts


def _packet(index, *, flags="0x0002", length=1200, destination="10.0.0.10"):
    return SimpleNamespace(
        timestamp=datetime(2026, 3, 1),
        packet_number=index,
        src_ip=f"10.0.1.{index % 20 + 1}",
        dst_ip=destination,
        protocol="TCP",
        src_port=50000 + index,
        dst_port=443,
        packet_length=length,
        tcp_flags=flags,
        dns_query=None,
        http_method=None,
    )


def test_ddos_and_syn_heuristics_require_correlated_signals():
    packets = [_packet(index) for index in range(120)]
    _, alerts, score, _, reasons = analyze_packets(packets)
    kinds = {alert["alert_type"] for alert in alerts}
    assert "Possible DDoS Activity" in kinds
    assert "Possible SYN Flood" in kinds
    assert score == 90
    assert len(reasons) == 2
    assert all("not proof" in alert["evidence"].lower() or "not confirmation" in alert["evidence"].lower() for alert in alerts)

    ordinary = [_packet(index, flags="0x0010", length=60) for index in range(10)]
    _, normal_alerts, *_ = analyze_packets(ordinary)
    assert not any(alert["alert_type"] in {"Possible DDoS Activity", "Possible SYN Flood"} for alert in normal_alerts)


def test_repeated_same_rule_alerts_do_not_inflate_score():
    score, _, reasons = score_alerts([
        {"alert_type": "Possible Port Scan", "score": 40},
        {"alert_type": "Possible Port Scan", "score": 40},
        {"alert_type": "Possible Port Scan", "score": 40},
    ])
    assert score == 40
    assert reasons == ["Possible Port Scan"]


def test_aes_gcm_authentication_and_manifest_signatures(monkeypatch, tmp_path):
    key = os.urandom(32)
    monkeypatch.setattr(evidence, "EVIDENCE_ENCRYPTION_KEY", base64.urlsafe_b64encode(key).decode())
    source = tmp_path / "capture.pcap"
    source.write_bytes(b"synthetic-pcap-evidence")
    expected_hash = evidence.sha256_file(source)
    encrypted_path = evidence.encrypt_evidence_file(source)
    assert source.exists() is False
    decrypted_path = tmp_path / "decrypted.pcap"
    evidence.decrypt_evidence_file(encrypted_path, decrypted_path)
    assert evidence.sha256_file(decrypted_path) == expected_hash

    corrupted = bytearray(encrypted_path.read_bytes())
    corrupted[-1] ^= 0x01
    encrypted_path.write_bytes(corrupted)
    rejected_path = tmp_path / "rejected.pcap"
    with pytest.raises(EvidenceError):
        evidence.decrypt_evidence_file(encrypted_path, rejected_path)
    assert rejected_path.exists() is False

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    monkeypatch.setattr(evidence, "EVIDENCE_SIGNING_PRIVATE_KEY", private_pem)
    monkeypatch.setattr(evidence, "EVIDENCE_SIGNING_PUBLIC_KEY", public_pem)
    manifest = {"analysis_id": 7, "company_id": 2, "pcap_sha256": expected_hash}
    signature, fingerprint = evidence.sign_manifest(manifest)
    assert evidence.verify_manifest(manifest, signature, fingerprint)
    assert not evidence.verify_manifest({**manifest, "company_id": 3}, signature, fingerprint)
