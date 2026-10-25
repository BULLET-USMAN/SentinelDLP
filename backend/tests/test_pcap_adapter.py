"""Unit Tests for Offline PCAP Adapter (Phase 7)."""

import io
import struct
from datetime import datetime, timezone
import pytest
from app.network.adapters.pcap_adapter import PcapAdapter


def build_synthetic_pcap_bytes() -> bytes:
    """Construct an in-memory valid libpcap binary stream with one TCP packet."""
    stream = io.BytesIO()

    # 1. Global Header (24 bytes)
    # magic=0xa1b2c3d4, v_maj=2, v_min=4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    stream.write(global_hdr)

    # 2. Packet payload construction (Ethernet + IPv4 + TCP = 54 bytes)
    # Ethernet Header (14 bytes): dest MAC, src MAC, ethertype=0x0800 (IPv4)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

    # IPv4 Header (20 bytes): ver/ihl=0x45, total_len=40, proto=6 (TCP), src=192.168.1.10, dst=198.51.100.20
    src_ip_bytes = bytes([192, 168, 1, 10])
    dst_ip_bytes = bytes([198, 51, 100, 20])
    ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 1234, 0, 64, 6, 0, src_ip_bytes, dst_ip_bytes)

    # TCP Header (20 bytes): src_port=54321, dst_port=443, seq=1, ack=0, offset=0x50, flags=0x02 (SYN), win=65535
    tcp_hdr = struct.pack(">HHIIBBHHH", 54321, 443, 1, 0, 0x50, 0x02, 65535, 0, 0)

    packet_bytes = eth_hdr + ip_hdr + tcp_hdr
    pkt_len = len(packet_bytes)
    assert pkt_len == 54

    # 3. Packet Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
    pkt_hdr = struct.pack("<IIII", 1729864800, 500000, pkt_len, pkt_len)
    stream.write(pkt_hdr)
    stream.write(packet_bytes)

    return stream.getvalue()


def test_pcap_adapter_valid_packet_stream():
    """Verify parsing synthetic valid PCAP packets."""
    raw_pcap = build_synthetic_pcap_bytes()
    file_obj = io.BytesIO(raw_pcap)

    results = list(PcapAdapter.parse_pcap_stream(file_obj, sensor_id="pcap-test-01"))
    assert len(results) == 1
    event, is_valid, err = results[0]

    assert is_valid is True
    assert event is not None
    assert event.sensor_id == "pcap-test-01"
    assert event.source_technology == "PCAP_ANALYZER"
    assert event.source_ip == "192.168.1.10"
    assert event.source_port == 54321
    assert event.destination_ip == "198.51.100.20"
    assert event.destination_port == 443
    assert event.transport_protocol == "TCP"
    assert event.total_bytes == 54
    assert event.evidence_provenance == "OBSERVED"


def test_pcap_adapter_invalid_magic_handling():
    """Verify rejecting invalid binary file with non-PCAP magic."""
    invalid_bytes = b"THIS IS NOT A VALID PCAP FILE HEADER"
    file_obj = io.BytesIO(invalid_bytes)

    results = list(PcapAdapter.parse_pcap_stream(file_obj))
    assert len(results) == 1
    event, is_valid, err = results[0]
    assert is_valid is False
    assert event is None
    assert "Unsupported PCAP magic number" in (err or "")


def test_pcap_adapter_truncated_packet_handling():
    """Verify clean recovery when packet stream is truncated."""
    raw_pcap = build_synthetic_pcap_bytes()
    # Truncate halfway through packet
    truncated_bytes = raw_pcap[:35]
    file_obj = io.BytesIO(truncated_bytes)

    results = list(PcapAdapter.parse_pcap_stream(file_obj))
    assert len(results) == 1
    event, is_valid, err = results[0]
    assert is_valid is False
    assert "Truncated" in (err or "")
