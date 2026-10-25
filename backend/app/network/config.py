"""Configuration and Detection Thresholds for Network Monitoring (Phase 7).

Defines default thresholds, baseline measurement intervals, and policy constants.
"""

from typing import Set

# Sensor Technology Constants
SENSOR_ZEEK = "ZEEK"
SENSOR_SURICATA = "SURICATA"
SENSOR_PCAP = "PCAP_ANALYZER"
SENSOR_SIMULATED = "SIMULATED"

# Supported Protocols
SUPPORTED_TRANSPORT_PROTOCOLS: Set[str] = {"TCP", "UDP", "ICMP"}
SUPPORTED_APP_PROTOCOLS: Set[str] = {"HTTP", "DNS", "TLS", "SSH", "SMB", "FTP", "SFTP"}

# Quantitative Anomaly Thresholds
THRESHOLD_OUTBOUND_FLOW_BYTES: int = 10 * 1024 * 1024  # 10 MB per single flow
THRESHOLD_CRITICAL_FLOW_BYTES: int = 100 * 1024 * 1024  # 100 MB
THRESHOLD_CONNECTION_BURST_COUNT: int = 25  # >= 25 connections in window
THRESHOLD_MULTI_PORT_COUNT: int = 15  # contacting >= 15 distinct destination ports
THRESHOLD_DNS_BURST_COUNT: int = 30  # >= 30 queries in window
THRESHOLD_DNS_NAME_LENGTH: int = 50  # Query name length > 50 characters (potential tunneling/DGA indicator)
THRESHOLD_DNS_SHANNON_ENTROPY: float = 3.8  # High randomness threshold in subdomain

# Temporal Windows in Minutes
WINDOW_ANOMALY_MINUTES: int = 15
WINDOW_BURST_MINUTES: int = 5

# Local Internal Subnet Defaults (RFC 1918)
DEFAULT_INTERNAL_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
]
