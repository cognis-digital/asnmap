"""asnmap - Map ASN/CIDR ownership & neighbors from whois/RIR exports.

Defensive netblock intelligence: parse RIR/whois exports you own or are
entitled to analyze, build an ASN -> CIDR ownership map, detect adjacency
(neighboring netblocks), and flag triage-worthy conditions (overlaps,
bogons, oversized aggregates, ownership drift).

Standard library only. No network access.
"""
from .core import (
    Record,
    Finding,
    parse_export,
    build_asn_map,
    find_neighbors,
    analyze,
    Report,
)

TOOL_NAME = "asnmap"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Record",
    "Finding",
    "parse_export",
    "build_asn_map",
    "find_neighbors",
    "analyze",
    "Report",
    "TOOL_NAME",
    "TOOL_VERSION",
]
