"""Core engine for asnmap.

Parses RIR/whois export lines into Records, builds an ASN ownership map,
computes CIDR adjacency/overlap, and runs a triage analysis that emits
severity-rated Findings.

Input format (one record per line, fields separated by '|' -- a common RIR
bulk-export style). Comments (#) and blank lines are ignored::

    cidr | asn | org | country | registry
    192.0.2.0/24 | 64512 | EXAMPLE-NET | US | arin

Flexible: missing trailing fields default to empty. The CIDR and ASN fields
are required.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# Severity ordering (higher = worse) for sorting / exit decisions.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# RFC 1918 / special-use ranges that should not appear in public RIR exports.
BOGON_NETS = [
    ipaddress.ip_network(c)
    for c in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "fc00::/7",
        "fe80::/10",
    )
]

# A /8 (v4) or shorter aggregate is unusually large for a single org block.
OVERSIZED_V4_PREFIX = 8
OVERSIZED_V6_PREFIX = 24


@dataclass
class Record:
    """A single parsed netblock ownership record."""

    cidr: str
    asn: str
    org: str = ""
    country: str = ""
    registry: str = ""
    lineno: int = 0

    @property
    def network(self) -> ipaddress._BaseNetwork:
        return ipaddress.ip_network(self.cidr, strict=False)

    @property
    def version(self) -> int:
        return self.network.version

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """A triage finding about the parsed data set."""

    severity: str
    kind: str
    message: str
    cidr: str = ""
    asn: str = ""
    related: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    """Full analysis result."""

    records: List[Record] = field(default_factory=list)
    asn_map: Dict[str, List[str]] = field(default_factory=dict)
    neighbors: List[Tuple[str, str]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def to_dict(self) -> dict:
        return {
            "records": [r.to_dict() for r in self.records],
            "asn_map": self.asn_map,
            "neighbors": [list(n) for n in self.neighbors],
            "findings": [f.to_dict() for f in self.findings],
            "parse_errors": self.parse_errors,
            "summary": {
                "records": len(self.records),
                "asns": len(self.asn_map),
                "neighbor_pairs": len(self.neighbors),
                "findings": len(self.findings),
                "max_severity": self.max_severity,
            },
        }


def parse_export(text: str) -> Tuple[List[Record], List[str]]:
    """Parse a pipe-delimited RIR/whois export into Records.

    Returns (records, parse_errors).
    """
    records: List[Record] = []
    errors: List[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2:
            errors.append(f"line {lineno}: need at least 'cidr|asn', got: {raw!r}")
            continue
        cidr, asn = parts[0], parts[1]
        org = parts[2] if len(parts) > 2 else ""
        country = parts[3] if len(parts) > 3 else ""
        registry = parts[4] if len(parts) > 4 else ""
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            errors.append(f"line {lineno}: invalid CIDR {cidr!r}: {exc}")
            continue
        if not asn or not asn.lstrip("ASas").isdigit():
            errors.append(f"line {lineno}: invalid ASN {asn!r}")
            continue
        norm_asn = "AS" + asn.lstrip("ASas")
        records.append(
            Record(
                cidr=cidr,
                asn=norm_asn,
                org=org,
                country=country,
                registry=registry.lower(),
                lineno=lineno,
            )
        )
    return records, errors


def build_asn_map(records: List[Record]) -> Dict[str, List[str]]:
    """Map each ASN to the sorted list of CIDRs it owns."""
    mapping: Dict[str, List[str]] = {}
    for rec in records:
        mapping.setdefault(rec.asn, []).append(rec.cidr)
    for asn in mapping:
        mapping[asn] = sorted(
            set(mapping[asn]),
            key=lambda c: (ipaddress.ip_network(c, strict=False).version, int(ipaddress.ip_network(c, strict=False).network_address)),
        )
    return mapping


def find_neighbors(records: List[Record]) -> List[Tuple[str, str]]:
    """Find adjacent (numerically contiguous) netblock pairs of same version.

    Two networks are neighbors if the address immediately after the end of one
    equals the start of the other. Useful to spot fragmented ownership that
    could be aggregated, or a foothold abutting an owned block.
    """
    nets = []
    for rec in records:
        nets.append((rec.network, rec.cidr))
    neighbors: List[Tuple[str, str]] = []
    nets.sort(key=lambda t: (t[0].version, int(t[0].network_address)))
    for i in range(len(nets)):
        a_net, a_cidr = nets[i]
        a_next = int(a_net.broadcast_address) + 1
        for j in range(i + 1, len(nets)):
            b_net, b_cidr = nets[j]
            if b_net.version != a_net.version:
                continue
            b_start = int(b_net.network_address)
            if b_start == a_next:
                neighbors.append((a_cidr, b_cidr))
            if b_start > a_next:
                break
    return neighbors


def _overlaps(records: List[Record]) -> List[Finding]:
    findings: List[Finding] = []
    nets = [(r.network, r) for r in records]
    for i in range(len(nets)):
        a_net, a_rec = nets[i]
        for j in range(i + 1, len(nets)):
            b_net, b_rec = nets[j]
            if a_net.version != b_net.version:
                continue
            if a_net.overlaps(b_net) and a_net != b_net:
                # subnet relationship vs partial overlap
                if a_net.subnet_of(b_net) or b_net.subnet_of(a_net):
                    sev = "medium"
                    kind = "nested-block"
                    msg = f"{a_rec.cidr} and {b_rec.cidr} are nested"
                else:
                    sev = "high"
                    kind = "partial-overlap"
                    msg = f"{a_rec.cidr} partially overlaps {b_rec.cidr}"
                drift = a_rec.asn != b_rec.asn
                if drift:
                    sev = "critical" if kind == "partial-overlap" else "high"
                    msg += f" with conflicting ownership ({a_rec.asn} vs {b_rec.asn})"
                findings.append(
                    Finding(
                        severity=sev,
                        kind=kind,
                        message=msg,
                        cidr=a_rec.cidr,
                        asn=a_rec.asn,
                        related=b_rec.cidr,
                    )
                )
    return findings


def analyze(records: List[Record], parse_errors: Optional[List[str]] = None) -> Report:
    """Run full triage analysis and build a Report."""
    parse_errors = list(parse_errors or [])
    asn_map = build_asn_map(records)
    neighbors = find_neighbors(records)
    findings: List[Finding] = []

    # Bogon / special-use blocks appearing in an export.
    for rec in records:
        net = rec.network
        for bogon in BOGON_NETS:
            if net.version != bogon.version:
                continue
            if net.overlaps(bogon):
                findings.append(
                    Finding(
                        severity="high",
                        kind="bogon",
                        message=f"{rec.cidr} falls in special-use/bogon range {bogon}",
                        cidr=rec.cidr,
                        asn=rec.asn,
                        related=str(bogon),
                    )
                )
                break

    # Oversized aggregates.
    for rec in records:
        net = rec.network
        limit = OVERSIZED_V4_PREFIX if net.version == 4 else OVERSIZED_V6_PREFIX
        if net.prefixlen <= limit:
            findings.append(
                Finding(
                    severity="medium",
                    kind="oversized-aggregate",
                    message=f"{rec.cidr} is an unusually large aggregate (/{net.prefixlen})",
                    cidr=rec.cidr,
                    asn=rec.asn,
                )
            )

    # Overlap / nesting / ownership-drift.
    findings.extend(_overlaps(records))

    # Multi-origin: same exact CIDR announced by >1 ASN (MOAS-like).
    cidr_to_asns: Dict[str, set] = {}
    for rec in records:
        key = str(rec.network)
        cidr_to_asns.setdefault(key, set()).add(rec.asn)
    for cidr, asns in cidr_to_asns.items():
        if len(asns) > 1:
            findings.append(
                Finding(
                    severity="critical",
                    kind="multi-origin",
                    message=f"{cidr} claimed by multiple ASNs: {', '.join(sorted(asns))}",
                    cidr=cidr,
                    asn=",".join(sorted(asns)),
                )
            )

    # Missing country / org metadata (low-severity hygiene).
    for rec in records:
        if not rec.org or not rec.country:
            findings.append(
                Finding(
                    severity="low",
                    kind="incomplete-metadata",
                    message=f"{rec.cidr} missing org/country attribution",
                    cidr=rec.cidr,
                    asn=rec.asn,
                )
            )

    # Parse errors surface as findings too.
    for err in parse_errors:
        findings.append(Finding(severity="low", kind="parse-error", message=err))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.kind, f.cidr))

    return Report(
        records=records,
        asn_map=asn_map,
        neighbors=neighbors,
        findings=findings,
        parse_errors=parse_errors,
    )
