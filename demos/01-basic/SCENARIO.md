# Demo 01 - Basic netblock triage

You exported the netblock ownership records for the ASNs your org controls
from an RIR bulk export (and merged in a peer's range for context). You want
to map ASN ownership, see which blocks are adjacent (aggregation / abutting
foothold candidates), and triage anything suspicious before publishing.

## Input

`sample_export.txt` is a pipe-delimited export:

```
cidr | asn | org | country | registry
```

It deliberately contains several triage-worthy conditions:

- A **multi-origin** CIDR (`198.51.100.0/24` claimed by two ASNs) -> critical.
- A **partial overlap with ownership drift** between two announced ranges.
- A **bogon / special-use** block (`10.0.0.0/16`) that should not be in a
  public export -> high.
- An **oversized aggregate** (`23.0.0.0/8`) -> medium.
- Two **adjacent** owned blocks that could be aggregated.
- A record with **incomplete metadata** (missing country).

## Run it

```bash
# Human-readable triage table
python -m asnmap analyze demos/01-basic/sample_export.txt

# Just the ASN -> CIDR ownership map
python -m asnmap map demos/01-basic/sample_export.txt

# Machine-readable for pipelines (exit code 2 when medium+ findings)
python -m asnmap --format json analyze demos/01-basic/sample_export.txt

# Shareable self-contained HTML report (the "UI")
python -m asnmap --format html -o report.html analyze demos/01-basic/sample_export.txt
```

## Expected

Exit code `2` (medium-or-higher findings present), a critical multi-origin
finding, a high bogon finding, and an adjacency between the two contiguous
owned blocks.
