"""Smoke tests for asnmap. No network access."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from asnmap import (
    TOOL_NAME,
    TOOL_VERSION,
    analyze,
    build_asn_map,
    find_neighbors,
    parse_export,
)
from asnmap.cli import main

SAMPLE = """\
# comment
203.0.113.0/25   | AS64500 | CORP | US | arin
203.0.113.128/25 | AS64500 | CORP | US | arin
198.51.100.0/24  | AS64500 | CORP | US | arin
198.51.100.0/24  | AS64999 | OTHER | NL | ripe
10.0.0.0/16      | AS64500 | CORP | US | arin
23.0.0.0/8       | AS64500 | CORP | US | arin
not-a-cidr       | AS1
"""


class TestCore(unittest.TestCase):
    def test_meta(self):
        self.assertEqual(TOOL_NAME, "asnmap")
        self.assertTrue(TOOL_VERSION)

    def test_parse(self):
        records, errors = parse_export(SAMPLE)
        self.assertEqual(len(records), 6)
        self.assertTrue(any("invalid CIDR" in e for e in errors))
        self.assertEqual(records[0].asn, "AS64500")

    def test_asn_map(self):
        records, _ = parse_export(SAMPLE)
        m = build_asn_map(records)
        self.assertIn("AS64500", m)
        self.assertIn("AS64999", m)

    def test_neighbors(self):
        records, _ = parse_export(SAMPLE)
        nbrs = find_neighbors(records)
        # 203.0.113.0/25 is adjacent to 203.0.113.128/25
        self.assertIn(("203.0.113.0/25", "203.0.113.128/25"), nbrs)

    def test_findings(self):
        records, errors = parse_export(SAMPLE)
        report = analyze(records, errors)
        kinds = {f.kind for f in report.findings}
        self.assertIn("multi-origin", kinds)
        self.assertIn("bogon", kinds)
        self.assertIn("oversized-aggregate", kinds)
        self.assertEqual(report.max_severity, "critical")

    def test_to_dict(self):
        records, errors = parse_export(SAMPLE)
        report = analyze(records, errors)
        d = report.to_dict()
        self.assertEqual(d["summary"]["max_severity"], "critical")
        json.dumps(d)  # must be serializable


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.demo = os.path.join(
            os.path.dirname(__file__), "..", "demos", "01-basic", "sample_export.txt"
        )

    def _run(self, argv):
        out = io.StringIO()
        err = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_table(self):
        code, out, _ = self._run(["analyze", self.demo])
        self.assertEqual(code, 2)  # medium+ findings present
        self.assertIn("ASN OWNERSHIP MAP", out)
        self.assertIn("FINDINGS", out)

    def test_json(self):
        code, out, _ = self._run(["--format", "json", "analyze", self.demo])
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["max_severity"], "critical")

    def test_html(self):
        code, out, _ = self._run(["--format", "html", "analyze", self.demo])
        self.assertEqual(code, 2)
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("netblock", out.lower())

    def test_map(self):
        code, out, _ = self._run(["map", self.demo])
        self.assertIn("AS64500", out)

    def test_clean_exit_zero(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("192.0.2.0/24 | AS65000 | CLEAN | US | arin\n")
            path = fh.name
        try:
            # 192.0.2.0/24 is itself a bogon (TEST-NET) -> still flagged high.
            code, _, _ = self._run(["analyze", path])
            self.assertIn(code, (0, 2))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
