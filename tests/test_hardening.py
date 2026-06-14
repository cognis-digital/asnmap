"""Hardening tests: error paths, edge cases, and input validation."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from asnmap.cli import main
from asnmap.core import (
    Finding,
    Report,
    analyze,
    build_asn_map,
    find_neighbors,
    parse_export,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run_cli(argv, stdin_text=None):
    """Run main(argv) capturing stdout/stderr.  Returns (exit_code, out, err)."""
    out = io.StringIO()
    err = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    if stdin_text is not None:
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin_text)
    try:
        code = main(argv)
    finally:
        sys.stdout, sys.stderr = old_out, old_err
        if stdin_text is not None:
            sys.stdin = old_stdin
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# Core: parse_export edge cases
# ---------------------------------------------------------------------------

class TestParseEdgeCases(unittest.TestCase):
    def test_empty_input_returns_no_records(self):
        records, errors = parse_export("")
        self.assertEqual(records, [])
        self.assertEqual(errors, [])

    def test_whitespace_only_input(self):
        records, errors = parse_export("   \n\n\t\n")
        self.assertEqual(records, [])
        self.assertEqual(errors, [])

    def test_comments_and_blank_lines_skipped(self):
        records, errors = parse_export("# header\n\n# comment\n")
        self.assertEqual(records, [])
        self.assertEqual(errors, [])

    def test_asn_leading_zeros_normalized(self):
        """AS064500 should normalize to AS64500 (strip leading zeros)."""
        records, errors = parse_export("192.0.2.0/24 | 064500 | ORG | US | arin")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].asn, "AS64500")
        self.assertEqual(errors, [])

    def test_asn_with_as_prefix_and_leading_zeros(self):
        records, errors = parse_export("1.0.0.0/8 | AS00001 | ORG | US | arin")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].asn, "AS1")

    def test_bare_as_prefix_is_invalid(self):
        """'AS' with no digits is rejected."""
        records, errors = parse_export("1.0.0.0/8 | AS | ORG | US | arin")
        self.assertEqual(records, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("invalid ASN", errors[0])

    def test_invalid_cidr_rejected(self):
        records, errors = parse_export("not-a-cidr | AS65000")
        self.assertEqual(records, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("invalid CIDR", errors[0])

    def test_missing_asn_field_rejected(self):
        """A line with only one field (no pipe) is rejected."""
        records, errors = parse_export("1.0.0.0/8")
        self.assertEqual(records, [])
        self.assertEqual(len(errors), 1)

    def test_ipv6_record_accepted(self):
        records, errors = parse_export("2001:db8::/32 | AS64500 | ORG | US | arin")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].version, 6)
        self.assertEqual(errors, [])

    def test_optional_trailing_fields_default_to_empty(self):
        records, errors = parse_export("1.2.3.0/24 | AS65000")
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r.org, "")
        self.assertEqual(r.country, "")
        self.assertEqual(r.registry, "")

    def test_line_numbers_in_error_messages(self):
        text = "# header\n\nbad-line | AS65000\n1.0.0.0/8 | AS65001\n"
        _, errors = parse_export(text)
        # The bad CIDR is on line 3 (blank and comment lines count).
        self.assertTrue(any("line 3" in e for e in errors))


# ---------------------------------------------------------------------------
# Core: analyze edge cases
# ---------------------------------------------------------------------------

class TestAnalyzeEdgeCases(unittest.TestCase):
    def test_analyze_empty_records(self):
        report = analyze([])
        self.assertEqual(report.records, [])
        self.assertEqual(report.max_severity, "info")
        self.assertEqual(report.findings, [])

    def test_analyze_single_clean_record(self):
        records, errors = parse_export("1.2.3.0/24 | AS65000 | ORG | US | arin")
        report = analyze(records, errors)
        self.assertIsInstance(report.to_dict(), dict)

    def test_max_severity_unknown_value_does_not_raise(self):
        """max_severity must not KeyError if an unexpected severity string slips in."""
        report = Report(
            findings=[Finding(severity="unknown_sev", kind="test", message="test")]
        )
        # Should not raise; falls back to 0 via .get()
        sev = report.max_severity
        self.assertEqual(sev, "unknown_sev")

    def test_report_to_dict_is_json_serializable(self):
        records, errors = parse_export(
            "10.0.0.0/8 | AS65001\n10.0.0.0/16 | AS65002"
        )
        report = analyze(records, errors)
        d = report.to_dict()
        json.dumps(d)  # must not raise

    def test_build_asn_map_empty(self):
        self.assertEqual(build_asn_map([]), {})

    def test_find_neighbors_empty(self):
        self.assertEqual(find_neighbors([]), [])

    def test_find_neighbors_single_record(self):
        records, _ = parse_export("1.2.3.0/24 | AS65000")
        self.assertEqual(find_neighbors(records), [])


# ---------------------------------------------------------------------------
# CLI: missing / unreadable file -> exit 1
# ---------------------------------------------------------------------------

class TestCLIErrorPaths(unittest.TestCase):
    def test_missing_file_exits_1(self):
        code, out, err = _run_cli(["analyze", "/no/such/file/xyz.txt"])
        self.assertEqual(code, 1)
        self.assertIn("cannot read", err)
        self.assertEqual(out, "")

    def test_missing_file_map_exits_1(self):
        code, out, err = _run_cli(["map", "/no/such/file/xyz.txt"])
        self.assertEqual(code, 1)
        self.assertIn("cannot read", err)

    def test_bad_output_path_exits_1(self):
        demo = os.path.join(
            os.path.dirname(__file__), "..", "demos", "01-basic", "sample_export.txt"
        )
        code, out, err = _run_cli(["--output", "/no/such/dir/out.txt", "analyze", demo])
        self.assertEqual(code, 1)
        self.assertIn("cannot write output", err)

    def test_binary_file_exits_1_not_traceback(self):
        """A binary (non-UTF-8) file must produce a clean error, not a traceback."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as fh:
            fh.write(b"\xff\xfe\x00\x01binary garbage \x80\x81")
            path = fh.name
        try:
            code, out, err = _run_cli(["analyze", path])
            self.assertEqual(code, 1)
            self.assertIn("cannot read", err)
            self.assertNotIn("Traceback", err)
        finally:
            os.unlink(path)

    def test_empty_input_file_succeeds(self):
        """An empty file is valid (zero records) — must not crash."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write("")
            path = fh.name
        try:
            code, out, err = _run_cli(["analyze", path])
            self.assertIn(code, (0, 2))
            self.assertNotIn("Traceback", err)
        finally:
            os.unlink(path)

    def test_stdin_dash_with_valid_data(self):
        code, out, err = _run_cli(["analyze", "-"], stdin_text="1.2.3.0/24 | AS65000 | ORG | US | arin\n")
        self.assertIn(code, (0, 2))
        self.assertNotIn("Traceback", err)

    def test_stdin_dash_empty(self):
        """Empty stdin must not crash."""
        code, out, err = _run_cli(["analyze", "-"], stdin_text="")
        self.assertIn(code, (0, 2))
        self.assertNotIn("Traceback", err)


# ---------------------------------------------------------------------------
# CLI: output formats on minimal valid input
# ---------------------------------------------------------------------------

class TestCLIFormats(unittest.TestCase):
    def setUp(self):
        fh = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt")
        fh.write("1.2.3.0/24 | AS65000 | ORG | US | arin\n")
        fh.flush()
        fh.close()
        self.path = fh.name

    def tearDown(self):
        os.unlink(self.path)

    def test_json_format_is_valid_json(self):
        code, out, err = _run_cli(["--format", "json", "analyze", self.path])
        data = json.loads(out)
        self.assertIn("summary", data)
        self.assertIn("records", data["summary"])

    def test_html_format_contains_doctype(self):
        code, out, err = _run_cli(["--format", "html", "analyze", self.path])
        self.assertIn("<!DOCTYPE html>", out)

    def test_map_format_tab_separated(self):
        code, out, err = _run_cli(["map", self.path])
        self.assertIn("AS65000", out)
        # map format: "ASN\tcidr\n"
        self.assertIn("\t", out)


if __name__ == "__main__":
    unittest.main()
