"""Offline regression tests for safe, honest report exports."""
from __future__ import annotations

import copy
import base64
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from openpyxl import load_workbook

sys.path.insert(0, str(Path(__file__).resolve().parent))

from jevseo import checks, score
from jevseo.report import build, view_model
from jevseo.report.pdf import render_html
from test_jevseo import HOME, crawl_fixture, dfs_fixture, judged_fixture, page


def audit_data(crawl=None, judged=None, perf=None):
    crawl = crawl or crawl_fixture()
    judged = judged or judged_fixture(crawl)
    findings = checks.run_checks(crawl) + score.jev_findings(crawl, judged)
    data = {
        "schema_version": "1.0",
        "tool": {"name": "jev-seo", "version": "test"},
        "run": {"started_at": "2026-09-21T10:00:00+00:00", "finished_at": "2026-09-21T10:05:00+00:00", "timings_s": {}, "options": {}},
        "site": {k: v for k, v in crawl.items() if k != "pages"},
        "pages": crawl["pages"],
        "findings": findings,
        "passed_rules": checks.passed_rules(findings),
        "jev": judged,
        "performance": perf,
        "dataforseo": None,
        "scores": score.score(crawl, findings, judged, perf),
        "actions": score.actions(findings, judged, len(checks.html_pages(crawl))),
    }
    return data


class ReportSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write_data(self, data):
        (self.tmp / "audit.json").write_text(json.dumps(data))

    def test_hostile_spreadsheet_strings_are_text_and_formulas_survive(self):
        crawl = crawl_fixture()
        hostile = ["=1+1", " +1", "\t=cmd", "\r@cmd", "  -2", "\n+cmd"]
        for p, title in zip(crawl["pages"], hostile):
            p["title"] = title
        data = audit_data(crawl)
        self.write_data(data)
        out = build(self.tmp, ["xlsx"], log=lambda *_: None)["xlsx"]

        wb = load_workbook(out, data_only=False)
        pages = wb["Pages"]
        for row in range(2, 2 + len(checks.html_pages(crawl))):
            value = pages.cell(row, 4).value
            self.assertIsInstance(value, str)
            self.assertEqual(pages.cell(row, 4).data_type, "s")
            self.assertTrue(value.startswith("'"))
        formulas = [cell for row in wb["Summary"].iter_rows() for cell in row if isinstance(cell.value, str) and cell.value.startswith("=")]
        self.assertTrue(formulas)
        self.assertTrue(any(cell.data_type == "f" for cell in formulas))

    def test_pdf_url_fetcher_allows_only_bundled_report_assets(self):
        from jevseo.report.pdf import allowed_url_fetcher

        font = next((Path(__file__).parent.parent / "jevseo" / "fonts").glob("*.otf"))
        fetched = allowed_url_fetcher(font.as_uri(), {font.resolve()})
        self.assertTrue(fetched)
        with self.assertRaises(ValueError):
            allowed_url_fetcher("https://evil.example/image.png", {font.resolve()})
        with self.assertRaises(ValueError):
            allowed_url_fetcher((self.tmp / "secret.txt").as_uri(), {font.resolve()})

    def test_page_text_cannot_create_active_html_or_markdown(self):
        crawl = crawl_fixture()
        payload = '<img src="https://evil.example/x" onerror="alert(1)"> ![remote](https://evil.example/x.png)'
        crawl["pages"][1]["title"] = payload
        crawl["pages"][1]["h1"] = [payload]
        data = audit_data(crawl)
        data["actions"][0]["evidence"] = payload
        self.write_data(data)
        vm = view_model(data, self.tmp)
        html = render_html(vm)
        self.assertNotIn('<img src="https://evil.example/x"', html)
        self.assertIn("&lt;img", html)
        md_path = self.tmp / "report.md"
        from jevseo.report.md import write_md

        write_md(vm, md_path)
        md = md_path.read_text()
        self.assertNotIn('<img src="https://evil.example/x"', md)
        self.assertNotIn("![remote](https://evil.example/x.png)", md)
        self.assertIn("&lt;img", md)
        self.assertIn("[source](https://", md)

    def test_auto_narrative_does_not_claim_claude_wrote_it(self):
        data = audit_data()
        self.write_data(data)
        vm = view_model(data, self.tmp)
        self.assertTrue(vm["narrative"]["automatic"])
        html = render_html(vm)
        self.assertNotIn("Claude writes", html)
        from jevseo.report.md import write_md

        md_path = self.tmp / "report.md"
        write_md(vm, md_path)
        self.assertNotIn("Claude writes", md_path.read_text())
        xlsx = build(self.tmp, ["xlsx"], log=lambda *_: None)["xlsx"]
        method = [cell.value for row in load_workbook(xlsx)["Method"].iter_rows() for cell in row if isinstance(cell.value, str)]
        self.assertIn("automatic evidence-only summary", " ".join(method))
        self.assertNotIn("narrative (lead agent)", " ".join(method))

    def test_partial_reasons_name_each_missing_measurement(self):
        crawl = crawl_fixture()
        crawl["limits"].update({"hit_page_cap": True, "hit_time_budget": True})
        crawl["render"].update({"browser_available": False})
        crawl["pages"][1].update({"raw_word_count": 10, "script_count": 3, "rendered": False})
        judged = judged_fixture(crawl)
        judged["pages"][crawl["pages"][1]["url"]] = None
        perf = {"runs": [
            {"url": HOME, "strategy": "mobile", "error": "HTTP 500"},
            {"url": HOME, "strategy": "desktop", "error": "Timeout"},
        ]}
        data = audit_data(crawl, judged, perf)
        partial = data["scores"]["partial"]
        text = " ".join(partial).lower()
        self.assertIn("pages were not judged", text)
        self.assertIn("pagespeed insights failed for mobile", text)
        self.assertIn("pagespeed insights failed for desktop", text)
        self.assertIn("page cap", text)
        self.assertIn("time budget", text)
        self.assertIn("javascript rendering", text)

    def test_failed_pagespeed_does_not_claim_low_traffic(self):
        perf = {"runs": [{"url": HOME, "strategy": "mobile", "error": "HTTP 500"}]}
        data = audit_data(perf=perf)
        self.write_data(data)
        html = render_html(view_model(data, self.tmp))
        self.assertIn("PageSpeed Insights failed", html)
        self.assertNotIn("too little traffic to be measured", html)

    def test_successful_pagespeed_without_field_data_has_no_traffic_diagnosis(self):
        perf = {"runs": [{"url": HOME, "strategy": "mobile", "scores": {"performance": 80}, "opportunities": []}]}
        data = audit_data(perf=perf)
        self.write_data(data)
        html = render_html(view_model(data, self.tmp))
        self.assertIn("field data is unavailable", html)
        self.assertNotIn("too little traffic to be measured", html)
        self.assertIn("homepage rendered with JavaScript", html)
        self.assertNotIn("homepage needed JavaScript rendering", html)

    def test_saved_source_url_cannot_break_markdown_or_html(self):
        data = audit_data()
        data["actions"][0]["source"] = "https://evil.example/)[remote](https://evil.example/pwn"
        self.write_data(data)
        vm = view_model(data, self.tmp)
        from jevseo.report.md import report_link, write_md

        self.assertEqual(report_link("https://user:pass@evil.example/x"), "#")
        self.assertEqual(report_link("https://evil.example/a b"), "#")
        self.assertEqual(report_link("https://evil.example/a\nb"), "#")
        self.assertEqual(report_link("https://official.example/a_(b)"), "https://official.example/a_%28b%29")
        quoted = report_link(data["actions"][0]["source"])
        self.assertEqual(quoted, "https://evil.example/%29%5Bremote%5D%28https://evil.example/pwn")
        md_path = self.tmp / "report.md"
        write_md(vm, md_path)
        md = md_path.read_text()
        self.assertIn(f"[source]({quoted})", md)
        self.assertNotIn("][remote](https://evil.example/pwn", md)
        self.assertNotIn("<img", render_html(vm))

    def test_hosted_markdown_embeds_only_generated_charts(self):
        data = audit_data()
        self.write_data(data)
        vm = view_model(data, self.tmp)
        from jevseo.report.md import write_md

        md_path = self.tmp / "hosted.md"
        with mock.patch.dict(os.environ, {"JEVSEO_HOSTED": "1"}):
            write_md(vm, md_path)
        md = md_path.read_text()
        prefix = 'src="data:image/png;base64,'
        self.assertGreater(md.count(prefix), 0)
        self.assertNotIn("charts/", md)
        generated = {p.read_bytes() for p in vm["charts"].png.values()}
        encoded = [part.split('"', 1)[0] for part in md.split(prefix)[1:]]
        self.assertTrue(all(base64.b64decode(value) in generated for value in encoded))
        self.assertEqual(base64.b64decode(encoded[0]), vm["charts"].png["gauge"].read_bytes())

    def test_cli_markdown_keeps_relative_chart_paths(self):
        data = audit_data()
        self.write_data(data)
        vm = view_model(data, self.tmp)
        from jevseo.report.md import write_md

        md_path = self.tmp / "cli.md"
        with mock.patch.dict(os.environ, {"JEVSEO_HOSTED": "0"}):
            write_md(vm, md_path)
        md = md_path.read_text()
        self.assertIn('src="charts/gauge.png"', md)
        self.assertNotIn("data:image/png;base64,", md)

    def test_build_attempts_each_requested_format_before_failing(self):
        data = audit_data()
        self.write_data(data)
        with mock.patch("jevseo.report.pdf.write_pdf", side_effect=RuntimeError("pdf failed")) as pdf, \
             mock.patch("jevseo.report.xlsx.write_xlsx", side_effect=RuntimeError("xlsx failed")) as xlsx, \
             mock.patch("jevseo.report.md.write_md", side_effect=RuntimeError("md failed")) as md:
            with self.assertRaises(RuntimeError):
                build(self.tmp, ["pdf", "xlsx", "md"], log=lambda *_: None)
        pdf.assert_called_once()
        xlsx.assert_called_once()
        md.assert_called_once()


if __name__ == "__main__":
    unittest.main()
