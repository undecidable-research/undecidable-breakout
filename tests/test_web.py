"""Frontend: every page renders, every page has a JSON twin, nothing escapes the
reports directory, nothing executes. No Docker needed."""
import json
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import breakout
from breakout import cli, scoring
from breakout.web import Site, handle, make_server


def _result(passed, output=""):
    return {"context": "p", "skipped": False, "skip_reason": "", "passed": passed,
            "exit_code": 0, "timeout": False, "duration": 0.1,
            "command": ["sh", "-s"], "output": output, "canary_hits": [],
            "flaky": False, "repeats": 1}


def _report(started, statuses):
    """statuses: {tech_id: (category, {profile: status})}"""
    techs = {}
    for tid, (cat, per) in statuses.items():
        techs[tid] = {"meta": {"name": f"name of {tid}", "category": cat,
                               "description": "d", "references": []},
                      "baseline": None,
                      "profiles": {slug: {"status": s, "reason": "",
                                          "result": _result(s == "ESCAPED", "<x>&")}
                                   for slug, s in per.items()}}
    return {"tool": "undecidable-breakout", "version": breakout.__version__,
            "started": started, "host": {"os": "linux", "kernel": "6.1", "baseline_mode": "auto"},
            "canary": {}, "run_nonce": "n", "techniques": techs,
            "scores": scoring.scores(techs)}


class WebTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        before = _report("2026-10-01T10:00:00+0000", {
            "net-literal-ip": ("net", {"docker-tight": "CONTAINED"}),
            "fs-dev-write": ("fs", {"docker-tight": "ESCAPED"}),
            "fs-etc-writable": ("fs", {"docker-tight": "SKIPPED"})})
        after = _report("2026-10-02T10:00:00+0000", {
            "net-literal-ip": ("net", {"docker-tight": "ESCAPED"}),
            "fs-dev-write": ("fs", {"docker-tight": "CONTAINED"}),
            "fs-etc-writable": ("fs", {"docker-tight": "CONTAINED"})})
        for name, rep in (("a", before), ("b", after)):
            (root / name).mkdir()
            (root / name / "report.json").write_text(json.dumps(rep), encoding="utf-8")
        (root / "not-a-report").mkdir()
        (root / "not-a-report" / "report.json").write_text("{}", encoding="utf-8")
        (root.parent / "outside.json").write_text("{}", encoding="utf-8")
        cls.site = Site(root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def get(self, path, accept="text/html"):
        return handle(self.site, path, accept)

    def data(self, path):
        r = self.get(path, "application/json")
        self.assertEqual(r.content_type, "application/json; charset=utf-8", path)
        return json.loads(r.body)

    PAGES = ("/", "/leaderboard", "/techniques", "/techniques?category=fs&q=dev",
             "/techniques/fs-dev-write", "/profiles", "/profiles/docker-tight",
             "/profiles/failopen-wrapper", "/reports", "/reports/b/report.json",
             "/reports/b/report.json?status=ESCAPED", "/diff", "/compose", "/doctor",
             "/agents")

    def test_every_page_renders_html_with_strict_csp(self):
        for p in self.PAGES:
            r = self.get(p)
            self.assertEqual(r.status, 200, p)
            body = r.body.decode()
            self.assertIn("<main id='main'", body, p)
            self.assertIn("rel='alternate' type='application/json'", body, p)
            # the CSP forbids inline styles and scripts: none may be emitted
            self.assertNotRegex(body, r"\sstyle\s*=", p)
            self.assertNotIn("<script>", body, p)
            self.assertNotIn("unsafe-inline", r.headers["Content-Security-Policy"])

    def test_json_twin_three_ways(self):
        for p in ("/techniques?category=net", "/reports/b/report.json", "/diff"):
            via_accept = self.data(p)
            sep = "&" if "?" in p else "?"
            via_query = json.loads(self.get(p + sep + "format=json").body)
            via_prefix = json.loads(self.get("/api" + p).body)
            self.assertEqual(via_accept, via_query, p)
            self.assertEqual(via_accept, via_prefix, p)
        self.assertEqual(self.data("/")["counts"]["reports"], 2)  # invalid json skipped

    def test_corpus_filters(self):
        d = self.data("/techniques?category=fs&q=dev")
        self.assertTrue(d["techniques"])
        self.assertTrue(all(t["category"] == "fs" for t in d["techniques"]))
        self.assertIn("fs-dev-write", [t["id"] for t in d["techniques"]])
        bad = self.data("/techniques?category=nope")
        self.assertTrue(bad["errors"])
        self.assertEqual(bad["count"], bad["total"])

    def test_technique_detail_and_404(self):
        d = self.data("/techniques/fs-dev-write")
        self.assertEqual(d["selftest"]["status"], "ground-truth")
        self.assertEqual({v["status"] for v in d["verdicts"]}, {"ESCAPED", "CONTAINED"})
        self.assertIn("--only fs-dev-write", d["commands"]["run"])
        r = self.get("/techniques/does-not-exist")
        self.assertEqual(r.status, 404)
        self.assertEqual(json.loads(self.get("/api/techniques/x").body)["status"], 404)

    def test_report_rows_filter_and_escape_evidence(self):
        d = self.data("/reports/b/report.json?status=ESCAPED")
        self.assertEqual([r["technique"] for r in d["rows"]], ["net-literal-ip"])
        html = self.get("/reports/b/report.json").body.decode()
        self.assertIn("&lt;x&gt;&amp;", html)
        self.assertNotIn("<x>&", html)

    def test_diff_flags_regression_and_lists_coverage(self):
        d = self.data("/diff?before=a/report.json&after=b/report.json")
        res = d["result"]
        self.assertEqual(res["exit_code"], 1)
        self.assertEqual([r["technique"] for r in res["regressions"]], ["net-literal-ip"])
        self.assertEqual([r["technique"] for r in res["improvements"]], ["fs-dev-write"])
        self.assertEqual([r["technique"] for r in res["coverage_changes"]], ["fs-etc-writable"])
        html = self.get("/diff?before=a/report.json&after=b/report.json").body.decode()
        self.assertIn("data-exit-code='1'", html)

    def test_compose_validates_and_never_executes(self):
        d = self.data("/compose?profile=docker-tight&category=fs&only=fs-dev-write&repeat=3")
        self.assertTrue(d["valid"])
        self.assertEqual(d["argv"][:4], ["python", "-m", "breakout.cli", "run"])
        for flag in ("--profile", "--categories", "--only", "--repeat", "--out"):
            self.assertIn(flag, d["argv"])
        bad = self.data("/compose?profile=nope&category=zz&only=x&repeat=0")
        self.assertFalse(bad["valid"])
        self.assertIsNone(bad["argv"])
        self.assertEqual(len(bad["errors"]), 4)

    def test_files_stay_inside_reports_dir(self):
        self.assertEqual(self.get("/files/b/report.json").status, 200)
        for p in ("/files/../outside.json", "/files/%2e%2e/outside.json",
                  "/files/..%2foutside.json", "/files/b/../../outside.json",
                  "/reports/../outside.json", "/files/%00", "/files/..\\outside.json"):
            self.assertIn(self.get(p).status, (400, 404), p)

    def test_agent_docs(self):
        txt = self.get("/llms.txt").body.decode()
        self.assertTrue(txt.startswith("# undecidable-breakout"))
        for p in ("/api/techniques", "/api/compose", "/api/diff", "/openapi.json"):
            self.assertIn(p, txt)
        spec = json.loads(self.get("/openapi.json").body)
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertIn("/api/reports/{path}", spec["paths"])
        idx = json.loads(self.get("/api").body)
        self.assertTrue(idx["read_only"])

    def test_assets_served(self):
        for p, ctype in (("/assets/app.css", "text/css"), ("/assets/app.js", "text/javascript"),
                         ("/assets/archivo.woff2", "font/woff2"), ("/assets/mark.svg", "image/svg+xml")):
            r = self.get(p)
            self.assertEqual(r.status, 200, p)
            self.assertTrue(r.content_type.startswith(ctype), p)
            self.assertTrue(r.body)
        css = self.get("/assets/app.css").body.decode()
        # palette discipline: the five greys, nothing else
        colors = set(re.findall(r"#[0-9a-fA-F]{6}\b", css))
        self.assertLessEqual(colors, {"#050505", "#838383", "#8a8a8a", "#484848", "#2e2e2e"})

    def test_server_is_read_only(self):
        srv = make_server(self.site, "127.0.0.1", 0)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            with urllib.request.urlopen(base + "/api/techniques", timeout=5) as r:
                self.assertEqual(json.loads(r.read())["total"], 47)
            req = urllib.request.Request(base + "/compose", data=b"x", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(cm.exception.code, 405)
            self.assertEqual(cm.exception.headers["Allow"], "GET, HEAD")
        finally:
            srv.shutdown()
            srv.server_close()


class RunOnlyFlagTest(unittest.TestCase):
    def test_unknown_technique_id_is_rejected_before_running(self):
        with self.assertRaises(SystemExit) as cm:
            cli.main(["run", "--profile", "none", "--only", "no-such-technique"])
        self.assertIn("unknown technique ids", str(cm.exception.code))


if __name__ == "__main__":
    unittest.main()
