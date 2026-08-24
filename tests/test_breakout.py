import ctypes
import json
import os
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import breakout
from breakout import corpus, reporting, runner, scoring
from breakout.canary import Canary
from breakout.sandboxes import load_profile, builtin_dir, render_docker_args


class CanaryTest(unittest.TestCase):
    def test_http_hit_roundtrip_and_time_filter(self):
        c = Canary()
        c.start()
        import urllib.request
        nonce = secrets.token_hex(8)
        with urllib.request.urlopen(
                f"http://127.0.0.1:{c.port}/hit/tech-x/{nonce}", timeout=5) as r:
            r.read()
        self.assertTrue(c.saw("tech-x", nonce))
        self.assertEqual(len(c.hits_for("tech-x", nonce)), 1)
        # a hit registered before `after` must not count (baseline pollution fix)
        time.sleep(0.01)
        self.assertEqual(c.hits_for("tech-x", nonce, after=time.time() + 1), [])
        self.assertFalse(c.saw("tech-x", "other-nonce"))
        c.stop()

    def test_abstract_listener_reported(self):
        import os
        c = Canary()
        info = c.info()
        self.assertEqual(info["abstract"], os.name == "posix")
        c.stop()

    def test_dns_responder_rebind_flip(self):
        # the DNS-rebinding E-path can't run inside Docker Desktop (its NAT won't
        # route a container's DNS back here), so prove the responder on loopback:
        # a normal name is loopback; a *.rebind name answers the allowlisted decoy
        # first and rebinds to loopback after.
        import socket
        import struct
        c = Canary()
        c.start()

        def resolve(name):
            q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            for part in name.split("."):
                q += bytes([len(part)]) + part.encode()
            q += struct.pack("!HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(q, ("127.0.0.1", c.info()["dns_port"]))
            data, _ = s.recvfrom(512)
            s.close()
            return ".".join(str(b) for b in data[-4:])

        self.assertEqual(resolve("example.com"), "127.0.0.1")
        self.assertEqual(resolve("abc123.rebind"), "203.0.113.9")   # allowlisted first
        self.assertEqual(resolve("abc123.rebind"), "127.0.0.1")     # rebound after
        c.stop()


class CorpusTest(unittest.TestCase):
    def test_builtin_corpus_loads_and_is_valid(self):
        techs = corpus.load_dir(corpus.default_dir())
        self.assertGreaterEqual(len(techs), 31)
        ids = [t.id for t in techs]
        self.assertEqual(len(ids), len(set(ids)), "duplicate technique ids")
        for t in techs:
            self.assertIn(t.category, corpus.CATEGORIES)
            self.assertIn(t.oracle, ("stdout", "canary"))
            self.assertTrue(t.probe.strip(), f"{t.id}: empty probe")
            self.assertGreaterEqual(t.timeout, 0)
        self.assertTrue(any(t.timeout for t in techs), "per-technique timeouts present")

    def test_every_category_populated(self):
        techs = corpus.load_dir(corpus.default_dir())
        cats = {t.category for t in techs}
        self.assertEqual(cats, set(corpus.CATEGORIES))

    def test_bad_token_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "t.toml"
            p.write_text('id = "x"\nname = "x"\ncategory = "net"\n'
                         "probe = '''echo @@NOPE@@'''\n", encoding="utf-8")
            with self.assertRaises(corpus.CorpusError):
                corpus.load_dir(d)


class OracleTest(unittest.TestCase):
    def test_stdout_oracle_is_line_anchored(self):
        from breakout.runner import _stdout_passed
        self.assertTrue(_stdout_passed("ESCAPED\n"))
        self.assertTrue(_stdout_passed("noise\n  ESCAPED  \ntrailer"))
        self.assertFalse(_stdout_passed("error: cannot ESCAPED here"))
        self.assertFalse(_stdout_passed(""))
        self.assertFalse(_stdout_passed("ESCAPEDISH"))

    def test_wait_for_hit_polls_and_filters_baseline(self):
        import threading
        from breakout.runner import _wait_for_hit
        c = Canary()
        c.start()
        # a hit recorded BEFORE `after` (the baseline) must never count
        c.record("t", "n1", "http", {})
        self.assertFalse(_wait_for_hit("t", "n1", c, after=time.time() + 1,
                                       deadline=0.2, poll=0.05))
        # a hit arriving late (0.1s in) is caught by the poll
        def late():
            time.sleep(0.1)
            c.record("t", "n2", "http", {})
        threading.Thread(target=late, daemon=True).start()
        self.assertTrue(_wait_for_hit("t", "n2", c, after=time.time(),
                                      deadline=2, poll=0.05))
        c.stop()


class ScoringTest(unittest.TestCase):
    def _mk(self, passed, skipped=False):
        return runner.ProbeResult(context="p", passed=passed, skipped=skipped)

    def test_classification_matrix(self):
        t = next(x for x in corpus.load_dir(corpus.default_dir())
                 if x.id == "net-literal-ip")

        r = scoring.classify(t, self._mk(True), {"p": self._mk(True)})
        self.assertEqual(r["profiles"]["p"]["status"], "ESCAPED")

        r = scoring.classify(t, self._mk(True), {"p": self._mk(False)})
        self.assertEqual(r["profiles"]["p"]["status"], "CONTAINED")

        r = scoring.classify(t, self._mk(False), {"p": self._mk(False)})
        self.assertEqual(r["profiles"]["p"]["status"], "SKIPPED")
        self.assertIn("baseline", r["profiles"]["p"]["reason"])

        r = scoring.classify(t, self._mk(True), {"p": self._mk(False, skipped=True)})
        self.assertEqual(r["profiles"]["p"]["status"], "SKIPPED")

    def test_skip_baseline_uses_sandbox_only(self):
        t = next(x for x in corpus.load_dir(corpus.default_dir())
                 if x.id == "integrity-failopen-retry")
        r = scoring.classify(t, None, {"p": self._mk(True)})
        self.assertEqual(r["profiles"]["p"]["status"], "ESCAPED")

    def test_scores_excluded_skipped(self):
        results = {
            "a": {"meta": {"category": "net"},
                  "profiles": {"p1": {"status": "CONTAINED"}, "p2": {"status": "SKIPPED"}}},
            "b": {"meta": {"category": "net"},
                  "profiles": {"p1": {"status": "SKIPPED"}, "p2": {"status": "SKIPPED"}}},
        }
        s = scoring.scores(results)
        self.assertEqual(s["p1"]["net"]["score"], 100)
        self.assertIsNone(s["p2"]["net"]["score"])

    def test_diff_flags_regressions_only(self):
        a = {"techniques": {"t": {"profiles": {"p": {"status": "CONTAINED"}}}}}
        b = {"techniques": {"t": {"profiles": {"p": {"status": "ESCAPED"}}}}}
        regs, imps = scoring.diff_reports(a, b)
        self.assertEqual(regs, [("p", "t", "CONTAINED", "ESCAPED")])
        self.assertEqual(imps, [])
        regs, imps = scoring.diff_reports(b, a)
        self.assertEqual(imps, [("p", "t", "ESCAPED", "CONTAINED")])

    def test_diff_ignores_coverage_changes(self):
        # a technique going to/from SKIPPED is a coverage/applicability change, not a
        # containment change: never an "improvement", never a "regression".
        a = {"techniques": {"t": {"profiles": {"p": {"status": "CONTAINED"}}}}}
        b = {"techniques": {"t": {"profiles": {"p": {"status": "SKIPPED"}}}}}
        self.assertEqual(scoring.diff_reports(a, b), ([], []))
        a2 = {"techniques": {"t": {"profiles": {"p": {"status": "ESCAPED"}}}}}
        self.assertEqual(scoring.diff_reports(a2, b), ([], []))


class ProfilesTest(unittest.TestCase):
    def test_builtin_profiles_parse(self):
        for f in sorted(builtin_dir().glob("*.toml")):
            p = load_profile(f)
            self.assertIn(p.kind, ("none", "docker", "bwrap", "landlock", "custom"))

    def test_os_and_requires_gates(self):
        from breakout.sandboxes import profile_unavailable
        mac = None
        for f in sorted(builtin_dir().glob("*.toml")):
            p = load_profile(f)
            if p.slug == "seatbelt-strict":
                mac = p
        self.assertIsNotNone(mac, "seatbelt profile present")
        reason = profile_unavailable(mac)
        if runner.host_os_key() != "macos":
            self.assertIn("requires os", reason)
        ghost = type(mac)(slug="ghost", name="g", kind="custom",
                          custom={"cmd": "@@CMD@@"}, requires=["definitely-not-a-binary"])
        self.assertIn("required binary not found", profile_unavailable(ghost))

    def test_unavailable_context_skips_every_probe(self):
        ctx = runner.RunContext(name="x", kind="custom", argv=[],
                                canary_host="h", canary_port=1, decoy_dir="/d",
                                ipv6=False, abstract=False, unavailable="boom")
        self.assertIn("profile unavailable: boom",
                      runner.check_preconditions(None, ctx, set()))
        self.assertEqual(runner.probe_bins(ctx, ["sh"]), set())

    def test_preflight_catches_broken_launcher(self):
        from breakout.sandboxes import preflight
        r = preflight(["definitely-not-a-binary-xyz"])
        self.assertIsNotNone(r)
        self.assertIn("preflight failed", r)

    def test_docker_render_network_none_has_no_add_host(self):
        argv = render_docker_args({"network": "none"}, "/tmp/d")
        self.assertIn("--network", argv)
        self.assertNotIn("host.docker.internal:host-gateway", argv)
        argv = render_docker_args({"network": "bridge"}, "/tmp/d")
        self.assertIn("host.docker.internal:host-gateway", argv)


def kernel_landlock_abi():
    """Highest Landlock ABI supported by the RUNNING KERNEL (0 = unavailable).

    Probed directly with landlock_create_ruleset(NULL, 0, VERSION) instead of
    trusting the helper on purpose: a launcher that dies during its own init
    must stay distinguishable from a kernel without Landlock, otherwise the
    enforcement tests below would silently skip over exactly the bug they
    exist to catch.
    """
    if not sys.platform.startswith("linux"):
        return 0
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        rv = libc.syscall(ctypes.c_long(444),           # SYS_landlock_create_ruleset
                          ctypes.c_void_p(None), ctypes.c_size_t(0),
                          ctypes.c_uint(1))             # LANDLOCK_CREATE_RULESET_VERSION
    except (OSError, AttributeError, ValueError):
        return 0
    return max(int(rv), 0)


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"),
                     "landlock helper is Linux-only and needs cc (verified in Linux CI)")
class LandlockTest(unittest.TestCase):
    def setUp(self):
        from breakout.sandboxes import landlock_binary
        self.binary = landlock_binary()
        self.abi = kernel_landlock_abi()

    def _require_kernel_landlock(self):
        if self.abi < 1:
            self.skipTest(f"kernel does not support Landlock (abi={self.abi})")

    def test_helper_execs_allowed_command(self):
        # Positive control: the launcher must reach exec. The historical bug made
        # landlock_create_ruleset() fail with EINVAL, so the helper exited 126
        # before executing anything while the old assertion ("secret absent from
        # stdout") kept passing vacuously.
        self._require_kernel_landlock()
        r = subprocess.run([self.binary, "sh", "-c", "printf breakout-ok"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0,
                         f"launcher exited {r.returncode} before exec: "
                         f"{r.stderr.strip()[:200]}")
        self.assertEqual(r.stdout.strip(), "breakout-ok")

    def test_helper_denies_home_read_after_child_started(self):
        # The child announces itself BEFORE attempting the forbidden read, so a
        # missing secret can only mean Landlock denied it -- never that the
        # launcher failed during initialization (the old false positive).
        self._require_kernel_landlock()
        with tempfile.TemporaryDirectory(dir=Path.home()) as d:
            secret = Path(d) / "secret.env"
            secret.write_text("BREAKOUT_NONCE=test-nonce\n")
            script = ("echo breakout-child-started; "
                      f"if cat {shlex.quote(str(secret))} >/dev/null 2>&1; "
                      "then echo breakout-decoy-readable; fi")
            r = subprocess.run([self.binary, "sh", "-c", script],
                               capture_output=True, text=True, timeout=30)
        # the child actually ran under the sandbox and shut down cleanly...
        self.assertIn("breakout-child-started", r.stdout,
                      f"child never started: rc={r.returncode} {r.stderr.strip()[:200]}")
        self.assertEqual(r.returncode, 0)
        # ...and Landlock denied the home read (home is intentionally unallowed)
        self.assertNotIn("BREAKOUT_NONCE", r.stdout)
        self.assertNotIn("breakout-decoy-readable", r.stdout)

    def test_helper_fails_closed_without_landlock(self):
        # On a kernel without Landlock the only correct behavior is refusing to
        # launch (exit 126), so the runner marks the profile SKIPPED instead of
        # running unsandboxed.
        if self.abi >= 1:
            self.skipTest("kernel supports Landlock; fail-closed path unreachable")
        r = subprocess.run([self.binary, "sh", "-c", "printf breakout-ok"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 126)
        self.assertNotIn("breakout-ok", r.stdout)


class ReportingTest(unittest.TestCase):
    def _report(self):
        return {
            "tool": "undecidable-breakout", "version": breakout.__version__,
            "started": "2026-08-22T00:00:00+0000",
            "host": {"os": "windows", "kernel": "x", "baseline_mode": "auto"},
            "canary": {"port": 1, "ipv6": False, "abstract": False, "abstract_name": None},
            "run_nonce": "n",
            "techniques": {
                "t1": {"meta": {"name": "T", "category": "net", "description": "d",
                                "references": []},
                       "baseline": None,
                       "profiles": {"p": {"status": "ESCAPED", "reason": "",
                                          "result": runner.ProbeResult(
                                              context="p", passed=True,
                                              command=["sh"], output="<x>&").as_dict()}}},
            },
            "scores": {"p": {"net": {"contained": 0, "escaped": 1, "skipped": 0, "score": 0},
                             "overall": {"contained": 0, "escaped": 1, "skipped": 0,
                                         "score": 0}}},
        }

    def test_sarif_results_carry_physical_location(self):
        # regression lock for the CodeQL upload failure: a SARIF result whose
        # location object lacks a physicalLocation is rejected by Code Scanning
        # ("locationFromSarifResult: expected a physical location"), which made
        # the breakout-sarif workflow fail for the whole PR. Every ESCAPED
        # result must be anchored to a physical location.
        with tempfile.TemporaryDirectory() as d:
            reporting.write_all(self._report(), Path(d))
            sarif = json.loads((Path(d) / "report.sarif").read_text())
            results = sarif["runs"][0]["results"]
            self.assertTrue(results, "expected at least one ESCAPED result")
            for result in results:
                phys = result["locations"][0]["physicalLocation"]
                self.assertTrue(phys["artifactLocation"]["uri"])
                self.assertIn("region", phys)

    def test_reports_render_and_escape(self):
        with tempfile.TemporaryDirectory() as d:
            reporting.write_all(self._report(), Path(d))
            html = (Path(d) / "report.html").read_text(encoding="utf-8")
            self.assertIn("&lt;x&gt;&amp;", html)  # evidence is escaped
            sarif = json.loads((Path(d) / "report.sarif").read_text())
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")
            data = reporting.leaderboard([str(Path(d) / "report.json")],
                                         Path(d) / "lb.html", Path(d) / "lb.json")
            self.assertEqual(len(data["rows"]), 1)
            self.assertIn("does not mean safe", data["disclaimer"])


class SelftestCoverageTest(unittest.TestCase):
    def test_every_technique_is_ground_truthed_or_exempt(self):
        # a new technique must be either asserted in the accuracy harness or
        # consciously exempted — it can't silently escape selftest coverage.
        from breakout.selftest import GROUND_TRUTH, SELFTEST_EXEMPT
        ids = {t.id for t in corpus.load_dir(corpus.default_dir())}
        self.assertFalse(set(GROUND_TRUTH) & SELFTEST_EXEMPT,
                         "a technique is both ground-truthed and exempt")
        self.assertFalse((set(GROUND_TRUTH) | SELFTEST_EXEMPT) - ids,
                         "selftest references unknown technique ids")
        undecided = ids - set(GROUND_TRUTH) - SELFTEST_EXEMPT
        self.assertFalse(undecided,
                         f"techniques with no selftest decision: {sorted(undecided)}")


class FailopenWrapperTest(unittest.TestCase):
    def test_wrapper_marker_is_detected_by_oracle(self):
        # regression lock: the failopen-wrapper must emit a BARE `ESCAPED` line so the
        # line-anchored oracle recognizes it — a decorated line (the old bug) would be
        # a silent false CONTAINED for the exact fail-open pattern the class targets.
        from breakout.runner import _stdout_passed
        from breakout.sandboxes import find_profile
        cmd = find_profile("failopen-wrapper").custom.get("cmd", "")
        self.assertRegex(cmd, r"(?m)^\s*echo ESCAPED\s*$")
        self.assertTrue(_stdout_passed("ESCAPED\nbreakout-probe-started"))
        self.assertFalse(_stdout_passed("ESCAPED (note)\nbreakout-probe-started"))


class RedactionTest(unittest.TestCase):
    def test_command_evidence_redacts_secret_and_host_path(self):
        from breakout.reporting import _redact_cmd, _redact_report
        cmd = ["docker", "run", "-e", "BREAKOUT_DECOY_API_KEY=sk-live-abcd1234",
               "-v", r"C:\Users\monti\.breakout-decoy:/breakout-decoy:ro",
               "python:3.12-alpine"]
        joined = " ".join(_redact_cmd(cmd))
        self.assertNotIn("sk-live-abcd1234", joined)
        self.assertIn("BREAKOUT_DECOY_API_KEY=***", joined)
        self.assertNotIn("monti", joined)
        self.assertIn("/breakout-decoy:ro", joined)  # container path + mode preserved
        rep = {"techniques": {"t": {"baseline": {"command": cmd},
               "profiles": {"p": {"result": {"command": cmd}}}}}}
        _redact_report(rep)
        self.assertNotIn("sk-live-abcd1234", json.dumps(rep))
        self.assertNotIn("monti", json.dumps(rep))


if __name__ == "__main__":
    unittest.main()
