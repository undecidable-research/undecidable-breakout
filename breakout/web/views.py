"""Pages of the frontend. Each view returns a Page: the HTML body a person reads
and the `data` dict an agent reads — built from the same values, so the two can
never disagree. Nothing here executes a probe: the frontend composes commands,
the operator runs them.
"""
import html
import json
import platform
import re
import shlex
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlencode

from .. import __version__, corpus, scoring
from .jobs import RunManager
from ..reporting import _DISCLAIMER, _evidence, _rings, _tier
from ..runner import DECOY_ENV_VAR
from ..sandboxes import (builtin_dir, docker_available, host_os_key, load_profile,
                         profile_unavailable, render_bwrap_args, render_docker_args)
from ..selftest import GROUND_TRUTH, SELFTEST_EXEMPT

TAGLINE = "You can't prove the cage holds. You can prove it doesn't."
CLI = ["python", "-m", "breakout.cli"]
STATUSES = ("ESCAPED", "CONTAINED", "SKIPPED")
BASELINES = ("auto", "host", "docker")

CATEGORY_NOTES = {
    "net": "Egress. Getting bytes out of the box: parser differentials, DNS, QUIC, "
           "ICMP, IPv6.",
    "fs": "Filesystem. Reading what should be hidden, writing what should be "
          "read-only.",
    "proc": "Process. Executing or escalating around the exec and capability policy.",
    "ipc": "IPC. Control sockets, descriptors and keyrings shared across the boundary.",
    "integrity": "Integrity. Does the wrapper notice when the sandbox is not there "
                 "at all?",
}
VERDICTS = {
    "ESCAPED": "Worked outside and inside: the sandbox did not contain it.",
    "CONTAINED": "Worked outside but was stopped inside.",
    "SKIPPED": "Did not apply on this machine (missing tool, OS, canary mode). "
               "Never counted against a score.",
}
ORACLES = {
    "stdout": "The probe prints a bare ESCAPED line from inside the boundary.",
    "canary": "The probe reaches the local canary carrying this run's nonce.",
}
TOKEN_NOTES = {
    "NONCE": "per-run random nonce: a canary hit proves this run, not an old one",
    "TECH_ID": "this technique's id",
    "CANARY_URL": "the local canary's HTTP endpoint",
    "CANARY_HOST": "the canary host as seen from inside the context",
    "CANARY_PORT": "the canary's TCP port",
    "DECOY_DIR": "the planted decoy directory as seen from inside the context",
    "CANARY_ABSTRACT": "the canary's abstract UNIX socket name (Linux only)",
    "CANARY_DNS_PORT": "the canary's UDP DNS responder port",
}
FIXTURES = {
    "airgap": "docker, --network none, no host paths",
    "wide-open": "docker, bridge network, decoys mounted read-only",
    "docker-tight": "the builtin hardened profile",
    "sock-exposed": "docker, Docker control socket mounted read-only",
}
CODES = {"C": "CONTAINED", "E": "ESCAPED", "K": "SKIPPED"}

NAV = (("overview", "/"), ("leaderboard", "/leaderboard"), ("corpus", "/techniques"),
       ("profiles", "/profiles"), ("reports", "/reports"), ("diff", "/diff"),
       ("compose", "/compose"), ("agents", "/agents"))
NAV_RUNS = ("runs", "/runs")  # inserted before "agents" when --allow-runs is on

# One list feeds /api, /openapi.json, /llms.txt and the agents page.
ENDPOINTS = (
    ("/", "Overview: counts, the latest run's scorecards, the verdict legend.", {}),
    ("/leaderboard", "CI-measured leaderboard plus every profile measured in local "
                     "reports.", {}),
    ("/techniques", "The corpus.",
     {"category": "net | fs | proc | ipc | integrity",
      "q": "substring over id, name, description and required binaries"}),
    ("/techniques/{id}", "One technique: description, probe source, preconditions, "
                         "selftest ground truth, every verdict in local reports.", {}),
    ("/profiles", "Containment profiles, availability on this host, scores.", {}),
    ("/profiles/{slug}", "One profile: TOML source, rendered launcher, scores, what "
                         "escaped it.", {}),
    ("/reports", "Every report.json under the reports directory, newest first.", {}),
    ("/reports/{path}", "One report as flat rows (technique x profile).",
     {"profile": "profile slug", "status": "ESCAPED | CONTAINED | SKIPPED",
      "category": "net | fs | proc | ipc | integrity", "q": "substring over id and name"}),
    ("/diff", "Compare two reports: regressions, improvements, coverage changes.",
     {"before": "report path, e.g. report.json", "after": "report path"}),
    ("/compose", "Build a `breakout run` command from parameters. Validates, never "
                 "executes.",
     {"profile": "profile slug (repeatable)", "category": "category (repeatable)",
      "only": "comma-separated technique ids", "repeat": "integer >= 1",
      "timeout": "seconds per probe", "baseline": "auto | host | docker",
      "out": "output directory"}),
    ("/doctor", "What this host can run: docker, bwrap, cc, availability of every "
                "builtin profile.", {}),
    ("/runs", "Run history and the submit contract (POST /api/runs). Present always; "
              "runs execute only when the server was started with --allow-runs on a "
              "loopback bind.", {}),
    ("/runs/{id}", "One run: status, command, exit code, output tail, report link.", {}),
)


# --------------------------------------------------------------------------- data

@dataclass
class Page:
    title: str
    nav: str
    body: str
    data: dict
    status: int = 200
    description: str = ""


@dataclass
class Req:
    path: str
    query: dict = field(default_factory=dict)

    def one(self, name, default=""):
        v = self.query.get(name)
        return v[-1] if v else default

    def many(self, name):
        out = []
        for v in self.query.get(name, []):
            out += [x.strip() for x in v.split(",") if x.strip()]
        return out


class NotFound(Exception):
    pass


class Reports:
    """report.json files under a directory, parsed once per mtime."""

    MAX_DEPTH = 4

    def __init__(self, root):
        self.root = Path(root).resolve()
        self._cache = {}
        self._lock = threading.Lock()

    def _load(self, path):
        try:
            st = path.stat()
        except OSError:
            return None
        key = (str(path), st.st_mtime_ns, st.st_size)
        with self._lock:
            hit = self._cache.get(str(path))
            if hit and hit[0] == key:
                return hit[1]
        try:
            rep = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            rep = None
        if not (isinstance(rep, dict) and isinstance(rep.get("techniques"), dict)
                and isinstance(rep.get("scores"), dict)):
            rep = None
        with self._lock:
            self._cache[str(path)] = (key, rep)
        return rep

    def list(self):
        if not self.root.is_dir():
            return []
        out = []
        for p in self.root.rglob("report.json"):
            rel = p.relative_to(self.root)
            if len(rel.parts) > self.MAX_DEPTH or any(x.startswith(".") for x in rel.parts):
                continue
            rep = self._load(p)
            if rep is not None:
                out.append((rel.as_posix(), rep))
        out.sort(key=lambda x: (str(x[1].get("started", "")), x[0]), reverse=True)
        return out

    def get(self, rid):
        return dict(self.list()).get(rid)

    def latest(self):
        items = self.list()
        return items[0] if items else None

    def artifacts(self, rid):
        d = (self.root / rid).parent
        names = ("report.json", "report.html", "report.sarif", "report.junit.xml")
        base = Path(rid).parent.as_posix()
        pre = "" if base == "." else base + "/"
        return {n.split(".", 1)[1]: f"/files/{_qp(pre + n)}"
                for n in names if (d / n).is_file()}


class Site:
    def __init__(self, reports_dir="reports", techniques_dir=None, leaderboard_json=None,
                 allow_runs=False):
        self.reports = Reports(reports_dir)
        self.techniques_dir = Path(techniques_dir) if techniques_dir else corpus.default_dir()
        if leaderboard_json is None:
            cand = Path(__file__).resolve().parents[2] / "docs" / "leaderboard" / "index.json"
            leaderboard_json = cand if cand.is_file() else None
        self.leaderboard_json = Path(leaderboard_json) if leaderboard_json else None
        self._doctor = (0.0, None)
        self._doctor_lock = threading.Lock()
        self.runs = RunManager(self.reports.root, enabled=allow_runs)

    def techniques(self):
        return corpus.load_dir(self.techniques_dir)

    def technique(self, tid):
        for t in self.techniques():
            if t.id == tid:
                return t
        raise NotFound(f"no technique '{tid}'")

    def profiles(self):
        return [load_profile(f) for f in sorted(builtin_dir().glob("*.toml"))]

    def profile(self, slug):
        for p in self.profiles():
            if p.slug == slug:
                return p
        raise NotFound(f"no builtin profile '{slug}'")

    def ci_leaderboard(self):
        if not self.leaderboard_json or not self.leaderboard_json.is_file():
            return None
        try:
            data = json.loads(self.leaderboard_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data.get("rows"), list) else None

    def doctor(self, ttl=60):
        """Host capabilities, cached: `docker info` can take seconds."""
        with self._doctor_lock:
            ts, data = self._doctor
            if data is not None and time.monotonic() - ts < ttl:
                return data
            ok, why = docker_available()
            cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
            profiles = {}
            for p in self.profiles():
                reason = profile_unavailable(p)
                if not reason and p.kind == "docker" and not ok:
                    reason = f"docker unavailable: {why}"
                profiles[p.slug] = {"kind": p.kind, "available": reason is None,
                                    "reason": reason}
            data = {"os": host_os_key(), "platform": platform.platform(),
                    "python": platform.python_version(),
                    "docker": {"available": ok, "detail": why},
                    "bwrap": {"available": bool(shutil.which("bwrap"))},
                    "cc": {"available": bool(cc)},
                    "profiles": profiles,
                    "note": "availability is a static check (os gate, binaries, docker "
                            "daemon); `breakout run` still preflights every launcher. "
                            "Run `breakout doctor` for the canary IPv6/abstract checks."}
            self._doctor = (time.monotonic(), data)
            return data


# ------------------------------------------------------------------------ helpers

def esc(x):
    return html.escape(str(x if x is not None else ""), quote=True)


def _qp(path):
    return quote(path, safe="/")


def _url(path, **params):
    flat = []
    for k, v in params.items():
        for x in (v if isinstance(v, (list, tuple)) else [v]):
            if x not in (None, ""):
                flat.append((k, x))
    return path + ("?" + urlencode(flat) if flat else "")


def api_path(page):
    """JSON twin of a page path: /api + path, except the overview (/api is the index)."""
    return "/?format=json" if page in ("", "/") else "/api" + page


def _cmd(*args):
    return shlex.join([*CLI, *args])


def _pct(score):
    return "n/a" if score is None else str(score)


def _when(started):
    s = str(started or "")
    return s.replace("T", " ", 1)[:16] + (" " + s[19:] if len(s) > 19 else "")


def _pill(status, small=False):
    s = status if status in STATUSES else "SKIPPED"
    return (f"<span class='pill {s}{' sm' if small else ''}' data-status='{s}'>"
            f"{esc(status)}</span>")


def _meter(score, label=""):
    lab = f" role='img' aria-label='{esc(label)}'" if label else " aria-hidden='true'"
    fill = ""
    if score is not None:
        op = "o0" if score >= 80 else ("o1" if score >= 50 else "o2")
        fill = f"<rect class='f {op}' width='{int(score)}' height='4'/>"
    return (f"<svg class='meter' viewBox='0 0 100 4' preserveAspectRatio='none'{lab}>"
            f"<rect class='t' width='100' height='4'/>{fill}</svg>")


def _score_row(score):
    return (f"<span class='srow'>{_meter(score, f'{_pct(score)}% contained')}"
            f"<span class='pct{' na' if score is None else ''}'>{_pct(score)}</span></span>")


def _cmd_block(cmd, note=""):
    n = f"<p class='cmd-note'>{esc(note)}</p>" if note else ""
    return (f"<div class='cmd'>{n}<div class='cmd-line'><pre>{esc(cmd)}</pre>"
            f"<button type='button' class='btn copy' data-copy hidden "
            f"aria-label='copy command'>copy</button></div></div>")


def _h2(title, right="", hid=""):
    i = f" id='{esc(hid)}'" if hid else ""
    r = f"<span class='right'>{right}</span>" if right else ""
    return f"<h2 class='h2'{i}><span>{esc(title)}</span>{r}</h2>"


def _head(kicker, title, meta="", lede="", plain=False, rings=True, display=False):
    cls = "h1" + (" plain" if plain else "") + (" display" if display else "")
    return ("<header class='head'>" + (_rings() if rings else "")
            + f"<p class='kicker'>{kicker}</p><h1 class='{cls}'>{title}</h1>"
            + (f"<p class='meta'>{meta}</p>" if meta else "")
            + (f"<p class='lede'>{lede}</p>" if lede else "") + "</header>")


def _honesty():
    return (f"<aside class='warn' aria-label='disclaimer'><b>honesty first</b>"
            f"<span>{esc(_DISCLAIMER)}</span></aside>")


def _facts(pairs):
    rows = "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in pairs)
    return f"<dl class='facts'>{rows}</dl>"


def _crumbs(*items):
    parts = []
    for label, href in items:
        parts.append(f"<a href='{esc(href)}'>{esc(label)}</a>" if href
                     else f"<span aria-current='page'>{esc(label)}</span>")
    return f"<nav class='crumbs' aria-label='breadcrumb'>{'<i>/</i>'.join(parts)}</nav>"


def _chips(name, options, current, legend):
    """Radio chips: a real form control (works without JS, keyboard-navigable)."""
    out = [f"<fieldset class='chips'><legend>{esc(legend)}</legend>"]
    for value, label, count in options:
        chk = " checked" if value == current else ""
        c = f" <small>{count}</small>" if count is not None else ""
        out.append(f"<label class='chip'><input type='radio' name='{esc(name)}' "
                   f"value='{esc(value)}'{chk}><span>{esc(label)}{c}</span></label>")
    out.append("</fieldset>")
    return "".join(out)


def _empty(text, cmd=None):
    return (f"<div class='empty'><p>{text}</p>" + (_cmd_block(cmd) if cmd else "")
            + "</div>")


def _selftest(tid):
    if tid in GROUND_TRUTH:
        return {"status": "ground-truth",
                "expected": {k: CODES[v] for k, v in GROUND_TRUTH[tid].items()}}
    if tid in SELFTEST_EXEMPT:
        return {"status": "exempt",
                "why": "needs a real Linux host, bwrap, an IPv6/abstract canary, or a "
                       "capability the docker fixtures cannot reproduce; measured by "
                       "the CI leaderboard instead"}
    return {"status": "undecided"}


def _tech_dict(t):
    return {"id": t.id, "name": t.name, "category": t.category,
            "description": t.description, "references": list(t.references),
            "oracle": t.oracle, "paired_baseline": not t.skip_baseline,
            "preconditions": {"os": list(t.os), "bins": list(t.bins),
                              "canary": t.canary_mode or None,
                              "timeout": t.timeout or None},
            "selftest": _selftest(t.id),
            "url": f"/techniques/{t.id}", "api": f"/api/techniques/{t.id}"}


def _search_text(*parts):
    return " ".join(str(p) for p in parts if p).lower()


def _report_summary(site, rid, rep):
    return {"id": rid, "url": f"/reports/{_qp(rid)}", "api": f"/api/reports/{_qp(rid)}",
            "started": rep.get("started"), "version": rep.get("version"),
            "host": rep.get("host"), "techniques": len(rep.get("techniques", {})),
            "scores": {slug: s.get("overall") for slug, s in rep.get("scores", {}).items()},
            "artifacts": site.reports.artifacts(rid)}


def _launcher(p):
    """What the harness launches for a profile, redacted like report evidence."""
    from ..reporting import _redact_cmd
    if p.kind == "docker":
        argv = render_docker_args(p.docker, None, env={DECOY_ENV_VAR: "***"}) + ["sh", "-s"]
    elif p.kind == "bwrap":
        argv = render_bwrap_args(p.bwrap) + ["sh", "-s"]
    elif p.kind == "landlock":
        argv = ["<landlock-helper>", "sh", "-s"]
    elif p.kind == "none":
        argv = ["sh", "-s"]
    else:
        return p.custom.get("cmd", "").strip().replace("@@CMD@@", "sh -s")
    home = str(Path.home())
    return shlex.join(x.replace(home, "~") if isinstance(x, str) else x
                      for x in _redact_cmd(argv))


# -------------------------------------------------------------------------- views

def overview(site, req):
    techs, profiles, reports = site.techniques(), site.profiles(), site.reports.list()
    cats = {c: sum(1 for t in techs if t.category == c) for c in corpus.CATEGORIES}
    latest = reports[0] if reports else None
    data = {"name": "undecidable-breakout", "version": __version__, "tagline": TAGLINE,
            "disclaimer": _DISCLAIMER,
            "counts": {"techniques": len(techs), "categories": cats,
                       "profiles": len(profiles), "reports": len(reports)},
            "latest_report": _report_summary(site, *latest) if latest else None,
            "verdicts": VERDICTS, "api": "/api", "llms_txt": "/llms.txt"}

    b = [_head(f"conformance suite · v{esc(__version__)}",
               "<span>undecidable-</span><span>breakout</span>",
               lede=esc(TAGLINE), display=True),
         "<p class='prose'>A fixed corpus of documented escape techniques, run "
         "<em>from inside</em> your sandbox. Every technique runs twice: outside, to "
         "learn whether it works on this machine at all, and inside, to learn whether "
         "the cage stopped it. It does not prove a sandbox is safe. It proves, "
         "reproducibly, when it is not.</p>",
         _honesty()]

    facts = [("techniques", len(techs), "/techniques", f"{len(cats)} classes of escape"),
             ("profiles", len(profiles), "/profiles", "containment configurations"),
             ("reports", len(reports), "/reports", "measured on this host"),
             ("ground truth", len(GROUND_TRUTH), "/techniques",
              f"techniques asserted by selftest · {len(SELFTEST_EXEMPT)} exempt")]
    b.append("<div class='cards facts-grid'>" + "".join(
        f"<a class='card' href='{h}' data-fact='{esc(k)}'><span class='slug'>{esc(k)}</span>"
        f"<span class='score s-hi'>{n}</span><span class='sub'>{esc(s)}</span></a>"
        for k, n, h, s in facts) + "</div>")

    if latest:
        rid, rep = latest
        b.append(_h2("latest run", f"<a href='/reports/{_qp(rid)}'>{esc(rid)} · "
                                   f"{esc(_when(rep.get('started')))}</a>"))
        b.append(_scorecards(rep, rid))
    else:
        b.append(_h2("latest run"))
        b.append(_empty("No report yet in the reports directory. Measure two "
                        "configurations and they appear here.",
                        _cmd("run", "--profile", "docker-loose", "--profile",
                             "docker-tight", "--out", "reports/")))

    b.append(_h2("how it works"))
    b.append("<ol class='steps'>"
             "<li><b>plant</b><span>A canary starts on this machine (localhost HTTP and, "
             "on Linux, an abstract UNIX socket) and decoy files land in "
             "<code>~/.breakout-decoy</code>. Nothing about your system leaves the "
             "machine.</span></li>"
             "<li><b>pair</b><span>Each technique runs outside the sandbox (baseline: "
             "does it work here at all?) and inside (did the sandbox stop it?). A "
             "launcher that cannot start is skipped with its reason, never scored as "
             "contained.</span></li>"
             "<li><b>judge</b><span>A binary oracle decides: a bare <code>ESCAPED</code> "
             "line on stdout, or a canary hit carrying this run's nonce.</span></li></ol>")

    b.append(_h2("verdicts"))
    b.append("<dl class='verdicts'>" + "".join(
        f"<dt>{_pill(s)}</dt><dd>{esc(VERDICTS[s])}</dd>" for s in STATUSES) + "</dl>")

    b.append(_h2("start here", "<a href='/compose'>compose a run →</a>"))
    b.append(_cmd_block(_cmd("verify"), "10-second self-check, no Docker needed"))
    b.append(_cmd_block(_cmd("run", "--profile", "docker-loose", "--profile",
                             "docker-tight", "--out", "reports/"),
                        "one red scorecard, one green-ish one"))
    b.append(_cmd_block(_cmd("serve", "--reports", "reports/"),
                        "this frontend, over whatever lands in reports/"))

    b.append(_h2("for agents", "<a href='/agents'>interface →</a>"))
    b.append("<p class='prose'>Every page you see has a JSON twin with the same facts: "
             "send <code>Accept: application/json</code>, add <code>?format=json</code>, "
             "or prefix the path with <code>/api</code>. Start at "
             "<a href='/llms.txt'>/llms.txt</a>. The frontend is read-only: it never runs "
             "a probe.</p>")
    return Page("overview", "overview", "".join(b), data,
                description=f"{TAGLINE} A conformance suite that tests whether a "
                            f"sandbox actually holds.")


def _scorecards(rep, rid):
    cards = []
    for slug, scores in rep.get("scores", {}).items():
        o = scores.get("overall", {})
        href = _url(f"/reports/{_qp(rid)}", profile=slug)
        cards.append(
            f"<a class='card' href='{esc(href)}' data-profile='{esc(slug)}' "
            f"data-score='{'' if o.get('score') is None else o['score']}'>"
            f"<span class='slug'>{esc(slug)}</span>"
            f"<span class='score {_tier(o.get('score'))}'>{_pct(o.get('score'))}</span>"
            f"<span class='sub'>{o.get('contained', 0)} contained · "
            f"{o.get('escaped', 0)} escaped · {o.get('skipped', 0)} skipped</span>"
            f"{_meter(o.get('score'))}</a>")
    return f"<div class='cards'>{''.join(cards)}</div>"


def leaderboard(site, req):
    ci = site.ci_leaderboard()
    local = []
    for rid, rep in site.reports.list():
        for slug, scores in rep.get("scores", {}).items():
            row = {"profile": slug, "report": rid, "date": rep.get("started"),
                   "host": f"{rep.get('host', {}).get('os', '')} "
                           f"{rep.get('host', {}).get('kernel', '')}".strip(),
                   "corpus_version": rep.get("version"),
                   "overall": scores.get("overall", {}).get("score")}
            row.update({c: (scores.get(c) or {}).get("score") for c in corpus.CATEGORIES})
            local.append(row)
    rank = lambda r: (r.get("overall") is None, -(r.get("overall") or 0), r.get("profile", ""))
    local.sort(key=rank)
    ci_rows = sorted(ci["rows"], key=rank) if ci else []
    data = {"disclaimer": _DISCLAIMER, "ci": ci_rows, "local": local,
            "score": "percentage of applicable techniques contained; skipped never "
                     "counts"}

    b = [_head("leaderboard", "which cages held",
               meta="measured, not self-reported · higher is better · "
                    "skipped never counts against a score"),
         _honesty(), _h2("measured by ci", f"{len(ci_rows)} profiles · pinned ubuntu "
                                           f"runner")]
    if ci_rows:
        b.append(_lb_table(ci_rows, with_report=False))
    else:
        b.append(_empty("No CI leaderboard found (docs/leaderboard/index.json). It is "
                        "published by the leaderboard workflow on every push to main."))
    b.append(_h2("measured here", f"{len(local)} rows from local reports"))
    if local:
        b.append(_lb_table(local, with_report=True))
    else:
        b.append(_empty("No local report yet.",
                        _cmd("run", "--profile", "docker-tight", "--out", "reports/")))
    return Page("leaderboard", "leaderboard", "".join(b), data)


def _lb_table(rows, with_report):
    head = ("<thead><tr><th scope='col'>#</th><th scope='col'>profile</th>"
            "<th scope='col' class='w-bar'>overall</th>"
            + "".join(f"<th scope='col'>{c}</th>" for c in corpus.CATEGORIES)
            + ("<th scope='col'>report</th>" if with_report else "")
            + "<th scope='col'>measured on</th><th scope='col'>date</th>"
              "<th scope='col'>corpus</th></tr></thead>")
    body = []
    for i, r in enumerate(rows, 1):
        rep = (f"<td><a href='/reports/{_qp(r['report'])}'>{esc(r['report'])}</a></td>"
               if with_report else "")
        body.append(
            f"<tr data-row data-profile='{esc(r['profile'])}' "
            f"data-score='{'' if r['overall'] is None else r['overall']}'>"
            f"<td class='note'>{i}</td>"
            f"<th scope='row'><a class='tname' href='/profiles/{esc(r['profile'])}'>"
            f"{esc(r['profile'])}</a></th><td>{_score_row(r['overall'])}</td>"
            + "".join(f"<td class='num'>{_pct(r.get(c))}</td>" for c in corpus.CATEGORIES)
            + rep + f"<td class='note'>{esc(r.get('host'))}</td>"
            f"<td class='note'>{esc(_when(r.get('date')))}</td>"
            f"<td class='note'>v{esc(r.get('corpus_version'))}</td></tr>")
    return f"<div class='scroll'><table>{head}<tbody>{''.join(body)}</tbody></table></div>"


def techniques_index(site, req):
    techs = site.techniques()
    cat, q = req.one("category"), req.one("q").strip()
    errors = []
    if cat and cat not in corpus.CATEGORIES:
        errors.append(f"unknown category '{cat}'; valid: {', '.join(corpus.CATEGORIES)}")
        cat = ""
    latest = site.reports.latest()
    lslugs = list(latest[1].get("scores", {})) if latest else []

    def verdicts(t):
        if not latest:
            return {}
        rec = latest[1]["techniques"].get(t.id, {}).get("profiles", {})
        return {s: rec[s]["status"] for s in lslugs if s in rec}

    rows = []
    for t in techs:
        hay = _search_text(t.id, t.name, t.description, " ".join(t.bins), t.category)
        shown = (not cat or t.category == cat) and (not q or q.lower() in hay)
        rows.append((t, hay, shown, verdicts(t)))
    items = [dict(_tech_dict(t), latest=v) for t, _, shown, v in rows if shown]
    data = {"count": len(items), "total": len(techs), "filters": {"category": cat, "q": q},
            "errors": errors, "categories": {c: CATEGORY_NOTES[c] for c in corpus.CATEGORIES},
            "latest_report": latest[0] if latest else None, "techniques": items}

    counts = {c: sum(1 for t in techs if t.category == c) for c in corpus.CATEGORIES}
    gt = sum(1 for t in techs if t.id in GROUND_TRUTH)
    b = [_head("corpus", f"{len(techs)} techniques",
               meta=f"{len(corpus.CATEGORIES)} classes · organized by how you get out · "
                    f"{gt} ground-truthed · {len(techs) - gt} exempt"),
         "<form class='filters' method='get' action='/techniques' data-filter='#corpus' "
         "role='search' aria-label='filter techniques'>"
         "<label class='field'><span>search <kbd>/</kbd></span>"
         f"<input type='search' name='q' value='{esc(q)}' placeholder='id, name, binary…' "
         "autocomplete='off' spellcheck='false'></label>",
         _chips("category", [("", "all", len(techs))]
                + [(c, c, counts[c]) for c in corpus.CATEGORIES], cat, "class"),
         "<button class='btn nojs-only' type='submit'>apply</button>"
         f"<p class='count' aria-live='polite'><span data-count>{len(items)}</span> "
         f"of {len(techs)} shown</p></form>"]
    b += [f"<p class='error' role='alert'>{esc(e)}</p>" for e in errors]
    if latest:
        b.append(f"<p class='note-l'>verdict columns: latest report "
                 f"<a href='/reports/{_qp(latest[0])}'>{esc(latest[0])}</a> · "
                 f"{esc(_when(latest[1].get('started')))}</p>")

    b.append("<div id='corpus'>")
    for c in corpus.CATEGORIES:
        group = [r for r in rows if r[0].category == c]
        hidden = "" if any(r[2] for r in group) else " hidden"
        b.append(f"<section data-group data-category-group='{c}'{hidden} "
                 f"aria-labelledby='cat-{c}'>"
                 + _h2(c, f"{len(group)} techniques", f"cat-{c}")
                 + f"<p class='note-l'>{esc(CATEGORY_NOTES[c])}</p>"
                 "<div class='scroll'><table><thead><tr>"
                 "<th scope='col'>technique</th><th scope='col'>oracle</th>"
                 "<th scope='col'>needs</th><th scope='col'>selftest</th>"
                 + "".join(f"<th scope='col'>{esc(s)}</th>" for s in lslugs)
                 + "</tr></thead><tbody>")
        for t, hay, shown, v in group:
            needs = ", ".join(t.bins + ([f"canary:{t.canary_mode}"] if t.canary_mode else []))
            st = _selftest(t.id)["status"]
            b.append(
                f"<tr data-row data-technique='{esc(t.id)}' data-category='{c}' "
                f"data-search='{esc(hay)}'{'' if shown else ' hidden'}>"
                f"<th scope='row'><a class='tname' href='/techniques/{esc(t.id)}'>"
                f"{esc(t.id)}<small>{esc(t.name)}</small></a></th>"
                f"<td class='note'>{esc(t.oracle)}</td>"
                f"<td class='note'>{esc(needs) or '—'}</td>"
                f"<td class='note'>{esc(st)}</td>"
                + "".join(f"<td>{_pill(v[s], True) if s in v else '—'}</td>" for s in lslugs)
                + "</tr>")
        b.append("</tbody></table></div></section>")
    b.append(f"<p class='empty' data-empty{' hidden' if items else ''}>No technique matches. "
             f"<a href='/techniques'>Clear the filters</a>.</p></div>")
    return Page("corpus", "corpus", "".join(b), data)


def technique_detail(site, req, tid):
    techs = site.techniques()
    idx = next((i for i, t in enumerate(techs) if t.id == tid), None)
    if idx is None:
        raise NotFound(f"no technique '{tid}'")
    t = techs[idx]
    verdicts = []
    for rid, rep in site.reports.list():
        rec = rep["techniques"].get(t.id)
        if not rec:
            continue
        for slug, p in rec.get("profiles", {}).items():
            verdicts.append((rid, rep, slug, p))
    tokens = [k for k in corpus.TOKENS if t.uses_token(k)]
    st = _selftest(t.id)
    run_cmd = _cmd("run", "--profile", "docker-loose", "--profile", "docker-tight",
                   "--only", t.id, "--out", f"reports/{t.id}/")
    data = dict(_tech_dict(t), probe=t.probe.strip("\n"),
                tokens={k: TOKEN_NOTES.get(k, "") for k in tokens},
                verdicts=[{"report": rid, "started": rep.get("started"), "profile": slug,
                           "status": p["status"], "reason": p.get("reason", ""),
                           "flaky": bool((p.get("result") or {}).get("flaky"))}
                          for rid, rep, slug, p in verdicts],
                commands={"run": run_cmd},
                prev=techs[idx - 1].id if idx > 0 else None,
                next=techs[idx + 1].id if idx + 1 < len(techs) else None)

    b = [_crumbs(("corpus", "/techniques"),
                 (t.category, _url("/techniques", category=t.category)), (t.id, None)),
         _head(f"{esc(t.category)} · {esc(t.id)}", esc(t.name), plain=True, rings=False),
         f"<p class='prose'>{esc(t.description)}</p>"]
    pre = t.os and ", ".join(t.os)
    b.append(_facts([
        ("class", f"<a href='{_url('/techniques', category=t.category)}'>{esc(t.category)}</a>"
                  f" <span class='note'>{esc(CATEGORY_NOTES[t.category])}</span>"),
        ("oracle", f"{esc(t.oracle)} <span class='note'>{esc(ORACLES[t.oracle])}</span>"),
        ("baseline", "paired: runs outside first; skipped here if it cannot work outside"
         if not t.skip_baseline else "sandbox only: the escape is a configuration "
                                     "artifact with no meaningful outside run"),
        ("host os", esc(pre) or "any"),
        ("needs", esc(", ".join(t.bins)) or "nothing beyond sh"),
        ("canary", esc(t.canary_mode) or "default (HTTP on localhost)"),
        ("timeout", f"{t.timeout}s" if t.timeout else "run default (20s)"),
        ("selftest", esc(st["status"])),
    ]))

    if st["status"] == "ground-truth":
        b.append(_h2("ground truth", "verdicts the accuracy harness asserts"))
        b.append("<div class='scroll'><table><thead><tr><th scope='col'>fixture</th>"
                 "<th scope='col'>what it is</th><th scope='col'>expected</th></tr></thead>"
                 "<tbody>" + "".join(
                     f"<tr><th scope='row' class='tname'>{esc(f)}</th>"
                     f"<td class='note'>{esc(FIXTURES.get(f, ''))}</td>"
                     f"<td>{_pill(v, True)}</td></tr>" for f, v in st["expected"].items())
                 + "</tbody></table></div>")
    elif st["status"] == "exempt":
        b.append(f"<p class='note-l'>Exempt from the docker-only selftest: "
                 f"{esc(st['why'])}.</p>")

    b.append(_h2("measured here", f"{len(verdicts)} verdicts in local reports"))
    if verdicts:
        b.append("<div class='scroll'><table><thead><tr><th scope='col'>report</th>"
                 "<th scope='col'>profile</th><th scope='col'>status</th>"
                 "<th scope='col'>notes</th></tr></thead><tbody>")
        for rid, rep, slug, p in verdicts:
            flaky = " <span class='note'>· flaky</span>" if (p.get("result") or {}).get(
                "flaky") else ""
            b.append(f"<tr data-row data-report='{esc(rid)}' data-profile='{esc(slug)}' "
                     f"data-status='{esc(p['status'])}'>"
                     f"<td><a href='/reports/{_qp(rid)}'>{esc(rid)}</a>"
                     f"<small class='block note'>{esc(_when(rep.get('started')))}</small></td>"
                     f"<td><a href='/profiles/{esc(slug)}'>{esc(slug)}</a></td>"
                     f"<td>{_pill(p['status'])}{flaky}</td>"
                     f"<td><span class='note'>{esc(p.get('reason', ''))}</span>"
                     f"{_evidence(p)}</td></tr>")
        b.append("</tbody></table></div>")
    else:
        b.append(_empty("Not measured on this host yet.", run_cmd))

    b.append(_h2("probe", "rendered shell, run inside the context"))
    b.append(f"<pre class='src'>{esc(t.probe.strip(chr(10)))}</pre>")
    if tokens:
        b.append("<dl class='facts tokens'>" + "".join(
            f"<dt>@@{esc(k)}@@</dt><dd>{esc(TOKEN_NOTES.get(k, ''))}</dd>" for k in tokens)
                 + "</dl>")

    if t.references:
        b.append(_h2("sources"))
        b.append("<ul class='refs'>" + "".join(f"<li>{esc(r)}</li>" for r in t.references)
                 + "</ul>")

    b.append(_h2("reproduce"))
    b.append(_cmd_block(run_cmd, "loose vs tight, this technique only"))
    b.append(_pager(("technique", "/techniques/", data["prev"], data["next"])))
    return Page(t.id, "corpus", "".join(b), data, description=t.description[:300])


def _pager(spec):
    _, base, prev, nxt = spec
    p = (f"<a rel='prev' href='{base}{esc(prev)}'>← {esc(prev)}</a>" if prev else "<span></span>")
    n = (f"<a rel='next' href='{base}{esc(nxt)}'>{esc(nxt)} →</a>" if nxt else "<span></span>")
    return f"<nav class='pager' aria-label='pagination'>{p}{n}</nav>"


def profiles_index(site, req):
    profiles = site.profiles()
    doc = site.doctor()
    ci = {r["profile"]: r for r in (site.ci_leaderboard() or {}).get("rows", [])}
    latest_local = {}
    for rid, rep in site.reports.list():
        for slug, s in rep.get("scores", {}).items():
            latest_local.setdefault(slug, (rid, s.get("overall", {}).get("score")))
    items = []
    for p in profiles:
        av = doc["profiles"].get(p.slug, {})
        items.append({"slug": p.slug, "name": p.name, "kind": p.kind,
                      "description": p.description, "os": list(p.os_allow),
                      "requires": list(p.requires),
                      "available_here": av.get("available"), "unavailable_reason": av.get("reason"),
                      "ci_score": ci.get(p.slug, {}).get("overall"),
                      "local_score": latest_local.get(p.slug, (None, None))[1],
                      "url": f"/profiles/{p.slug}", "api": f"/api/profiles/{p.slug}"})
    data = {"count": len(items), "profiles": items, "host": {
        "os": doc["os"], "docker": doc["docker"]["available"]}}

    b = [_head("profiles", f"{len(items)} cages",
               meta="profiles are data (toml) · write your own: examples/profiles/ · "
                    f"host {esc(doc['os'])} · docker "
                    f"{'ok' if doc['docker']['available'] else 'unavailable'}"),
         "<div class='scroll'><table><thead><tr><th scope='col'>profile</th>"
         "<th scope='col'>kind</th><th scope='col'>what it is</th>"
         "<th scope='col'>here</th><th scope='col' class='w-bar'>ci</th>"
         "<th scope='col' class='w-bar'>local</th></tr></thead><tbody>"]
    for it in items:
        here = ("<span class='pill CONTAINED sm'>runs</span>" if it["available_here"]
                else f"<span class='pill SKIPPED sm' title='{esc(it['unavailable_reason'])}'>"
                     f"no</span><small class='block note'>"
                     f"{esc(it['unavailable_reason'])}</small>")
        b.append(f"<tr data-row data-profile='{esc(it['slug'])}' data-kind='{esc(it['kind'])}' "
                 f"data-available='{str(bool(it['available_here'])).lower()}'>"
                 f"<th scope='row'><a class='tname' href='{it['url']}'>{esc(it['slug'])}</a></th>"
                 f"<td class='note'>{esc(it['kind'])}</td>"
                 f"<td class='desc'>{esc(it['description'])}</td><td>{here}</td>"
                 f"<td>{_score_row(it['ci_score'])}</td>"
                 f"<td>{_score_row(it['local_score'])}</td></tr>")
    b.append("</tbody></table></div>"
             "<p class='note-l'>here: static check (os gate, required binaries, docker "
             "daemon) · <a href='/doctor'>host details</a> · <code>breakout run</code> "
             "still preflights every launcher</p>")
    return Page("profiles", "profiles", "".join(b), data)


def profile_detail(site, req, slug):
    p = site.profile(slug)
    doc = site.doctor()["profiles"].get(slug, {})
    src = Path(p.source).read_text(encoding="utf-8") if p.source else ""
    launcher = _launcher(p)
    ci = next((r for r in (site.ci_leaderboard() or {}).get("rows", [])
               if r.get("profile") == slug), None)
    local, escaped = [], None
    for rid, rep in site.reports.list():
        s = rep.get("scores", {}).get(slug)
        if not s:
            continue
        local.append((rid, rep, s))
        if escaped is None:
            escaped = (rid, [(tid, t["meta"]["name"]) for tid, t in rep["techniques"].items()
                             if t.get("profiles", {}).get(slug, {}).get("status") == "ESCAPED"])
    run_cmd = _cmd("run", "--profile", slug, "--out", f"reports/{slug}/")
    data = {"slug": p.slug, "name": p.name, "kind": p.kind, "description": p.description,
            "os": list(p.os_allow), "requires": list(p.requires),
            "available_here": doc.get("available"), "unavailable_reason": doc.get("reason"),
            "toml": src, "launcher": launcher, "ci": ci,
            "local": [{"report": rid, "started": rep.get("started"),
                       "scores": {c: v.get("score") for c, v in s.items()}}
                      for rid, rep, s in local],
            "escaped_in_latest": ({"report": escaped[0],
                                   "techniques": [t for t, _ in escaped[1]]}
                                  if escaped else None),
            "commands": {"run": run_cmd}}

    b = [_crumbs(("profiles", "/profiles"), (slug, None)),
         _head(f"{esc(p.kind)} profile", esc(slug), rings=True,
               meta=("runs on this host" if doc.get("available")
                     else f"unavailable here · {esc(doc.get('reason'))}")),
         f"<p class='prose'>{esc(p.description)}</p>"]

    rows = []
    if ci:
        rows.append(("ci", ci.get("date"), {c: ci.get(c) for c in ("overall", *corpus.CATEGORIES)},
                     None))
    for rid, rep, s in local:
        rows.append((rid, rep.get("started"),
                     {c: (s.get(c) or {}).get("score") for c in ("overall", *corpus.CATEGORIES)},
                     f"/reports/{_qp(rid)}"))
    b.append(_h2("scores", "percentage of applicable techniques contained"))
    if rows:
        b.append("<div class='scroll'><table><thead><tr><th scope='col'>measured by</th>"
                 "<th scope='col' class='w-bar'>overall</th>"
                 + "".join(f"<th scope='col'>{c}</th>" for c in corpus.CATEGORIES)
                 + "<th scope='col'>date</th></tr></thead><tbody>")
        for label, when, sc, href in rows:
            name = f"<a href='{esc(href)}'>{esc(label)}</a>" if href else esc(label)
            b.append(f"<tr><th scope='row' class='tname'>{name}</th>"
                     f"<td>{_score_row(sc['overall'])}</td>"
                     + "".join(f"<td class='num'>{_pct(sc.get(c))}</td>"
                               for c in corpus.CATEGORIES)
                     + f"<td class='note'>{esc(_when(when))}</td></tr>")
        b.append("</tbody></table></div>")
    else:
        b.append(_empty("Not measured yet.", run_cmd))

    if escaped:
        rid, techs = escaped
        b.append(_h2("what got out", f"{len(techs)} escaped in "
                                     f"<a href='{esc(_url('/reports/' + _qp(rid), profile=slug, status='ESCAPED'))}'>"
                                     f"{esc(rid)}</a>"))
        b.append("<ul class='escaped'>" + "".join(
            f"<li data-technique='{esc(tid)}'><a class='tname' href='/techniques/{esc(tid)}'>"
            f"{esc(tid)}<small>{esc(name)}</small></a></li>" for tid, name in techs)
                 + "</ul>" if techs else "<p class='prose'>Nothing escaped in the latest "
                                         "report. That is a measurement, not a "
                                         "certification.</p>")

    b.append(_h2("launcher", "what the harness wraps every probe in"))
    b.append(f"<pre class='src'>{esc(launcher)}</pre>")
    b.append(_h2("source", esc(Path(p.source).name)))
    b.append(f"<pre class='src'>{esc(src.strip())}</pre>")
    b.append(_h2("reproduce"))
    b.append(_cmd_block(run_cmd))
    return Page(slug, "profiles", "".join(b), data, description=p.description[:300])


def reports_index(site, req):
    reports = site.reports.list()
    items = [_report_summary(site, rid, rep) for rid, rep in reports]
    data = {"root": site.reports.root.name, "count": len(items), "reports": items}
    b = [_head("reports", f"{len(items)} on disk",
               meta=f"every report.json under {esc(site.reports.root.name)}/ · newest first")]
    if not items:
        b.append(_empty("No report.json found. Run the corpus and point "
                        "<code>serve --reports</code> at the output directory.",
                        _cmd("run", "--profile", "docker-tight", "--out", "reports/")))
        return Page("reports", "reports", "".join(b), data)
    b.append("<div class='scroll'><table><thead><tr><th scope='col'>report</th>"
             "<th scope='col'>started</th><th scope='col'>host</th>"
             "<th scope='col'>profiles</th><th scope='col'>files</th></tr></thead><tbody>")
    for it in items:
        profs = "".join(f"<span class='kv'><a href='{esc(_url(it['url'], profile=s))}'>"
                        f"{esc(s)}</a> <b>{_pct((o or {}).get('score'))}</b></span>"
                        for s, o in it["scores"].items())
        files = " · ".join(f"<a href='{esc(u)}'>{esc(k)}</a>" for k, u in it["artifacts"].items())
        host = it.get("host") or {}
        b.append(f"<tr data-row data-report='{esc(it['id'])}'>"
                 f"<th scope='row'><a class='tname' href='{esc(it['url'])}'>{esc(it['id'])}"
                 f"<small>v{esc(it['version'])} · {it['techniques']} techniques</small></a></th>"
                 f"<td class='note'>{esc(_when(it['started']))}</td>"
                 f"<td class='note'>{esc(host.get('os'))} {esc(host.get('kernel'))}</td>"
                 f"<td>{profs}</td><td class='note'>{files}</td></tr>")
    b.append("</tbody></table></div>")
    if len(items) >= 2:
        b.append(_cmd_block(_cmd("diff", f"reports/{items[1]['id']}",
                                 f"reports/{items[0]['id']}"),
                            "compare the two newest: exit 1 on any regression"))
    return Page("reports", "reports", "".join(b), data)


def report_detail(site, req, rid):
    rep = site.reports.get(rid)
    if rep is None:
        raise NotFound(f"no report '{rid}' under {site.reports.root.name}/")
    slugs = list(rep.get("scores", {}))
    f = {"profile": req.one("profile"), "status": req.one("status").upper(),
         "category": req.one("category"), "q": req.one("q").strip()}
    errors = []
    for key, valid in (("profile", slugs), ("status", STATUSES),
                       ("category", corpus.CATEGORIES)):
        if f[key] and f[key] not in valid:
            errors.append(f"unknown {key} '{f[key]}'; valid: {', '.join(valid)}")
            f[key] = ""

    rows = []
    for tid, t in rep["techniques"].items():
        meta = t.get("meta", {})
        for slug, p in t.get("profiles", {}).items():
            hay = _search_text(tid, meta.get("name"))
            shown = ((not f["profile"] or slug == f["profile"])
                     and (not f["status"] or p["status"] == f["status"])
                     and (not f["category"] or meta.get("category") == f["category"])
                     and (not f["q"] or f["q"].lower() in hay))
            rows.append((tid, meta, slug, p, hay, shown))
    flat = [{"technique": tid, "name": m.get("name"), "category": m.get("category"),
             "profile": slug, "status": p["status"], "reason": p.get("reason", ""),
             "flaky": bool((p.get("result") or {}).get("flaky")),
             "technique_url": f"/techniques/{tid}"}
            for tid, m, slug, p, _, shown in rows if shown]
    summ = _report_summary(site, rid, rep)
    data = {"report": summ, "filters": f, "errors": errors, "count": len(flat),
            "total": len(rows), "scores": rep.get("scores"), "rows": flat,
            "evidence": "full evidence (commands, output, canary hits): "
                        + summ["artifacts"].get("json", "")}

    host = rep.get("host", {})
    b = [_crumbs(("reports", "/reports"), (rid, None)),
         _head("conformance report", esc(rid), plain=True,
               meta=f"v{esc(rep.get('version'))} · {esc(_when(rep.get('started')))} · "
                    f"host {esc(host.get('os'))} {esc(host.get('kernel'))} · baseline "
                    f"{esc(host.get('baseline_mode'))} · nonce {esc(rep.get('run_nonce'))}"),
         _honesty(), _scorecards(rep, rid)]
    files = " · ".join(f"<a href='{esc(u)}'>{esc(k)}</a>" for k, u in summ["artifacts"].items())
    b.append(f"<p class='note-l'>files: {files} · "
             f"<a href='{esc(_url('/diff', after=rid))}'>compare with another report</a></p>")

    status_counts = {s: sum(1 for r in rows if r[3]["status"] == s) for s in STATUSES}
    b.append(f"<form class='filters' method='get' action='/reports/{_qp(rid)}' "
             "data-filter='#rows' role='search' aria-label='filter verdicts'>"
             "<label class='field'><span>search <kbd>/</kbd></span>"
             f"<input type='search' name='q' value='{esc(f['q'])}' placeholder='technique…' "
             "autocomplete='off' spellcheck='false'></label>"
             + _chips("status", [("", "all", len(rows))]
                      + [(s, s.lower(), status_counts[s]) for s in STATUSES], f["status"],
                      "status")
             + _chips("profile", [("", "all", None)] + [(s, s, None) for s in slugs],
                      f["profile"], "profile")
             + _chips("category", [("", "all", None)]
                      + [(c, c, None) for c in corpus.CATEGORIES], f["category"], "class")
             + "<button class='btn nojs-only' type='submit'>apply</button>"
             f"<p class='count' aria-live='polite'><span data-count>{len(flat)}</span> of "
             f"{len(rows)} verdicts</p></form>")
    b += [f"<p class='error' role='alert'>{esc(e)}</p>" for e in errors]

    b.append("<div id='rows'>")
    for c in corpus.CATEGORIES:
        group = [r for r in rows if r[1].get("category") == c]
        if not group:
            continue
        hidden = "" if any(r[5] for r in group) else " hidden"
        b.append(f"<section data-group{hidden} aria-labelledby='rc-{c}'>"
                 + _h2(c, f"{len({r[0] for r in group})} techniques", f"rc-{c}")
                 + "<div class='scroll'><table><thead><tr><th scope='col'>technique</th>"
                   "<th scope='col'>profile</th><th scope='col'>status</th>"
                   "<th scope='col'>notes</th></tr></thead><tbody>")
        for tid, meta, slug, p, hay, shown in group:
            flaky = (" <span class='note'>· flaky</span>"
                     if (p.get("result") or {}).get("flaky") else "")
            b.append(f"<tr data-row data-technique='{esc(tid)}' data-profile='{esc(slug)}' "
                     f"data-status='{esc(p['status'])}' data-category='{esc(c)}' "
                     f"data-search='{esc(hay)}'{'' if shown else ' hidden'}>"
                     f"<th scope='row'><a class='tname' href='/techniques/{esc(tid)}'>"
                     f"{esc(tid)}<small>{esc(meta.get('name'))}</small></a></th>"
                     f"<td class='note'>{esc(slug)}</td><td>{_pill(p['status'])}{flaky}</td>"
                     f"<td><span class='note'>{esc(p.get('reason', ''))}</span>"
                     f"{_evidence(p)}</td></tr>")
        b.append("</tbody></table></div></section>")
    b.append(f"<p class='empty' data-empty{' hidden' if flat else ''}>No verdict matches. "
             f"<a href='/reports/{_qp(rid)}'>Clear the filters</a>.</p></div>")
    return Page(f"report {rid}", "reports", "".join(b), data)


def diff(site, req):
    reports = site.reports.list()
    ids = [rid for rid, _ in reports]
    before, after = req.one("before"), req.one("after")
    if not after and ids:
        after = ids[0]
    if not before and len(ids) > 1:
        before = next((i for i in ids if i != after), "")
    errors = [f"unknown report '{x}'" for x in (before, after) if x and x not in ids]
    result = None
    if before in ids and after in ids and not errors:
        a, bb = dict(reports)[before], dict(reports)[after]
        regs, imps = scoring.diff_reports(a, bb)
        coverage = []
        for tid, t in bb["techniques"].items():
            if tid not in a["techniques"]:
                continue
            for slug, p in t["profiles"].items():
                was = a["techniques"][tid]["profiles"].get(slug, {}).get("status")
                if was and was != p["status"] and "SKIPPED" in (was, p["status"]):
                    coverage.append((slug, tid, was, p["status"]))
        pa, pb = set(a.get("scores", {})), set(bb.get("scores", {}))
        tup = lambda x: {"profile": x[0], "technique": x[1], "before": x[2], "after": x[3]}
        result = {"regressions": [tup(x) for x in regs],
                  "improvements": [tup(x) for x in imps],
                  "coverage_changes": [tup(x) for x in coverage],
                  "only_in_before": sorted(pa - pb), "only_in_after": sorted(pb - pa),
                  "exit_code": 1 if regs else 0}
    cmd = _cmd("diff", f"reports/{before or 'before/report.json'}",
               f"reports/{after or 'after/report.json'}")
    data = {"before": before or None, "after": after or None, "errors": errors,
            "reports": ids, "result": result, "command": cmd}

    b = [_head("diff", "did it get looser?",
               meta="a regression is anything that became escaped · coverage changes "
                    "(to or from skipped) are listed, never scored")]
    opts = lambda cur: "".join(f"<option value='{esc(i)}'{' selected' if i == cur else ''}>"
                               f"{esc(i)} · {esc(_when(dict(reports)[i].get('started')))}"
                               f"</option>" for i in ids)
    if len(ids) < 2:
        b.append(_empty("Diff needs two reports on disk. Measure the same profile twice "
                        "(before and after a config change).",
                        _cmd("run", "--profile", "docker-tight", "--out", "reports/later/")))
        return Page("diff", "diff", "".join(b), data)
    b.append("<form class='filters' method='get' action='/diff' aria-label='choose reports'>"
             f"<label class='field'><span>before</span><select name='before'>{opts(before)}"
             f"</select></label><label class='field'><span>after</span>"
             f"<select name='after'>{opts(after)}</select></label>"
             "<button class='btn primary' type='submit'>compare</button></form>")
    b += [f"<p class='error' role='alert'>{esc(e)}</p>" for e in errors]
    if result:
        n = len(result["regressions"])
        verdict = (f"{n} regression{'s' if n != 1 else ''}" if n else "no regressions")
        b.append(f"<div class='verdict {'bad' if n else 'ok'}' data-exit-code='{result['exit_code']}'>"
                 f"<span class='score {'s-hi' if n else 's-mid'}'>{esc(verdict)}</span>"
                 f"<span class='sub'>breakout diff exits {result['exit_code']} · "
                 f"{len(result['improvements'])} improved · "
                 f"{len(result['coverage_changes'])} coverage changes</span></div>")
        for key, title in (("regressions", "regressed"), ("improvements", "improved"),
                           ("coverage_changes", "coverage changed")):
            items = result[key]
            b.append(_h2(title, str(len(items))))
            if not items:
                b.append("<p class='note-l'>none</p>")
                continue
            b.append("<div class='scroll'><table><thead><tr><th scope='col'>technique</th>"
                     "<th scope='col'>profile</th><th scope='col'>before</th>"
                     "<th scope='col'>after</th></tr></thead><tbody>" + "".join(
                         f"<tr data-row data-kind='{key}' data-technique='{esc(x['technique'])}' "
                         f"data-profile='{esc(x['profile'])}'><th scope='row'>"
                         f"<a class='tname' href='/techniques/{esc(x['technique'])}'>"
                         f"{esc(x['technique'])}</a></th><td class='note'>{esc(x['profile'])}</td>"
                         f"<td>{_pill(x['before'], True)}</td><td>{_pill(x['after'], True)}</td></tr>"
                         for x in items) + "</tbody></table></div>")
        for key, label in (("only_in_before", "only in before"), ("only_in_after", "only in after")):
            if result[key]:
                b.append(f"<p class='note-l'>{label}: {esc(', '.join(result[key]))} "
                         f"(not compared)</p>")
    b.append(_h2("in ci"))
    b.append(_cmd_block(cmd, "same comparison as a gate: exit 1 on any regression"))
    return Page("diff", "diff", "".join(b), data)


def build_run(site, req, default_profiles=True):
    """Validate run parameters and build the `breakout run` argv. Single source of
    truth for both /compose (shows the command) and POST /api/runs (executes it),
    so the two can never disagree on what a given request means."""
    profiles = site.profiles()
    slugs = [p.slug for p in profiles]
    techs = site.techniques()
    tids = {t.id for t in techs}
    fresh = default_profiles and not [k for k in req.query if k != "format"]
    sel_p = ["docker-loose", "docker-tight"] if fresh else req.many("profile")
    sel_c = req.many("category")
    only = req.many("only")
    repeat, timeout = req.one("repeat", "1"), req.one("timeout", "20")
    baseline, out = req.one("baseline", "auto"), req.one("out", "reports/") or "reports/"
    errors = []
    if not sel_p:
        errors.append("choose at least one profile")
    for p in sel_p:
        if p not in slugs and not p.endswith(".toml"):
            errors.append(f"unknown profile '{p}'; builtin: {', '.join(slugs)}")
    for c in sel_c:
        if c not in corpus.CATEGORIES:
            errors.append(f"unknown category '{c}'; valid: {', '.join(corpus.CATEGORIES)}")
    for t in only:
        if t not in tids:
            errors.append(f"unknown technique id '{t}'")
    for name, val, lo in (("repeat", repeat, 1), ("timeout", timeout, 1)):
        if not re.fullmatch(r"\d{1,4}", val or "") or int(val) < lo:
            errors.append(f"{name} must be an integer >= {lo}")
    if baseline not in BASELINES:
        errors.append(f"baseline must be one of {', '.join(BASELINES)}")
    if re.search(r"[\x00-\x1f]", out):
        errors.append("out must be a plain path")

    def argv_with(out_value, cli=None):
        a = [*(cli or CLI), "run"]
        for p in sel_p:
            a += ["--profile", p]
        if sel_c:
            a += ["--categories", ",".join(sel_c)]
        if only:
            a += ["--only", ",".join(only)]
        if repeat not in ("", "1"):
            a += ["--repeat", repeat]
        if timeout not in ("", "20"):
            a += ["--timeout", timeout]
        if baseline != "auto":
            a += ["--baseline", baseline]
        return a + ["--out", out_value]

    argv = argv_with(out)
    ok = not errors
    doc = site.doctor()
    unavailable = {p: doc["profiles"][p]["reason"] for p in sel_p
                   if p in doc["profiles"] and not doc["profiles"][p]["available"]}
    report = out.rstrip("/") + "/report.json"
    return {"valid": ok, "errors": errors, "argv": argv if ok else None,
            "command": shlex.join(argv) if ok else None,
            "then": [_cmd("score", report), _cmd("serve", "--reports", out)] if ok else [],
            "unavailable_here": unavailable,
            "external_traffic": (not sel_c or "net" in sel_c) and not only,
            "selection": {"profiles": sel_p, "categories": sel_c, "only": only,
                          "repeat": repeat, "timeout": timeout, "baseline": baseline,
                          "out": out},
            "_argv_with": argv_with,
            "note": "the frontend never executes probes unless started with "
                    "--allow-runs on a loopback bind; otherwise run the command "
                    "yourself, on a system you own or are authorized to test"}


def compose(site, req):
    profiles = site.profiles()
    techs = site.techniques()
    plan = build_run(site, req)
    sel = plan["selection"]
    sel_p, sel_c, only = sel["profiles"], sel["categories"], sel["only"]
    repeat, timeout, baseline, out = (sel["repeat"], sel["timeout"], sel["baseline"],
                                      sel["out"])
    errors, ok, unavailable = plan["errors"], plan["valid"], plan["unavailable_here"]
    doc = site.doctor()
    runs_on = site.runs.enabled
    data = {k: v for k, v in plan.items() if not k.startswith("_") and k != "selection"}
    data["runnable_here"] = runs_on

    datalist = "".join(f"<option value='{esc(t.id)}'>" for t in techs)
    b = [_head("compose", "write the run",
               meta="pick the cages and the classes · this page never executes a probe · "
                    "it writes the command, you run it")]
    b.append("<form class='compose' method='get' action='/compose' data-compose "
             "aria-label='compose a run'>")
    b.append("<fieldset class='checks'><legend>profiles</legend>" + "".join(
        f"<label class='check'><input type='checkbox' name='profile' value='{esc(p.slug)}'"
        f"{' checked' if p.slug in sel_p else ''}><span>{esc(p.slug)}"
        f"<small>{esc(p.kind)}{'' if doc['profiles'][p.slug]['available'] else ' · unavailable here'}"
        f"</small></span></label>" for p in profiles) + "</fieldset>")
    b.append("<fieldset class='checks'><legend>classes <small>(none = all)</small></legend>"
             + "".join(f"<label class='check'><input type='checkbox' name='category' "
                       f"value='{c}'{' checked' if c in sel_c else ''}><span>{c}</span></label>"
                       for c in corpus.CATEGORIES) + "</fieldset>")
    b.append("<div class='row'>"
             f"<label class='field grow'><span>only these technique ids</span>"
             f"<input type='text' name='only' value='{esc(','.join(only))}' "
             f"placeholder='net-literal-ip,fs-dev-write' list='tids' autocomplete='off' "
             f"spellcheck='false'></label>"
             f"<datalist id='tids'>{datalist}</datalist>"
             f"<label class='field'><span>repeat</span><input type='number' name='repeat' "
             f"min='1' max='99' value='{esc(repeat)}'></label>"
             f"<label class='field'><span>timeout s</span><input type='number' name='timeout' "
             f"min='1' max='600' value='{esc(timeout)}'></label>"
             "<label class='field'><span>baseline</span><select name='baseline'>"
             + "".join(f"<option{' selected' if x == baseline else ''}>{x}</option>"
                       for x in BASELINES)
             + "</select></label>"
             f"<label class='field'><span>out</span><input type='text' name='out' "
             f"value='{esc(out)}' spellcheck='false'></label></div>"
             "<button class='btn primary nojs-only' type='submit'>write command</button>"
             "</form>")
    b.append("<div data-compose-out aria-live='polite'>")
    b.append(_h2("command"))
    b.append(f"<ul class='errors' data-compose-errors{'' if errors else ' hidden'}>"
             + "".join(f"<li>{esc(e)}</li>" for e in errors) + "</ul>")
    b.append(f"<div data-compose-ok{'' if ok else ' hidden'}>"
             + _cmd_block(data["command"] or "", "measure") + "".join(
                 _cmd_block(c, n) for c, n in zip(data["then"] or ["", ""],
                                                  ("read the scorecard", "browse it here")))
             + "</div>")
    b.append(f"<p class='note-l' data-compose-unavailable{'' if unavailable else ' hidden'}>"
             + "".join(f"{esc(k)}: {esc(v)}. " for k, v in unavailable.items())
             + "Unavailable profiles are reported SKIPPED with this reason.</p>")
    b.append(f"<p class='note-l' data-compose-net{'' if data['external_traffic'] else ' hidden'}>"
             "The net class makes constant, data-free lookups to public resolvers; on a "
             "monitored network they look like DNS/ICMP tunneling. Pick fs, proc, ipc "
             "to stay local.</p></div>")
    if runs_on:
        b.append(_h2("run on this host", "<a href='/runs'>run history →</a>"))
        b.append("<p class='prose'>This server was started with <code>--allow-runs</code> "
                 "on a loopback bind, so it can execute the composed command here and "
                 "write the report into the served directory. Only the validated "
                 "parameters above are run, never a free-form command.</p>"
                 "<button class='btn primary' type='button' data-run"
                 f"{'' if ok else ' disabled'}>run here</button>"
                 "<div data-run-out aria-live='polite'></div>")
    else:
        b.append(_h2("run on this host"))
        b.append("<p class='prose'>This server is read-only: it composes the command and "
                 "never executes a probe. To run here, start it with "
                 "<code>breakout serve --allow-runs</code> on a loopback bind "
                 "(<code>--host 127.0.0.1</code>); it refuses <code>--allow-runs</code> on "
                 "any other interface.</p>")
    return Page("compose", "compose", "".join(b), data)


_RUN_STATUS_PILL = {"queued": "SKIPPED", "running": "CONTAINED", "done": "CONTAINED",
                    "failed": "ESCAPED", "error": "ESCAPED"}


def submit_run(site, req):
    """Validate and enqueue a run. Returns (data, status). Used by POST /api/runs."""
    if not site.runs.enabled:
        return ({"error": "runs are disabled: start with `breakout serve --allow-runs` "
                          "on a loopback bind (--host 127.0.0.1)", "status": 403}, 403)
    plan = build_run(site, req, default_profiles=False)
    if not plan["valid"]:
        return ({"error": "invalid run parameters", "errors": plan["errors"],
                 "status": 400}, 400)
    rec, err = site.runs.submit(plan)
    if err:
        return ({"error": err, "status": 409}, 409)
    rec["url"] = f"/runs/{rec['id']}"
    rec["api"] = f"/api/runs/{rec['id']}"
    return (rec, 202)


def runs_page(site, req):
    runs = site.runs.list()
    data = {"enabled": site.runs.enabled, "count": len(runs), "runs": runs,
            "submit": {"method": "POST", "path": "/api/runs",
                       "body": "same parameters as /compose (profile, category, only, "
                               "repeat, timeout, baseline), as form or JSON"},
            "note": "runs execute `breakout run` on this host, one at a time, from the "
                    "validated parameters only; output lands under the served reports "
                    "directory"}
    b = [_head("runs", "run on this host",
               meta=("enabled · loopback only · one at a time" if site.runs.enabled
                     else "disabled · read-only server"))]
    if not site.runs.enabled:
        b.append("<p class='prose'>This server is read-only. Start it with "
                 "<code>breakout serve --allow-runs</code> on a loopback bind to execute "
                 "runs from <a href='/compose'>compose</a>. It refuses "
                 "<code>--allow-runs</code> on any non-loopback interface, so a shared "
                 "or preview deployment can never run probes.</p>")
        return Page("runs", "runs", "".join(b), data)
    b.append("<p class='prose'>Compose a run and press <b>run here</b>, or POST the same "
             "parameters to <code>/api/runs</code>. Each run executes "
             "<code>breakout run</code> from the validated parameters only and writes "
             "its report under the served directory, where it appears in "
             "<a href='/reports'>reports</a>.</p>")
    b.append(_h2("history", f"{len(runs)} runs"))
    if not runs:
        b.append(_empty("No run yet. <a href='/compose'>Compose one</a> and run it here."))
        return Page("runs", "runs", "".join(b), data)
    b.append("<div class='scroll'><table><thead><tr><th scope='col'>run</th>"
             "<th scope='col'>status</th><th scope='col'>command</th>"
             "<th scope='col'>report</th><th scope='col'>started</th></tr></thead><tbody>")
    for r in runs:
        rep = (f"<a href='/reports/{_qp(r['report'])}'>report</a>"
               if r["status"] == "done" else "<span class='note'>—</span>")
        b.append(f"<tr data-row data-run='{esc(r['id'])}' data-status='{esc(r['status'])}'>"
                 f"<th scope='row'><a class='tname' href='/runs/{esc(r['id'])}'>"
                 f"{esc(r['id'])}</a></th>"
                 f"<td>{_pill(_RUN_STATUS_PILL.get(r['status'], 'SKIPPED'), True)} "
                 f"<span class='note'>{esc(r['status'])}</span></td>"
                 f"<td class='note'><code>{esc(r['command'])}</code></td>"
                 f"<td>{rep}</td><td class='note'>{esc(_when(r['started']))}</td></tr>")
    b.append("</tbody></table></div>")
    return Page("runs", "runs", "".join(b), data)


def run_detail(site, req, rid):
    rec = site.runs.get(rid)
    if rec is None:
        raise NotFound(f"no run '{rid}'")
    rec["url"] = f"/runs/{rid}"
    rec["report_url"] = (f"/reports/{rec['report']}" if rec["status"] == "done" else None)
    b = [_crumbs(("runs", "/runs"), (rid, None)),
         _head("run", esc(rid), plain=True, rings=False,
               meta=f"{esc(rec['status'])} · exit {esc(rec['exit_code'])} · "
                    f"started {esc(_when(rec['started']))}"),
         _facts([("status", f"{_pill(_RUN_STATUS_PILL.get(rec['status'], 'SKIPPED'), True)} "
                            f"{esc(rec['status'])}"),
                 ("command", f"<code>{esc(rec['command'])}</code>"),
                 ("out", esc(rec["out"])),
                 ("report", f"<a href='/reports/{_qp(rec['report'])}'>{esc(rec['report'])}</a>"
                  if rec["status"] == "done" else "written when the run finishes"),
                 ("exit code", esc(rec["exit_code"]))])]
    if rec["error"]:
        b.append(f"<p class='error' role='alert'>{esc(rec['error'])}</p>")
    b.append(_h2("output", "tail"))
    b.append(f"<pre class='src' data-run-log>{esc(rec['log'] or '(no output yet)')}</pre>")
    if rec["status"] in ("queued", "running"):
        b.append("<p class='note-l' data-run-poll>Running. Reload for the latest output, "
                 "or watch it from <a href='/runs'>run history</a>.</p>")
    return Page(f"run {rid}", "runs", "".join(b), rec)


def doctor_page(site, req):
    doc = site.doctor()
    b = [_crumbs(("profiles", "/profiles"), ("doctor", None)),
         _head("doctor", "this host", meta=f"{esc(doc['platform'])} · python "
                                           f"{esc(doc['python'])}"),
         _facts([("os", esc(doc["os"])),
                 ("docker", ("ok · " + esc(doc["docker"]["detail"])) if doc["docker"]["available"]
                  else "unavailable · " + esc(doc["docker"]["detail"])),
                 ("bwrap", "ok" if doc["bwrap"]["available"] else "not found"),
                 ("cc", "ok (landlock helper)" if doc["cc"]["available"] else "not found")]),
         _h2("builtin profiles"),
         "<div class='scroll'><table><thead><tr><th scope='col'>profile</th>"
         "<th scope='col'>kind</th><th scope='col'>here</th></tr></thead><tbody>"
         + "".join(f"<tr data-row data-profile='{esc(s)}' "
                   f"data-available='{str(v['available']).lower()}'><th scope='row'>"
                   f"<a class='tname' href='/profiles/{esc(s)}'>{esc(s)}</a></th>"
                   f"<td class='note'>{esc(v['kind'])}</td><td>"
                   + ("<span class='pill CONTAINED sm'>runs</span>" if v["available"]
                      else f"<span class='note'>{esc(v['reason'])}</span>") + "</td></tr>"
                   for s, v in doc["profiles"].items())
         + "</tbody></table></div>",
         f"<p class='note-l'>{esc(doc['note'])}</p>", _cmd_block(_cmd("doctor"))]
    return Page("doctor", "profiles", "".join(b), doc)


def agents(site, req):
    data = api_index(site, req)
    rows = "".join(
        f"<tr><th scope='row' class='tname'>{esc(p)}</th><td class='desc'>{esc(d)}"
        + ("".join(f"<small class='block note'><b>{esc(k)}</b> {esc(v)}</small>"
                   for k, v in params.items()))
        + f"</td><td class='note'>{esc(api_path(p))}</td></tr>"
        for p, d, params in ENDPOINTS)
    b = [_head("agents", "same facts, as data",
               meta="read-only · no auth · no javascript required · stable urls"),
         "<p class='prose'>This frontend is built to be read by people and by agents "
         "with the same fidelity. Nothing on a page exists only as pixels: every number "
         "a person sees is a field an agent can fetch.</p>",
         _h2("three ways to get json"),
         _facts([("accept", "<code>Accept: application/json</code> on any page URL"),
                 ("query", "<code>?format=json</code> on any page URL"),
                 ("prefix", "<code>/api</code> + the page path, e.g. "
                            "<a href='/api/techniques?category=net'>/api/techniques?category=net</a>")]),
         _h2("endpoints", f"<a href='/openapi.json'>openapi.json</a> · "
                          f"<a href='/llms.txt'>llms.txt</a>"),
         "<div class='scroll'><table><thead><tr><th scope='col'>page</th>"
         "<th scope='col'>what · params</th><th scope='col'>json</th></tr></thead>"
         f"<tbody>{rows}</tbody></table></div>",
         _h2("dom hooks", "for agents that drive a browser"),
         _facts([("data-page", "on <code>&lt;main&gt;</code>: the page key"),
                 ("data-row", "every data row; filters toggle the <code>hidden</code> "
                              "attribute, never remove nodes"),
                 ("data-technique · data-profile · data-category",
                  "identity of the row, matching the JSON ids"),
                 ("data-status", "ESCAPED, CONTAINED or SKIPPED on every verdict"),
                 ("data-exit-code", "on the diff verdict: what <code>breakout diff</code> "
                                    "would exit with"),
                 ("forms", "every filter is a plain GET form: build the URL instead of "
                           "clicking")]),
         _h2("a loop that works"),
         "<ol class='steps'>"
         "<li><b>check</b><span>GET <a href='/api/doctor'>/api/doctor</a>: which profiles "
         "can run here.</span></li>"
         "<li><b>compose</b><span>GET <code>/api/compose?profile=docker-tight&amp;category=fs</code>: "
         "validated <code>argv</code>, no shell quoting to get wrong.</span></li>"
         "<li><b>run</b><span>Execute the argv yourself, only on a system you own or are "
         "authorized to test. Or, when this server runs with <code>--allow-runs</code> on "
         "a loopback bind, POST the same parameters to <a href='/api/runs'>/api/runs</a> "
         "and poll <code>/api/runs/&lt;id&gt;</code>. Without that flag POST is refused: "
         "the server only composes.</span></li>"
         "<li><b>read</b><span>GET <code>/api/reports/&lt;path&gt;?status=ESCAPED</code>: "
         "what got out, as flat rows.</span></li>"
         "<li><b>gate</b><span>GET <code>/api/diff?before=…&amp;after=…</code> or run "
         "<code>breakout diff</code>: exit 1 means it got looser.</span></li></ol>",
         _h2("ground rules"),
         "<ul class='refs'><li>A high score is a measurement on one machine, one "
         "configuration, one kernel. Never report it as a certification.</li>"
         "<li>Skipped techniques did not apply here. They are neither good nor bad "
         "news.</li><li>Report evidence is redacted (decoy secret, host decoy path) "
         "before it is written; keep it that way when you quote it.</li></ul>"]
    return Page("agents", "agents", "".join(b), data)


def api_index(site, req):
    return {"name": "undecidable-breakout", "version": __version__, "read_only": True,
            "negotiation": {"accept": "application/json", "query": "format=json",
                            "prefix": "/api"},
            "endpoints": [{"page": p, "json": api_path(p),
                           "description": d, "params": params}
                          for p, d, params in ENDPOINTS],
            "docs": {"agents": "/agents", "llms_txt": "/llms.txt",
                     "openapi": "/openapi.json"},
            "files": "/files/<path> serves report artifacts under the reports directory"}


def llms_txt(site):
    techs = site.techniques()
    lines = ["# undecidable-breakout", "",
             f"> {TAGLINE} A conformance suite that runs a fixed corpus of "
             f"{len(techs)} documented sandbox-escape techniques from inside a containment "
             "configuration and reports, per technique, ESCAPED / CONTAINED / SKIPPED.", "",
             "This server is a read-only frontend over the corpus, the builtin profiles "
             "and the reports on disk. Every HTML page has a JSON twin: send "
             "`Accept: application/json`, add `?format=json`, or prefix the path with "
             "`/api`. By default it executes nothing; /compose returns a validated argv to "
             "run yourself, only on systems you own or are authorized to test. When "
             "started with `--allow-runs` on a loopback bind it also accepts POST "
             "/api/runs (the same parameters as /compose) and runs them here, one at a "
             "time; otherwise POST is refused.", "",
             f"A high score is not a certification: {_DISCLAIMER}", "", "## Pages", ""]
    for p, d, params in ENDPOINTS:
        ps = f" Params: {'; '.join(f'{k} ({v})' for k, v in params.items())}." if params else ""
        lines.append(f"- [{p}]({api_path(p)}): {d}{ps}")
    lines += ["", "## Reference", "",
              "- [/agents](/agents): the agent interface, DOM hooks, a working loop",
              "- [/openapi.json](/openapi.json): OpenAPI 3.1 description of the JSON endpoints",
              "", "## Verdicts", ""]
    lines += [f"- {s}: {VERDICTS[s]}" for s in STATUSES]
    lines += ["", "## Optional", "",
              "- [/api/techniques](/api/techniques): the full corpus with preconditions"]
    return "\n".join(lines) + "\n"


def openapi(site):
    paths = {}
    paths["/api"] = {"get": {"summary": "Endpoint index (this list, as data).",
                             "responses": {"200": {"description": "JSON"}}}}
    for p, d, params in ENDPOINTS:
        api = "/api" + p if p != "/" else "/"
        prm = [{"name": k, "in": "query", "required": False,
                "description": v, "schema": {"type": "string"}} for k, v in params.items()]
        if p == "/":
            prm.append({"name": "format", "in": "query", "required": True,
                        "schema": {"type": "string", "enum": ["json"]}})
        for var in re.findall(r"{(\w+)}", api):
            prm.append({"name": var, "in": "path", "required": True,
                        "schema": {"type": "string"}})
        paths[api] = {"get": {"summary": d, "parameters": prm,
                              "responses": {"200": {"description": "JSON",
                                                    "content": {"application/json": {
                                                        "schema": {"type": "object"}}}},
                                            "404": {"description": "not found"}}}}
    run_params = {k: v for p, _, params in ENDPOINTS if p == "/compose"
                  for k, v in params.items() if k != "out"}
    paths["/api/runs"]["post"] = {
        "summary": "Queue a `breakout run` on this host (only when the server was "
                   "started with --allow-runs on a loopback bind; else 403).",
        "requestBody": {"required": True, "content": {
            "application/json": {"schema": {"type": "object", "properties": {
                k: {"type": "string", "description": v} for k, v in run_params.items()}}},
            "application/x-www-form-urlencoded": {"schema": {"type": "object"}}}},
        "responses": {"202": {"description": "run queued"},
                      "400": {"description": "invalid parameters"},
                      "403": {"description": "runs disabled or non-loopback caller"},
                      "409": {"description": "too many runs pending"}}}
    return {"openapi": "3.1.0",
            "info": {"title": "undecidable-breakout frontend", "version": __version__,
                     "description": "Read-only JSON twin of every page. " + TAGLINE},
            "paths": paths}


def not_found(message):
    b = [_head("404", "nothing here",
               meta="the path is wrong, or the thing it names is not on disk"),
         f"<p class='prose'>{esc(message)}</p>",
         "<p class='prose'><a href='/'>overview</a> · <a href='/techniques'>corpus</a> · "
         "<a href='/reports'>reports</a> · <a href='/api'>/api</a></p>"]
    return Page("not found", "", "".join(b),
                {"error": message, "status": 404, "hint": "GET /api lists every endpoint"},
                status=404)


ROUTES = (
    (re.compile(r"/"), overview),
    (re.compile(r"/leaderboard"), leaderboard),
    (re.compile(r"/techniques"), techniques_index),
    (re.compile(r"/techniques/(?P<tid>[a-z0-9][a-z0-9-]{0,80})"), technique_detail),
    (re.compile(r"/profiles"), profiles_index),
    (re.compile(r"/profiles/(?P<slug>[a-z0-9][a-z0-9-]{0,80})"), profile_detail),
    (re.compile(r"/reports"), reports_index),
    (re.compile(r"/reports/(?P<rid>[^\x00]{1,512}\.json)"), report_detail),
    (re.compile(r"/diff"), diff),
    (re.compile(r"/compose"), compose),
    (re.compile(r"/doctor"), doctor_page),
    (re.compile(r"/runs"), runs_page),
    (re.compile(r"/runs/(?P<rid>[0-9A-Za-z._-]{1,64})"), run_detail),
    (re.compile(r"/agents"), agents),
)


def route(site, path, query):
    req = Req(path=path, query=query)
    for rx, fn in ROUTES:
        m = rx.fullmatch(path.rstrip("/") or "/")
        if m:
            try:
                return fn(site, req, **m.groupdict())
            except NotFound as e:
                return not_found(str(e))
    return not_found(f"no page at {path}")


def layout(page, path, query_string, show_runs=False):
    items = list(NAV)
    if show_runs:
        items.insert(len(items) - 1, NAV_RUNS)  # before "agents"
    cur = " aria-current='page'"
    nav = "".join(f"<li><a href='{h}'{cur if page.nav == k else ''}>{k}</a></li>"
                  for k, h in items)
    sep = "&" if query_string else ""
    json_href = f"{path}?{query_string}{sep}format=json"
    desc = page.description or TAGLINE
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='color-scheme' content='dark'><meta name='theme-color' content='#050505'>"
        f"<title>{esc(page.title)} · undecidable-breakout</title>"
        f"<meta name='description' content='{esc(desc)}'>"
        "<link rel='icon' href='/assets/mark.svg' type='image/svg+xml'>"
        "<link rel='preload' href='/assets/archivo.woff2' as='font' type='font/woff2' crossorigin>"
        "<link rel='stylesheet' href='/assets/app.css'>"
        f"<link rel='alternate' type='application/json' href='{esc(json_href)}'>"
        "<link rel='help' type='text/plain' href='/llms.txt'>"
        "<script src='/assets/app.js' defer></script></head><body>"
        "<a class='skip' href='#main'>skip to content</a>"
        "<header class='bar'><a class='brand' href='/' aria-label='undecidable-breakout, overview'>"
        "<svg viewBox='0 0 500 500' aria-hidden='true'><path fill='#838383' d='M40 20 H190 V290 "
        "A55 55 0 0 0 310 290 V20 H460 V320 A160 160 0 0 1 40 320 Z'/><rect fill='#050505' "
        "x='16' y='210' width='468' height='30'/></svg>"
        "<span class='u'>undecidable&#8209;breakout</span></a>"
        f"<nav class='nav' aria-label='primary'><ul>{nav}</ul></nav>"
        f"<a class='alt' href='{esc(json_href)}' type='application/json' "
        f"aria-label='this page as JSON'>json</a></header>"
        f"<main id='main' class='wrap' data-page='{esc(page.nav or 'error')}'>{page.body}</main>"
        "<footer class='wrap foot'>undecidable&#8209;breakout · every verdict is reproducible: "
        "same corpus, same profile, same kernel · skipped never counts against a score · "
        "<a href='/agents'>agents</a> · <a href='/llms.txt'>llms.txt</a></footer>"
        "</body></html>")
