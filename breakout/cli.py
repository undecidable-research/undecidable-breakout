"""CLI: run, list, score, diff, leaderboard, verify."""
import argparse
import json
import secrets
import sys
import urllib.request
from pathlib import Path

from . import __version__, corpus, reporting, runner, scoring
from .canary import Canary
from .sandboxes import builtin_dir, find_profile, load_profile


def _load_corpus(techniques_dir):
    return corpus.load_dir(techniques_dir or corpus.default_dir())


def _bar(score, width=20):
    if score is None:
        return "-" * width
    filled = round(width * score / 100)
    return "#" * filled + "." * (width - filled)


def cmd_run(args):
    techs = _load_corpus(args.techniques_dir)
    cats = [c for c in args.categories.split(",") if c] or None
    if cats:
        bad = [c for c in cats if c not in corpus.CATEGORIES]
        if bad:
            sys.exit(f"unknown categories: {', '.join(bad)}. Valid: {', '.join(corpus.CATEGORIES)}")
    profiles = [find_profile(slug) for slug in args.profile]
    report = runner.run(profiles, techs, categories=cats, out_dir=args.out,
                        timeout=args.timeout, baseline_mode=args.baseline)
    print()
    for slug, scores in report["scores"].items():
        o = scores["overall"]
        pct = " n/a" if o["score"] is None else f"{o['score']:>3}%"
        print(f"  {slug:<22} {_bar(o['score'])} {pct}   "
              f"{o['contained']:>2} contained / {o['escaped']:>2} escaped / "
              f"{o['skipped']:>2} skipped")
    print(f"\n  reports -> {Path(args.out).resolve()} "
          f"(report.json, report.html, report.sarif)")


def cmd_list(args):
    techs = _load_corpus(args.techniques_dir)
    print(f"techniques ({len(techs)}):")
    for t in techs:
        print(f"  {t.category:<9} {t.id:<32} {t.name}")
    print("profiles:")
    for f in sorted(builtin_dir().glob("*.toml")):
        p = load_profile(f)
        print(f"  {p.slug:<24} {p.kind:<8} {p.name}")


def cmd_score(args):
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    for slug, scores in report.get("scores", {}).items():
        print(f"\n{slug}")
        for cat, s in scores.items():
            score = "n/a" if s["score"] is None else f"{s['score']}%"
            print(f"  {cat:<10} {score:>5}  (C {s['contained']} / E {s['escaped']} / K {s['skipped']})")


def cmd_diff(args):
    a = json.loads(Path(args.before).read_text(encoding="utf-8"))
    b = json.loads(Path(args.after).read_text(encoding="utf-8"))
    regs, imps = scoring.diff_reports(a, b)
    for slug, tid, sa, sb in imps:
        print(f"improved   {slug:<20} {tid:<32} {sa} -> {sb}")
    for slug, tid, sa, sb in regs:
        print(f"REGRESSED  {slug:<20} {tid:<32} {sa} -> {sb}")
    if not regs and not imps:
        print("no changes")
    sys.exit(1 if regs else 0)


def cmd_leaderboard(args):
    data = reporting.leaderboard(args.reports, args.out,
                                 args.out.replace(".html", ".json") if args.out.endswith(".html") else None)
    print(f"leaderboard: {Path(args.out).resolve()} ({len(data['rows'])} rows)")


def cmd_verify(args):
    techs = _load_corpus(args.techniques_dir)
    assert techs and all(t.oracle in ("stdout", "canary") for t in techs), "corpus broken"
    canary = Canary()
    canary.start()
    nonce = secrets.token_hex(8)
    with urllib.request.urlopen(
            f"http://127.0.0.1:{canary.port}/hit/selfcheck/{nonce}", timeout=5) as r:
        assert r.read() == b"breakout-canary"
    assert canary.saw("selfcheck", nonce), "canary did not record the hit"
    canary.stop()
    decoy = runner.write_decoys(secrets.token_hex(8))
    assert (decoy / "credentials.env").read_text().startswith("# breakout decoy")
    n = 0
    for f in sorted(builtin_dir().glob("*.toml")):
        load_profile(f)
        n += 1
    print(f"verify OK: {len(techs)} techniques, {n} profiles, canary port {canary.port}, "
          f"ipv6={canary.info()['ipv6']}, decoys in {decoy}")


def cmd_selftest(args):
    from . import selftest
    sys.exit(0 if selftest.run(out_dir=args.out, timeout=args.timeout) else 1)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="breakout",
        description="You can't prove the cage holds. You can prove it doesn't.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="run the corpus against one or more profiles")
    p.add_argument("--profile", action="append", required=True,
                   help="profile slug or path (repeatable)")
    p.add_argument("--categories", default="", help="comma-separated: net,fs,proc,ipc,integrity")
    p.add_argument("--out", default="reports")
    p.add_argument("--timeout", type=int, default=20, help="per-probe timeout seconds")
    p.add_argument("--techniques-dir")
    p.add_argument("--baseline", choices=("auto", "host", "docker"), default="auto",
                   help="where the outside-sandbox control runs (auto: host on POSIX, "
                        "docker on Windows)")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("list", help="list techniques and profiles")
    p.add_argument("--techniques-dir")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("score", help="print the scorecard of a saved report")
    p.add_argument("report")
    p.set_defaults(fn=cmd_score)

    p = sub.add_parser("diff", help="compare two reports; exit 1 on regressions")
    p.add_argument("before")
    p.add_argument("after")
    p.set_defaults(fn=cmd_diff)

    p = sub.add_parser("leaderboard", help="build the leaderboard page from reports")
    p.add_argument("reports", nargs="+")
    p.add_argument("--out", default="docs/leaderboard/index.html")
    p.set_defaults(fn=cmd_leaderboard)

    p = sub.add_parser("verify", help="self-check: corpus, canary roundtrip, decoys, profiles")
    p.add_argument("--techniques-dir")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("selftest",
                       help="ground-truth accuracy check: profiles with known outcomes, "
                            "every verdict must match (needs docker)")
    p.add_argument("--out", default="reports/selftest")
    p.add_argument("--timeout", type=int, default=20)
    p.set_defaults(fn=cmd_selftest)

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
