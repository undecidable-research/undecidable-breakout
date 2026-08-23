"""Reports: JSON, self-contained HTML, SARIF 2.1.0, and the leaderboard page.

Palette discipline: five values only (--field, --ink, --ink-hi, --dim, --rule).
No accents, no white, no gradients. Ink at four opacities is the only variance,
so geometry and text are the same material. One font: Archivo Variable,
self-hosted, subset latin, embedded as base64 (niente mono, mai).
"""
import base64
import html
import json
from pathlib import Path

_FONT_B64 = None


def _font():
    global _FONT_B64
    if _FONT_B64 is None:
        f = Path(__file__).with_name("archivo-latin-wght-normal.woff2")
        _FONT_B64 = base64.b64encode(f.read_bytes()).decode() if f.exists() else ""
    return _FONT_B64


_CSS = """
:root{
--field:#050505;--ink:#838383;--ink-hi:#8a8a8a;--dim:#484848;--rule:#2e2e2e;
--display:clamp(2.25rem,min(8.2vw,13.5vh),6.75rem);
--display-2:clamp(1.375rem,min(4.4vw,6.2vh),3.25rem);
--body:clamp(1.125rem,min(2vw,2.9vh),1.625rem);
--micro:0.6875rem;
--edge:clamp(1rem,3.2vw,2.5rem);--gutter:clamp(1.5rem,4vw,3rem);
--chrome:calc(var(--edge) + var(--gutter) + 3.5rem);
--ease:cubic-bezier(0.2,0,0,1);--t-hover:90ms;--t-enter:220ms;--t-nav:320ms}
*{box-sizing:border-box;font-synthesis-weight:none}
html{background:var(--field)}
body{margin:0;background:var(--field);color:var(--ink-hi);
font-family:'Archivo Variable',Archivo,system-ui,sans-serif;font-weight:500;
font-size:var(--body);line-height:1.5;padding-top:var(--chrome);
-webkit-font-smoothing:antialiased}
a{color:var(--ink-hi);text-decoration:none;border-bottom:1px solid var(--rule)}
a:hover{border-bottom-color:var(--ink);transition:border-color var(--t-hover) var(--ease)}
/* fixed micro chrome */
.bar{position:fixed;top:0;left:0;right:0;z-index:10;display:flex;justify-content:space-between;
align-items:baseline;padding:var(--edge) var(--gutter);background:var(--field);
border-bottom:1px solid var(--rule)}
.bar .u{font-weight:600;letter-spacing:.14em;text-transform:uppercase;
font-size:var(--micro);color:var(--ink)}
.bar .where{font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
.wrap{max-width:64rem;margin:0 auto;padding:var(--gutter) var(--gutter) calc(var(--gutter)*2)}
h1{font-size:var(--display-2);font-weight:800;line-height:.94;letter-spacing:-.035em;
text-transform:uppercase;color:var(--ink);margin:0}
.kicker{font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;
color:var(--dim);margin:0 0 .9rem}
.meta{color:var(--dim);font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;
margin:.9rem 0 0;line-height:2}
.warn{border-left:2px solid var(--ink);padding:.2rem 0 .2rem var(--gutter);margin:2.2rem 0;
max-width:60ch}
.warn b{display:block;font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;
color:var(--ink);font-weight:600;margin-bottom:.35rem}
.warn span{color:var(--ink);font-size:var(--body);max-width:34ch;display:block}
/* header with the rings: geometry in ink at four opacities, never resolving */
.head{position:relative}
.rings{position:absolute;right:calc(var(--edge)*-1);top:-4rem;width:min(46vw,15rem);
aspect-ratio:1;pointer-events:none}
.rings g{transform-box:fill-box;transform-origin:center}
.r1{animation:spin 61s linear infinite}
.r2{animation:spin 97s linear infinite reverse}
.r3{animation:spin 149s linear infinite}
.r4{animation:spin 223s linear infinite reverse}
@keyframes spin{to{transform:rotate(360deg)}}
/* score cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));
gap:1px;background:var(--rule);border:1px solid var(--rule);margin:2.6rem 0}
.card{background:var(--field);padding:var(--gutter) var(--gutter) calc(var(--gutter)*.8)}
.card .slug{font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;
color:var(--ink);font-weight:600}
.card .score{font-size:var(--display);font-weight:800;line-height:.94;
letter-spacing:-.035em;margin:.35rem 0 .3rem;opacity:1;animation:enter var(--t-enter) var(--ease)}
.card .score.s-hi{color:var(--ink-hi)}.card .score.s-mid{color:var(--ink)}
.card .score.s-lo{color:var(--dim)}
.card .sub{font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
@keyframes enter{from{opacity:0}to{opacity:1}}
/* tables */
h2{margin:3.2rem 0 0}
.cat{display:inline-block;font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;
font-weight:600;color:var(--ink);border:1px solid var(--rule);padding:.45rem .8rem}
.count{font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
table{border-collapse:collapse;width:100%;margin:.7rem 0 0;font-size:1rem}
th{font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;color:var(--dim);
font-weight:600;text-align:left;padding:.7rem .75rem .5rem;border-bottom:1px solid var(--rule)}
td{padding:.75rem;border-bottom:1px solid var(--rule);vertical-align:top;text-align:left}
tr:hover td{background:color-mix(in srgb,var(--ink) 5%,transparent);
transition:background var(--t-hover) var(--ease)}
.tname{font-weight:600;color:var(--ink-hi)}
.tname small{display:block;font-weight:500;color:var(--dim);font-size:var(--micro);
letter-spacing:.02em;margin-top:.2rem;text-transform:none}
/* statuses: grayscale only — the loudest thing on the page is the lightest */
.pill{display:inline-block;font-size:var(--micro);letter-spacing:.14em;
text-transform:uppercase;font-weight:600;padding:.28rem .65rem;white-space:nowrap}
.pill.ESCAPED{background:var(--ink-hi);color:var(--field)}
.pill.CONTAINED{border:1px solid var(--ink);color:var(--ink)}
.pill.SKIPPED{border:1px solid var(--rule);color:var(--dim)}
.note{color:var(--dim);font-size:var(--micro);letter-spacing:.02em}
details{margin-top:.3rem}
summary{cursor:pointer;color:var(--dim);font-size:var(--micro);letter-spacing:.14em;
text-transform:uppercase;user-select:none;list-style:none}
summary:hover{color:var(--ink);transition:color var(--t-hover) var(--ease)}
summary::before{content:"+ "}
details[open] summary::before{content:"− "}
pre{font-family:inherit;font-size:var(--micro);color:var(--ink-hi);
border-left:1px solid var(--rule);margin:.35rem 0;padding:.25rem 0 .25rem .8rem;
overflow-x:auto;white-space:pre-wrap;word-break:break-all}
/* leaderboard */
table.ranked td.big{font-weight:600;color:var(--ink-hi)}
.sb{height:7px;background:var(--rule);flex:1;margin:0 .8rem;min-width:4rem}
.sbrow{display:flex;align-items:center}
.sb i{display:block;height:100%;background:var(--ink)}
.o0{opacity:.9}.o1{opacity:.55}.o2{opacity:.3}
.pct{font-weight:800;letter-spacing:-.035em;color:var(--ink-hi);min-width:4ch;
text-align:right;font-size:1.1rem}
.pct.na{color:var(--dim);font-weight:500}
footer{margin-top:4rem;border-top:1px solid var(--rule);padding-top:var(--gutter);
font-size:var(--micro);letter-spacing:.14em;text-transform:uppercase;color:var(--dim);line-height:2.2}
@media (prefers-reduced-motion:reduce){
.r1,.r2,.r3,.r4,.card .score{animation-duration:1ms}
*{transition-duration:1ms!important}}
"""

_FONT_FACE = ("@font-face{font-family:'Archivo Variable';font-style:normal;"
              "font-weight:100 900;font-display:swap;"
              "src:url(data:font/woff2;base64,%%FONT%%) format('woff2')}")

_DISCLAIMER = ("A high score does not mean safe. It means that, against this corpus, "
               "in this configuration, on this kernel, those techniques did not get out. "
               "The rest remains undecidable.")


def _esc(x):
    return html.escape(str(x if x is not None else ""))


def _pill(status):
    return f'<span class="pill {_esc(status)}">{_esc(status)}</span>'


def _tier(score):
    return "s-hi" if (score or 0) >= 80 else ("s-mid" if (score or 0) >= 50 else "s-lo")


def _style():
    face = _FONT_FACE.replace("%%FONT%%", _font()) if _font() else ""
    return f"<style>{face}{_CSS}</style>"


def _chrome(where):
    return (f"<div class='bar'><span class='u'>undecidable&#8209;breakout</span>"
            f"<span class='where'>{_esc(where)}</span></div>")


def _rings():
    # concentric, dashed, rotating at incommensurable periods: never resolve
    rings = ((30, 150, 38.5, 1.0, "r1"), (60, 300, 77, 0.55, "r2"),
             (90, 450, 115.5, 0.3, "r3"), (110, 552, 139, 0.15, "r4"))
    g = [f"<svg class='rings' viewBox='0 0 220 220' aria-hidden='true' "
         f"fill='none' stroke='#838383'>"]
    for r, dash, gap, op, cls in rings:
        g.append(f"<g class='{cls}'><circle cx='110' cy='110' r='{r}' "
                 f"stroke-dasharray='{dash} {gap}' stroke-opacity='{op}'/></g>")
    g.append("</svg>")
    return "".join(g)


def _evidence(p):
    r = p.get("result") or {}
    ev = ["<details><summary>evidence</summary>",
          f"<pre>command: {_esc(' '.join(r.get('command') or []))}</pre>",
          f"<pre>exit: {_esc(r.get('exit_code'))}  ·  duration: {r.get('duration', 0):.2f}s"
          f"  ·  timeout: {r.get('timeout', False)}</pre>",
          f"<pre>{_esc(r.get('output', ''))}</pre>"]
    if r.get("canary_hits"):
        ev.append(f"<pre>canary hits: {_esc(json.dumps(r['canary_hits'], default=str))}</pre>")
    ev.append("</details>")
    return "".join(ev)


def _head(title, where):
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<meta name='color-scheme' content='dark'>"
            f"<title>{_esc(title)}</title>{_style()}</head><body>"
            f"{_chrome(where)}<div class='wrap'>")


def render_html(report):
    h = [_head("breakout report", "conformance report"),
         "<div class='head'>", _rings(),
         "<p class='kicker'>conformance report</p>",
         "<h1>undecidable&#8209;breakout</h1>",
         f"<p class='meta'>v{_esc(report['version'])} · {_esc(report['started'])} · "
         f"host {_esc(report['host']['os'])} {_esc(report['host']['kernel'])} · "
         f"baseline {_esc(report['host']['baseline_mode'])} · "
         f"nonce {_esc(report['run_nonce'])}</p></div>",
         "<div class='warn'><b>honesty first</b>"
         f"<span>{_esc(_DISCLAIMER)}</span></div>"]
    cards = []
    for slug, scores in report.get("scores", {}).items():
        o = scores["overall"]
        score = "n/a" if o["score"] is None else f"{o['score']}"
        cards.append(
            f"<div class='card'><div class='slug'>{_esc(slug)}</div>"
            f"<div class='score {_tier(o['score'])}'>{score}</div>"
            f"<div class='sub'>{o['contained']} contained · {o['escaped']} escaped · "
            f"{o['skipped']} skipped</div></div>")
    h.append(f"<div class='cards'>{''.join(cards)}</div>")

    by_cat = {}
    for tid, t in report["techniques"].items():
        by_cat.setdefault(t["meta"]["category"], []).append((tid, t))
    for cat, items in sorted(by_cat.items()):
        h.append(f"<h2><span class='cat'>{_esc(cat)}</span> "
                 f"<span class='count'>{len(items)} techniques</span></h2>")
        h.append("<table><thead><tr><th>technique</th><th>profile</th>"
                 "<th>status</th><th>notes</th></tr></thead><tbody>")
        for tid, t in items:
            first = True
            for slug, p in t["profiles"].items():
                name_cell = (f"<span class='tname'>{_esc(tid)}<small>{_esc(t['meta']['name'])}"
                             f"</small></span>") if first else ""
                first = False
                h.append(f"<tr><td>{name_cell}</td><td class='note' style='letter-spacing:0'>"
                         f"{_esc(slug)}</td>"
                         f"<td>{_pill(p['status'])}</td>"
                         f"<td><span class='note'>{_esc(p['reason'])}</span>"
                         f"{_evidence(p)}</td></tr>")
        h.append("</tbody></table>")
    h.append("<footer>undecidable&#8209;breakout · every verdict is reproducible: "
             "same corpus, same profile, same kernel · skipped techniques never "
             "count against a score</footer></div></body></html>")
    return "".join(h)


def render_sarif(report):
    rules, results = [], []
    for tid, t in report["techniques"].items():
        rules.append({"id": tid, "shortDescription": {"text": t["meta"]["name"]}})
        for slug, p in t["profiles"].items():
            if p["status"] != "ESCAPED":
                continue
            out = (p.get("result") or {}).get("output", "")[:300]
            results.append({
                "ruleId": tid, "level": "error",
                "message": {"text": f"{t['meta']['name']} escaped containment in profile "
                                    f"'{slug}'. Evidence: {out}"},
                "locations": [{"logicalLocations": [
                    {"fullyQualifiedName": f"{slug}/{tid}", "kind": "namespace"}]}]})
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {
                "name": "undecidable-breakout", "version": report["version"],
                "informationUri": "https://github.com/undecidable-research/undecidable-breakout",
                "rules": rules}}, "results": results}]}


def write_all(report, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    (out / "report.html").write_text(render_html(report), encoding="utf-8")
    (out / "report.sarif").write_text(json.dumps(render_sarif(report), indent=2), encoding="utf-8")


def _bar_cell(score):
    if score is None:
        return "<div class='sbrow'><div class='sb'></div><span class='pct na'>n/a</span></div>"
    op = "o0" if score >= 80 else ("o1" if score >= 50 else "o2")
    return (f"<div class='sbrow'><div class='sb'><i class='{op}' "
            f"style='width:{score}%'></i></div>"
            f"<span class='pct'>{score}</span></div>")


def leaderboard(report_paths, out_html, out_json=None):
    rows = []
    for rp in report_paths:
        report = json.loads(Path(rp).read_text(encoding="utf-8"))
        for slug, scores in report.get("scores", {}).items():
            rows.append({
                "profile": slug, "date": report["started"],
                "host": f"{report['host']['os']} {report['host']['kernel']}",
                "corpus_version": report["version"],
                "overall": scores.get("overall", {}).get("score"),
                **{c: (scores.get(c) or {}).get("score") for c in scores if c != "overall"},
            })
    rows.sort(key=lambda r: (r["overall"] is None, -(r["overall"] or 0), r["profile"]))
    data = {"disclaimer": _DISCLAIMER, "rows": rows}
    cats = sorted({c for r in rows for c in r
                   if c not in ("profile", "date", "host", "corpus_version", "overall")})
    h = [_head("breakout leaderboard", "leaderboard"),
         "<div class='head'>", _rings(),
         "<p class='kicker'>leaderboard</p>",
         "<h1>undecidable&#8209;breakout</h1>",
         "<p class='meta'>which containment configurations actually held · "
         "measured, not self&#8209;reported</p></div>",
         "<div class='warn'><b>honesty first</b>"
         f"<span>{_esc(_DISCLAIMER)}</span></div>",
         "<table class='ranked'><thead><tr><th>profile</th><th>overall</th>",
         *[f"<th>{_esc(c)}</th>" for c in cats],
         "<th>measured on</th><th>date</th><th>corpus</th></tr></thead><tbody>"]
    for r in rows:
        h.append(f"<tr><td class='big'>{_esc(r['profile'])}</td>"
                 f"<td>{_bar_cell(r['overall'])}</td>"
                 + "".join(f"<td class='note' style='letter-spacing:0'>"
                           f"{'n/a' if r.get(c) is None else str(r[c])}</td>" for c in cats)
                 + f"<td class='note' style='letter-spacing:0'>{_esc(r['host'])}</td>"
                 f"<td class='note' style='letter-spacing:0'>{_esc(r['date'])}</td>"
                 f"<td class='note' style='letter-spacing:0'>v{_esc(r['corpus_version'])}</td></tr>")
    h.append("</tbody></table>"
             "<footer>higher is better: percentage of applicable techniques contained · "
             "skipped techniques never count against a score · "
             "rows are measured, not self-reported</footer></div></body></html>")
    out = Path(out_html)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(h), encoding="utf-8")
    if out_json:
        Path(out_json).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data
