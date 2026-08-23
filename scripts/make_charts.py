"""Generate the README case-study charts from a measured report.json.

Palette-only SVG plates: near-black field, ink at a few opacities, micro caps
labels, no other colour. Stdlib only; output committed so GitHub renders it.
Usage: python scripts/make_charts.py [report.json]
"""
import json
import sys
from pathlib import Path

FIELD, INK, DIM, RULE = "#050505", "#838383", "#484848", "#2e2e2e"
FONT = "Archivo, ui-sans-serif, system-ui, sans-serif"
W = 1200
EDGE = 96


def _op(score):
    return 0.92 if score >= 80 else (0.72 if score >= 50 else 0.62)


def _micro(x, y, text, size=13, anchor="start", fill=INK, weight=600, spacing=3.2):
    return (f"<text x='{x:.0f}' y='{y:.0f}' font-family='{FONT}' font-size='{size}' "
            f"letter-spacing='{spacing}' fill='{fill}' font-weight='{weight}' "
            f"text-anchor='{anchor}'>{text.upper()}</text>")


def _hair(y, x0=EDGE, x1=W - EDGE):
    return f"<rect x='{x0}' y='{y:.0f}' width='{x1 - x0:.0f}' height='1' fill='{RULE}'/>"


def _svg(body, h):
    return (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {W} {h}' "
            f"width='{W}' height='{h}'><rect width='{W}' height='{h}' "
            f"fill='{FIELD}'/>{''.join(body)}</svg>")


def overall(report):
    rows = list(report["scores"].items())
    top, rowh = 118, 168
    h = top + rowh * len(rows) + 8
    num_x, col_x = 316, 372
    body = [_micro(EDGE, 74, "containment score — same corpus, same machine, one flag apart",
                   14, fill=DIM, spacing=3.6),
            _hair(94)]
    for i, (slug, sc) in enumerate(rows):
        o = sc["overall"]
        s = 0 if o["score"] is None else o["score"]
        cy = top + i * rowh + rowh / 2 - 22
        pct = "n/a%" if o["score"] is None else f"{s}%"
        body += [
            f"<text x='{num_x}' y='{cy + 30:.0f}' font-family='{FONT}' font-size='98' "
            f"font-weight='800' letter-spacing='-4' fill='{INK}' "
            f"text-anchor='end'>{pct}</text>",
            _micro(col_x, cy - 34, slug, 19, fill=INK, weight=700, spacing=2),
            f"<rect x='{col_x}' y='{cy - 7:.0f}' width='{W - EDGE - col_x}' height='13' "
            f"rx='6.5' fill='{RULE}'/>",
            f"<rect x='{col_x}' y='{cy - 7:.0f}' "
            f"width='{max(13, (W - EDGE - col_x) * s / 100):.1f}' height='13' rx='6.5' "
            f"fill='{INK}' opacity='{_op(s)}'/>",
            _micro(col_x, cy + 42, f"{o['contained']} contained · {o['escaped']} escaped · "
                   f"{o['skipped']} skipped", 13.5, fill=DIM, weight=500, spacing=2.4),
        ]
        if i < len(rows) - 1:
            body.append(_hair(top + i * rowh + rowh - 12))
    return _svg(body, h)


def categories(report):
    slugs = list(report["scores"])                       # [loose, tight]
    cats = [c for c in ("net", "fs", "proc", "ipc", "integrity")
            if any(report["scores"][s].get(c, {}).get("score") is not None for s in slugs)]
    x0, x1 = 232, W - EDGE
    top, grp, barh, inner = 130, 92, 16, 11
    pair = 2 * barh + inner
    h = top + grp * len(cats) + 30
    axis_top, axis_bot = top - 20, top + grp * (len(cats) - 1) + pair + 12
    body = [_micro(EDGE, 72, "containment by class of escape", 14, fill=DIM, spacing=3.6),
            _micro(W - EDGE, 72, "percent contained · loose vs tight", 12, anchor="end",
                   fill=DIM, spacing=2.6),
            _hair(92)]
    for gx in (0, 50, 100):                               # subtle grid behind the bars
        x = x0 + (x1 - x0) * gx / 100
        body.append(f"<rect x='{x:.1f}' y='{axis_top}' width='{1.5 if gx == 0 else 1}' "
                    f"height='{axis_bot - axis_top}' fill='{RULE}'/>")
        body.append(_micro(x, axis_bot + 28, str(gx), 12, anchor="middle", fill=DIM,
                           weight=500, spacing=1))
    for i, cat in enumerate(cats):
        gy = top + i * grp
        body.append(_micro(EDGE, gy + pair / 2 + 5, cat, 17, fill=INK, weight=700, spacing=1.5))
        for r, slug in enumerate(slugs):
            score = report["scores"][slug].get(cat, {}).get("score")
            v = 0 if score is None else score
            by = gy + r * (barh + inner)
            w = (x1 - x0) * v / 100
            if v > 0:
                body.append(f"<rect x='{x0}' y='{by}' width='{w:.1f}' height='{barh}' "
                            f"rx='2.5' fill='{INK}' opacity='{0.24 if r == 0 else 0.9}'/>")
            label = "n/a" if score is None else str(v)
            if w > 60 and r == 1:                        # inside the solid (tight) bar
                body.append(_micro(x0 + w - 11, by + barh - 3.5, label, 11.5, anchor="end",
                                   fill=FIELD, weight=700, spacing=0.5))
            else:                                        # outside, dim
                body.append(_micro(x0 + w + 11, by + barh - 3.5, label, 11.5, anchor="start",
                                   fill=DIM, weight=600, spacing=0.5))
    ly = h - 26
    body += [f"<rect x='{EDGE}' y='{ly - 9:.0f}' width='20' height='10' rx='2' "
             f"fill='{INK}' opacity='0.24'/>",
             _micro(EDGE + 28, ly, slugs[0].replace('docker-', ''), 11.5, fill=DIM, weight=600),
             f"<rect x='{EDGE + 140}' y='{ly - 9:.0f}' width='20' height='10' rx='2' "
             f"fill='{INK}' opacity='0.9'/>",
             _micro(EDGE + 168, ly, slugs[-1].replace('docker-', ''), 11.5, fill=DIM, weight=600)]
    tight = "docker-tight" if "docker-tight" in report["scores"] else slugs[-1]
    reds = [tid.split("-", 1)[1] for tid, d in report.get("techniques", {}).items()
            if d.get("profiles", {}).get(tight, {}).get("status") == "ESCAPED"]
    note = (f"{len(reds)} honest reds survive {tight}: " + ", ".join(reds[:4])
            if reds else f"nothing survives {tight}")
    body.append(_micro(W - EDGE, ly, note, 11.5, anchor="end", fill=DIM, weight=500, spacing=1.6))
    return _svg(body, h)


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "reports/case-study/report.json")
    report = json.loads(src.read_text(encoding="utf-8"))
    out = Path("docs/assets")
    out.mkdir(parents=True, exist_ok=True)
    (out / "case-study-overall.svg").write_text(overall(report), encoding="utf-8")
    (out / "case-study-categories.svg").write_text(categories(report), encoding="utf-8")
    print(f"charts -> {out.resolve()}")


if __name__ == "__main__":
    main()
