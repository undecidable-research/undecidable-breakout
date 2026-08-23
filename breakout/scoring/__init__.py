"""Classification and scores.

CONTAINED / ESCAPED only when the baseline established the technique works on
this machine; otherwise SKIPPED so it never pollutes the score.
"""


def classify(tech, baseline, per_profile):
    base_skipped = None
    if not tech.skip_baseline:
        if baseline is None or baseline.skipped:
            base_skipped = f"baseline skipped: {baseline.skip_reason if baseline else 'n/a'}"
        elif not baseline.passed:
            base_skipped = "baseline did not reach the objective; technique not applicable here"
    profiles = {}
    for name, r in per_profile.items():
        if r.skipped:
            s, rr = "SKIPPED", r.skip_reason
        elif base_skipped:
            s, rr = "SKIPPED", base_skipped
        elif tech.skip_baseline:
            s, rr = ("ESCAPED", "containment bypassed") if r.passed else ("CONTAINED", "")
        else:
            s, rr = ("ESCAPED", "") if r.passed else ("CONTAINED", "")
        profiles[name] = {"status": s, "reason": rr, "result": r.as_dict()}
    return {"baseline": baseline.as_dict() if baseline else None, "profiles": profiles}


def scores(results):
    """results: {tid: {"meta": {"category": ...}, "profiles": {slug: {"status": ...}}}}
    -> {slug: {category: {...}, "overall": {...}}}"""
    by = {}
    for tid, r in results.items():
        cat = r["meta"]["category"]
        for slug, p in r["profiles"].items():
            by.setdefault(slug, {}).setdefault(cat, []).append(p["status"])
    final = {}
    for slug, cats in by.items():
        final[slug] = {}
        for cat, sts in cats.items():
            c, e, k = sts.count("CONTAINED"), sts.count("ESCAPED"), sts.count("SKIPPED")
            final[slug][cat] = {"contained": c, "escaped": e, "skipped": k,
                                "score": round(100 * c / (c + e)) if c + e else None}
        tc = sum(v["contained"] for v in final[slug].values())
        te = sum(v["escaped"] for v in final[slug].values())
        tk = sum(v["skipped"] for v in final[slug].values())
        final[slug]["overall"] = {"contained": tc, "escaped": te, "skipped": tk,
                                  "score": round(100 * tc / (tc + te)) if tc + te else None}
    return final


def diff_reports(a, b):
    """(regressions, improvements) as (profile, technique, before, after) tuples.
    A regression is anything that became ESCAPED and was not before."""
    regressions, improvements = [], []
    for tid, t in b["techniques"].items():
        if tid not in a["techniques"]:
            continue
        for slug, p in t["profiles"].items():
            before = a["techniques"][tid]["profiles"].get(slug, {}).get("status")
            after = p["status"]
            if before == after:
                continue
            if after == "SKIPPED" or before == "SKIPPED":
                continue  # coverage change (applicability), not a containment change
            item = (slug, tid, before, after)
            (regressions if after == "ESCAPED" else improvements).append(item)
    return regressions, improvements
