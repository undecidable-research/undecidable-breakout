"""Self-test: does Breakout tell the truth?

Runs the corpus against profiles whose outcomes are known *by construction*
(an airgapped container cannot reach the canary; a wide-open one must), plus
the documented honest reds, and scores the tool itself: every verdict must
match ground truth. Exit code 1 on any mismatch, so CI holds the tool to the
same standard it holds sandboxes.
"""
import sys
from pathlib import Path

from . import runner
from .corpus import load_dir, default_dir
from .sandboxes import Profile, docker_available, find_profile

# tech_id -> {profile_slug: expected verdict}
# C = CONTAINED, E = ESCAPED, K = SKIPPED
GROUND_TRUTH = {
    # outbound must be impossible from --network none, trivial from bridge
    "net-literal-ip":            {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-vhost-host-header":     {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-nullbyte-hostname":     {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-dns-over-https":        {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-dns-tunneling":         {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-arbitrary-resolver":    {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-icmp-channel":          {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    # no IPv6 listener inside docker: skip logic must hold (never a false score)
    "net-ipv6-fallback":         {"airgap": "K", "wide-open": "K", "docker-tight": "K"},
    # decoy mounted ro: readable; unmounted/none: unreadable
    "fs-read-denied-credentials": {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "fs-proc-self-root":         {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "fs-symlink-escape":         {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    # capabilities: default docker keeps CAP_MKNOD; --cap-drop ALL must remove it
    "fs-mknod-device":           {"airgap": "E", "wide-open": "E", "docker-tight": "C"},
    "proc-cap-dangeff":          {"airgap": "E", "wide-open": "E", "docker-tight": "C"},
    # documented honest reds: these MUST keep escaping, or the tool went blind
    "fs-dev-write":              {"airgap": "E", "wide-open": "E", "docker-tight": "E"},
    "proc-ld-linux-exec":        {"airgap": "E", "wide-open": "E", "docker-tight": "E"},
    # baseline cannot reach /proc/keys keys in docker: skipped, never scored
    "ipc-keyring":               {"airgap": "K", "wide-open": "K", "docker-tight": "K"},

    # --- v0.3 corpus additions, verdicts known by construction ---
    # writable /etc: the default rootfs is writable, --read-only makes it not
    "fs-etc-writable":           {"airgap": "E", "wide-open": "E", "docker-tight": "C"},
    # a credential-shaped env var is planted into every launched context; Docker
    # never scrubs it, so it leaks even from docker-tight (clearenv sandboxes are
    # the mitigation — see bwrap-strict on the leaderboard). An honest red.
    "fs-proc-environ":           {"airgap": "E", "wide-open": "E", "docker-tight": "E"},
    # the PID namespace is isolated here: these MUST NOT fire — the assertion is
    # that the tool reports no false red when the boundary actually holds.
    "fs-proc-pid1-cmdline":      {"airgap": "K", "wide-open": "K", "docker-tight": "K"},
    "proc-signal-pid1":          {"airgap": "K", "wide-open": "K", "docker-tight": "K"},
    # a minimal image carries no setuid surface; unprivileged userns is disabled
    # on this daemon — both correctly skip rather than invent a finding.
    "fs-setuid-inventory":       {"airgap": "K", "wide-open": "K", "docker-tight": "K"},
    "proc-unshare-userns":       {"airgap": "K", "wide-open": "K", "docker-tight": "K"},
    # egress parser-differentials and nonstandard reach: bridge lets them out,
    # --network none contains them.
    "net-alt-ip-encodings":      {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-backslash-authority":   {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-crlf-header-injection": {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-dns-nonstandard-port":  {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    "net-redirect-follow":       {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    # DNS rebinding needs the container to route a DNS query back to our canary;
    # Docker Desktop's NAT does not, so it correctly skips here (it fires from a
    # Linux host or bwrap context, where loopback is the canary).
    "net-dns-rebinding":         {"airgap": "K", "wide-open": "K", "docker-tight": "K"},
    # fd passing reads the mounted decoy through an SCM_RIGHTS-passed descriptor
    "ipc-fd-passing":            {"airgap": "C", "wide-open": "E", "docker-tight": "C"},
    # the docker socket is a configuration artifact, not a runtime capability, so
    # there is no baseline: mounted => escape, absent => contained.
    "ipc-docker-sock":           {"airgap": "C", "wide-open": "C", "docker-tight": "C",
                                  "sock-exposed": "E"},
}

_CODES = {"C": "CONTAINED", "E": "ESCAPED", "K": "SKIPPED"}

# Techniques deliberately NOT in the docker-only accuracy triad: they need a real
# Linux host, bwrap, an IPv6/abstract canary, or a capability the airgap/wide-open/
# docker-tight fixtures cannot reproduce by construction. They are exercised in the
# CI leaderboard instead. Every corpus id must be here or in GROUND_TRUTH — the
# unit-test coverage guard fails if a new technique is neither (so nothing is added
# without a conscious verification decision).
SELFTEST_EXEMPT = {
    "net-dns-over-tcp", "net-ipv6-mapped-literal", "net-quic-udp443",
    "net-sni-host-mismatch", "net-url-userinfo", "net-websocket-upgrade",
    "fs-hardlink-escape", "fs-sys-writable",
    "proc-cgroup-release-agent", "proc-ld-preload", "proc-ptrace-attach",
    "proc-tiocsti",
    "ipc-abstract-socket",
    "integrity-failopen-retry", "integrity-no-sandbox-indicator",
}


def _profiles(decoy_host):
    return [
        Profile(slug="airgap", name="airgap", kind="docker",
                description="selftest fixture: no network, no host paths",
                docker={"network": "none"}),
        Profile(slug="wide-open", name="wide-open", kind="docker",
                description="selftest fixture: bridge net, decoys mounted ro",
                docker={"network": "bridge",
                        "mounts": [[str(decoy_host), "/breakout-decoy", "ro"]]}),
        find_profile("docker-tight"),
        Profile(slug="sock-exposed", name="sock-exposed", kind="docker",
                description="selftest fixture: docker control socket mounted ro",
                docker={"network": "none",
                        "mounts": [["/var/run/docker.sock", "/var/run/docker.sock", "ro"]]}),
    ]


def run(out_dir="reports/selftest", timeout=20):
    ok, why = docker_available()
    if not ok:
        print(f"selftest needs docker: {why}")
        return False
    techs = load_dir(default_dir())
    ids = list(GROUND_TRUTH)
    unknown = [i for i in ids if i not in {t.id for t in techs}]
    if unknown:
        print(f"ground truth references unknown techniques: {unknown}")
        return False
    decoy_host = runner.DECOY_HOST_DIR
    profiles = _profiles(decoy_host)
    report = runner.run(profiles, techs, tech_ids=ids, out_dir=out_dir,
                        timeout=timeout)

    total = hits = 0
    wrong = []
    print()
    for tid, expected in GROUND_TRUTH.items():
        for slug, code in expected.items():
            got = (report["techniques"][tid]["profiles"].get(slug, {})
                   .get("status", "MISSING"))
            want = _CODES[code]
            total += 1
            mark = "ok" if got == want else "WRONG"
            if got == want:
                hits += 1
            else:
                wrong.append((tid, slug, want, got))
            print(f"  {mark:<5} {tid:<30} {slug:<13} want {want:<9} got {got}")
    acc = 100 * hits / total
    print(f"\n  selftest accuracy: {hits}/{total} ({acc:.0f}%)")
    if wrong:
        print("  the tool disagrees with ground truth — fix the tool, not the truth")
        return False
    return True
