"""Paired runner: each technique runs outside (baseline) and inside the sandbox."""
import json
import os
import platform
import secrets
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from ..canary import Canary
from ..corpus import CATEGORIES
from ..sandboxes import (Profile, docker_available, host_is_posix, host_os_key,
                         landlock_binary, preflight, profile_unavailable,
                         render_bwrap_args, render_docker_args)

DECOY_HOST_DIR = Path.home() / ".breakout-decoy"
DECOY_CONTAINER_DIR = "/breakout-decoy"
# python3.12 + busybox (nc, wget, unshare): a container that can actually run
# code, which is the realistic threat model — an empty alpine can't exercise the
# SSRF/parser-differential corpus at all.
BASELINE_IMAGE = "python:3.12-alpine"
# a credential-shaped env var planted into every launched context; fs-proc-environ
# proves whether the boundary scrubs it (docker doesn't; clearenv sandboxes do).
DECOY_ENV_VAR = "BREAKOUT_DECOY_API_KEY"
DEFAULT_TIMEOUT = 20


@dataclass
class ProbeResult:
    context: str
    skipped: bool = False
    skip_reason: str = ""
    passed: bool = False
    exit_code: int = None
    timeout: bool = False
    duration: float = 0.0
    command: list = field(default_factory=list)
    output: str = ""
    canary_hits: list = field(default_factory=list)
    flaky: bool = False          # escaped/passed on some repeats only
    repeats: int = 1

    def as_dict(self):
        return asdict(self)


@dataclass
class RunContext:
    name: str
    kind: str                    # "host" | "docker" | "bwrap" | "custom" | "none"
    argv: list                   # command that reads the probe on stdin
    canary_host: str
    canary_port: int
    decoy_dir: str
    ipv6: bool
    abstract: bool
    os_key: str = "linux"        # OS of the execution environment
    profile: Profile = None
    unavailable: str = ""        # non-empty => every probe in this context skips

    def tokens(self, tech_id, nonce, canary):
        url = f"http://{self.canary_host}:{self.canary_port}"
        return {
            "NONCE": nonce, "TECH_ID": tech_id,
            "CANARY_URL": url, "CANARY_HOST": self.canary_host,
            "CANARY_PORT": str(self.canary_port),
            "CANARY_DNS_PORT": str(canary.dns_port),
            "DECOY_DIR": self.decoy_dir,
            "CANARY_ABSTRACT": canary.abstract_name or "",
        }


def _sh(script, argv, timeout):
    t0 = time.monotonic()
    try:
        r = subprocess.run(argv, input=script.encode(), capture_output=True,
                           timeout=timeout)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
        return ProbeResult(context="", exit_code=r.returncode, duration=time.monotonic() - t0,
                           command=argv, output=out[-2000:])
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"") + (e.stderr or b"")).decode("utf-8", "replace")
        return ProbeResult(context="", exit_code=None, timeout=True,
                           duration=time.monotonic() - t0, command=argv,
                           output=out[-2000:])
    except OSError as e:
        return ProbeResult(context="", skipped=True, skip_reason=f"exec error: {e}",
                           command=argv)


def write_decoys(nonce):
    DECOY_HOST_DIR.mkdir(mode=0o700, exist_ok=True)
    (DECOY_HOST_DIR / "credentials.env").write_text(
        f"# breakout decoy - not a real secret\nBREAKOUT_NONCE={nonce}\n")
    (DECOY_HOST_DIR / "ssh.key").write_text(
        f"-----BEGIN OPENSSH PRIVATE KEY-----\nbreakout-decoy-{nonce}\n-----END-----\n")
    return DECOY_HOST_DIR


def build_contexts(profiles, canary_info, baseline_mode, decoy_host, decoy_env=None):
    """baseline_mode: auto (docker on windows host, host-sh on posix) | host | docker."""
    ctxs = []
    posix = host_is_posix()
    if baseline_mode == "host" or (baseline_mode == "auto" and posix):
        ctxs.append(RunContext(
            name="baseline", kind="host", argv=["sh", "-s"],
            canary_host="127.0.0.1", canary_port=canary_info["port"],
            decoy_dir=str(decoy_host), ipv6=canary_info["ipv6"],
            abstract=canary_info["abstract"], os_key=host_os_key()))
    else:
        argv = render_docker_args({"network": "bridge",
                                   "mounts": [[str(decoy_host), DECOY_CONTAINER_DIR, "ro"]]},
                                  decoy_host, image=BASELINE_IMAGE, env=decoy_env) + ["sh", "-s"]
        ctxs.append(RunContext(
            name="baseline(docker)", kind="docker", argv=argv,
            canary_host="host.docker.internal", canary_port=canary_info["port"],
            decoy_dir=DECOY_CONTAINER_DIR, ipv6=False, abstract=False,
            os_key="linux"))
    for p in profiles:
        reason = profile_unavailable(p)
        if not reason and not posix and p.kind in ("none", "custom", "bwrap"):
            reason = f"profile kind '{p.kind}' requires a POSIX host"
        if not reason and p.kind == "landlock":
            if host_os_key() != "linux":
                reason = "landlock requires Linux"
            else:
                helper = landlock_binary()
                reason = (preflight([helper, "sh"]) if helper
                          else "cc not found to build the landlock helper")
        if not reason and p.kind == "docker":
            argv = render_docker_args(p.docker, decoy_host, env=decoy_env) + ["sh", "-s"]
            reason = preflight(argv, timeout=90)
        elif not reason and p.kind == "bwrap":
            argv = render_bwrap_args(p.bwrap) + ["sh", "-s"]
            reason = preflight(argv)
        elif not reason and p.kind == "custom":
            tpl = p.custom.get("cmd", "")
            if "@@CMD@@" not in tpl:
                raise ValueError(f"profile {p.slug}: custom.cmd must contain @@CMD@@")
            argv = ["sh", "-c", tpl.replace("@@CMD@@", "sh -s")]
            reason = preflight(argv)
        if reason:
            ctxs.append(RunContext(
                name=p.slug, kind=p.kind, argv=[], profile=p,
                canary_host="127.0.0.1", canary_port=canary_info["port"],
                decoy_dir=str(decoy_host), ipv6=canary_info["ipv6"],
                abstract=canary_info["abstract"], os_key=host_os_key(),
                unavailable=reason))
            continue
        if p.kind == "docker":
            ctxs.append(RunContext(
                name=p.slug, kind="docker", argv=argv, profile=p,
                canary_host="host.docker.internal",
                canary_port=canary_info["port"], decoy_dir=DECOY_CONTAINER_DIR,
                ipv6=False, abstract=False, os_key="linux"))
        elif p.kind == "bwrap":
            ctxs.append(RunContext(
                name=p.slug, kind="bwrap", argv=argv, profile=p,
                canary_host="127.0.0.1", canary_port=canary_info["port"],
                decoy_dir=str(decoy_host), ipv6=canary_info["ipv6"],
                abstract=canary_info["abstract"] if "net" not in p.bwrap.get("unshare", [])
                else False, os_key="linux"))
        elif p.kind == "none":
            ctxs.append(RunContext(
                name=p.slug, kind="none", argv=["sh", "-s"], profile=p,
                canary_host="127.0.0.1", canary_port=canary_info["port"],
                decoy_dir=str(decoy_host), ipv6=canary_info["ipv6"],
                abstract=canary_info["abstract"], os_key=host_os_key()))
        elif p.kind == "landlock":
            ctxs.append(RunContext(
                name=p.slug, kind="landlock", argv=[landlock_binary(), "sh", "-s"],
                profile=p, canary_host="127.0.0.1", canary_port=canary_info["port"],
                decoy_dir=str(decoy_host), ipv6=canary_info["ipv6"],
                abstract=canary_info["abstract"], os_key="linux"))
        elif p.kind == "custom":
            ctxs.append(RunContext(
                name=p.slug, kind="custom", argv=argv, profile=p,
                canary_host="127.0.0.1", canary_port=canary_info["port"],
                decoy_dir=str(decoy_host), ipv6=canary_info["ipv6"],
                abstract=canary_info["abstract"], os_key=host_os_key()))
    return ctxs


def probe_bins(ctx, bins):
    """Which of `bins` exist inside the context's execution environment.
    Retried once: a transient container-start hiccup must not read as 'binary
    missing', which would silently turn a real ESCAPED/CONTAINED into SKIPPED."""
    if not bins or ctx.unavailable:
        return set()
    script = "for b in $@; do command -v \"$b\" >/dev/null 2>&1 && echo \"$b\"; done"
    for timeout in (30, 60):
        r = _sh(script.replace("$@", " ".join(bins)), ctx.argv, timeout)
        if not (r.timeout or (r.exit_code != 0 and not r.output)):
            return {line.strip() for line in r.output.splitlines() if line.strip()}
    return set()


def check_preconditions(tech, ctx, bins_available):
    if ctx.unavailable:
        return f"profile unavailable: {ctx.unavailable}"
    if ctx.os_key not in tech.os:
        return f"os {ctx.os_key} not in {tech.os}"
    missing = [b for b in tech.bins if b not in bins_available]
    if missing:
        return f"missing binaries: {', '.join(missing)}"
    if tech.canary_mode == "ipv6" and not ctx.ipv6:
        return "canary not reachable over IPv6 in this context"
    if tech.canary_mode == "abstract" and not ctx.abstract:
        return "abstract UNIX socket not shared with this context"
    return None


def render_probe(tech, ctx, nonce, canary):
    script = tech.probe
    for k, v in ctx.tokens(tech.id, nonce, canary).items():
        script = script.replace(f"@@{k}@@", str(v))
    return script


def _stdout_passed(output):
    """Line-anchored oracle: a full line must equal ESCAPED, so an error
    message that merely contains the word can never forge a verdict."""
    return any(line.strip() == "ESCAPED" for line in output.splitlines())


def _wait_for_hit(tech_id, nonce, canary, after, deadline=2.0, poll=0.1):
    """Late-hit guard: a slow path can deliver a canary hit after the probe
    process exits. Poll briefly before letting a CONTAINED stand. `after`
    keeps earlier runs (same nonce, e.g. the baseline) from counting."""
    t0 = time.time()
    while time.time() - t0 < deadline:
        if canary.saw(tech_id, nonce, after=after):
            return True
        time.sleep(poll)
    return False


def run_probe(tech, ctx, nonce, canary, timeout):
    if ctx.kind in ("none", "custom", "bwrap") and not host_is_posix():
        return ProbeResult(context=ctx.name, skipped=True,
                           skip_reason=f"profile kind '{ctx.kind}' requires a POSIX host")
    script = render_probe(tech, ctx, nonce, canary)
    t_start = time.time()
    r = _sh(script, ctx.argv, tech.timeout or timeout)
    r.context = ctx.name
    if tech.oracle == "canary":
        r.passed = (bool(canary.hits_for(tech.id, nonce, after=t_start))
                    or (not r.timeout and _wait_for_hit(tech.id, nonce, canary,
                                                        after=t_start)))
        r.canary_hits = canary.hits_for(tech.id, nonce, after=t_start)
    else:
        r.passed = _stdout_passed(r.output)
    return r


def _aggregate(results):
    """Collapse repeated ProbeResults into one representative verdict.
    Escape semantics: passed on ANY repeat means passed (an escape that works
    one time in five is still an escape); flaky marks the instability."""
    live = [r for r in results if not r.skipped]
    if not live:
        r = results[0]
        return r
    best = max(live, key=lambda r: (r.passed, not r.timeout))
    passed = [r for r in live if r.passed]
    best = ProbeResult(
        context=best.context, exit_code=best.exit_code, timeout=best.timeout,
        duration=sum(r.duration for r in live),
        command=best.command,
        output="\n---\n".join(r.output for r in live if r.output)[-2000:],
        canary_hits=[h for r in live for h in r.canary_hits],
        passed=bool(passed),
        flaky=bool(passed) and len(passed) != len(live),
        repeats=len(live))
    return best


def _probe_repeated(tech, ctx, canary, timeout, repeat, bins_available):
    """Run a probe `repeat` times and collapse the results into one verdict.
    repeat=1 is exactly one check_preconditions + run_probe call, so it is
    behaviorally identical to the old unrepeated path."""
    outs = []
    for _ in range(max(1, repeat)):
        nonce = secrets.token_hex(8)
        reason = check_preconditions(tech, ctx, bins_available)
        outs.append(ProbeResult(context=ctx.name, skipped=True, skip_reason=reason)
                    if reason else run_probe(tech, ctx, nonce, canary, timeout))
    return _aggregate(outs)


_ctx_bins_cache = {}


def run(profiles, techniques, categories=None, tech_ids=None, out_dir="reports",
        timeout=DEFAULT_TIMEOUT, baseline_mode="auto", repeat=1, jobs=1, quiet=False):
    from .. import scoring, reporting  # local import: avoid cycle at module load

    canary = Canary()
    canary.start()
    nonce_run = secrets.token_hex(8)
    decoy_host = write_decoys(nonce_run)
    # plant a credential-shaped env secret in every context we launch: host/none/
    # bwrap inherit it from this process, docker gets it via -e (below). Restored
    # in the finally below so an in-process (library/CI) caller is not left with a
    # stray fake credential in its environment.
    decoy_env = {DECOY_ENV_VAR: f"sk-live-{nonce_run}"}
    _prev_decoy_env = os.environ.get(DECOY_ENV_VAR)
    os.environ[DECOY_ENV_VAR] = decoy_env[DECOY_ENV_VAR]
    try:
        if any(p.kind == "docker" for p in profiles) or baseline_mode == "docker" or (
                baseline_mode == "auto" and not host_is_posix()):
            ok, why = docker_available()
            if not ok:
                raise RuntimeError(f"docker required but unavailable: {why}")
            for img in {p.docker.get("image", BASELINE_IMAGE) for p in profiles if p.kind == "docker"} | {
                    BASELINE_IMAGE}:
                subprocess.run(["docker", "pull", "-q", img], capture_output=True, timeout=300)

        ctxs = build_contexts(profiles, canary.info(), baseline_mode, decoy_host, decoy_env)
        all_bins = sorted({b for t in techniques for b in t.bins})
        bins_per_ctx = {ctx.name: probe_bins(ctx, all_bins) for ctx in ctxs}

        results = {}
        for tech in techniques:
            if categories and tech.category not in categories:
                continue
            if tech_ids is not None and tech.id not in tech_ids:
                continue
            base = None
            if not tech.skip_baseline:
                bctx = ctxs[0]
                base = _probe_repeated(tech, bctx, canary, timeout, repeat,
                                       bins_per_ctx[bctx.name])
            per_profile = {}
            for ctx in ctxs[1:]:
                per_profile[ctx.name] = _probe_repeated(
                    tech, ctx, canary, timeout, repeat, bins_per_ctx[ctx.name])
            results[tech.id] = {"meta": {"name": tech.name, "category": tech.category,
                                         "description": tech.description,
                                         "references": tech.references},
                                **scoring.classify(tech, base, per_profile)}

        canary.stop()
        import breakout
        report = {
            "tool": "undecidable-breakout", "version": breakout.__version__,
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "host": {"os": host_os_key(), "kernel": platform.release(),
                     "baseline_mode": baseline_mode},
            "canary": canary.info(), "run_nonce": nonce_run,
            "techniques": results,
            "scores": scoring.scores(results),
        }
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        reporting.write_all(report, out)
        return report
    finally:
        if _prev_decoy_env is None:
            os.environ.pop(DECOY_ENV_VAR, None)
        else:
            os.environ[DECOY_ENV_VAR] = _prev_decoy_env
