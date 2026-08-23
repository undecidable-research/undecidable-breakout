"""Sandbox profiles: how to launch a command inside a containment config.

A profile is data (TOML). Kind is one of: none, docker, bwrap, landlock, custom.
"""
import os
import platform
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PROFILE_KINDS = ("none", "docker", "bwrap", "landlock", "custom")


class ProfileError(Exception):
    pass


@dataclass
class Profile:
    slug: str
    name: str
    kind: str
    description: str = ""
    docker: dict = field(default_factory=dict)
    bwrap: dict = field(default_factory=dict)
    custom: dict = field(default_factory=dict)
    os_allow: list = field(default_factory=list)   # [] = any host OS
    requires: list = field(default_factory=list)   # binaries that must exist
    source: str = ""

    @property
    def is_posix_only(self):
        return self.kind in ("none", "bwrap", "custom", "landlock")


def load_profile(path):
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    p = raw.get("profile", raw)
    kind = p.get("kind", "")
    if kind not in PROFILE_KINDS:
        raise ProfileError(f"{path}: kind must be one of {PROFILE_KINDS}")
    return Profile(
        slug=Path(path).stem, name=p.get("name", Path(path).stem), kind=kind,
        description=p.get("description", ""), docker=p.get("docker", {}),
        bwrap=p.get("bwrap", {}), custom=p.get("custom", {}),
        os_allow=p.get("os", []), requires=p.get("requires", []), source=str(path))


def builtin_dir():
    pkg = Path(__file__).resolve().parent.parent / "_data" / "profiles"
    if pkg.is_dir():
        return pkg
    return Path(__file__).resolve().parent.parent.parent / "profiles"


def find_profile(slug, extra_dirs=()):
    """Resolve a profile by slug from builtin dir (or a path directly)."""
    p = Path(slug)
    if p.suffix == ".toml" and p.is_file():
        return load_profile(p)
    for d in (*extra_dirs, builtin_dir()):
        cand = Path(d) / f"{slug}.toml"
        if cand.is_file():
            return load_profile(cand)
    raise ProfileError(f"profile not found: {slug}")


def docker_available():
    if not shutil.which("docker"):
        return False, "docker binary not found"
    try:
        r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            return True, r.stdout.strip()
        return False, "docker daemon not reachable"
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"docker daemon not reachable: {e}"


def render_docker_args(d, decoy_host_dir, image=None, env=None):
    """d: profile [docker] table -> docker run argv (without trailing sh -s)."""
    args = ["docker", "run", "--rm", "-i"]
    for k, v in (env or {}).items():
        args += ["-e", f"{k}={v}"]
    net = d.get("network", "bridge")
    if net in ("none", "host", "bridge"):
        args += ["--network", net]
    elif net:
        args += ["--network", net]
    if net != "none":
        args += ["--add-host", "host.docker.internal:host-gateway"]
    if d.get("read_only"):
        args += ["--read-only"]
    caps = d.get("cap_drop", [])
    for c in (["ALL"] if caps == "ALL" else caps):
        args += ["--cap-drop", c]
    for o in d.get("security_opt", []):
        args += ["--security-opt", o]
    if d.get("pids_limit") is not None:
        args += ["--pids-limit", str(d["pids_limit"])]
    for t in d.get("tmpfs", []):
        args += ["--tmpfs", t]
    for m in d.get("mounts", []):
        host, cont = m[0], m[1]
        mode = m[2] if len(m) > 2 else ""
        host = str(Path(host).expanduser()) if host.startswith("~") else host
        args += ["-v", f"{host}:{cont}:{mode}" if mode else f"{host}:{cont}"]
    args.append(image or d.get("image", "python:3.12-alpine"))
    return args


def render_bwrap_args(b):
    args = ["bwrap"]
    for x in b.get("ro_bind", []):
        args += ["--ro-bind", x, x]
    for x in b.get("bind", []):
        args += ["--bind", x, x]
    for x in b.get("dev_bind", []):
        args += ["--dev-bind", x, x]
    for x in b.get("proc_bind", []):
        args += ["--proc", x]
    for x in b.get("tmpfs", []):
        args += ["--tmpfs", x]
    for x in b.get("unshare", []):
        args += [f"--unshare-{x}"]
    if b.get("clearenv"):
        args += ["--clearenv"]
    if b.get("new_session"):
        args += ["--new-session"]
    if b.get("die_with_parent"):
        args += ["--die-with-parent"]
    return args


def host_is_posix():
    return os.name == "posix"


def host_os_key():
    return {"linux": "linux", "darwin": "macos", "win32": "windows"}.get(
        platform.system().lower(), platform.system().lower())


def profile_unavailable(p):
    """None if the profile can run on this host, else the reason."""
    if p.os_allow and host_os_key() not in p.os_allow:
        return f"profile requires os in {p.os_allow}, host is {host_os_key()}"
    reqs = list(p.requires)
    if p.kind == "bwrap" and "bwrap" not in reqs:
        reqs.append("bwrap")
    if p.kind == "landlock" and "cc" not in reqs:
        reqs.append("cc")
    for b in reqs:
        if not shutil.which(b):
            return f"required binary not found: {b}"
    return None


_landlock_bin = None


def landlock_binary():
    """Compile the Landlock helper once per process; None if it can't build."""
    global _landlock_bin
    if _landlock_bin:
        return _landlock_bin
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        return None
    src = Path(__file__).with_name("landlock.c")
    out = Path(tempfile.gettempdir()) / f"breakout-landlock-{os.getuid() if os.name == 'posix' else 'user'}"
    r = subprocess.run([cc, "-O2", "-o", str(out), str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        raise ProfileError(f"failed to compile landlock helper:\n{r.stderr}")
    _landlock_bin = str(out)
    return _landlock_bin


def preflight(argv, expect="ok", timeout=30):
    """Run a context launcher once with a trivial command; None if healthy.
    Guards against broken wrappers scoring silent false CONTAINEDs."""
    try:
        r = subprocess.run(argv, input=b"echo " + expect.encode() + b"\n",
                           capture_output=True, timeout=timeout)
        if expect in r.stdout.decode("utf-8", "replace"):
            return None
        return (f"preflight failed: launcher exited {r.returncode}: "
                f"{r.stderr.decode('utf-8', 'replace')[:200]}")
    except subprocess.TimeoutExpired:
        return "preflight failed: launcher timed out"
    except OSError as e:
        return f"preflight failed: exec error: {e}"
