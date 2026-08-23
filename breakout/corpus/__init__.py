import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CATEGORIES = ("net", "fs", "proc", "ipc", "integrity")
TOKENS = ("NONCE", "TECH_ID", "CANARY_URL", "CANARY_HOST", "CANARY_PORT",
          "DECOY_DIR", "CANARY_ABSTRACT", "CANARY_DNS_PORT")
_TOKEN_RE = re.compile(r"@@([A-Z_]+)@@")


class CorpusError(Exception):
    pass


@dataclass
class Technique:
    id: str
    name: str
    category: str
    description: str = ""
    references: list = field(default_factory=list)
    os: list = field(default_factory=lambda: ["linux"])
    bins: list = field(default_factory=list)
    canary_mode: str = ""
    skip_baseline: bool = False
    timeout: int = 0
    probe: str = ""
    oracle: str = "stdout"

    def uses_token(self, token):
        return f"@@{token}@@" in self.probe


def _parse(path):
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    pre = raw.get("preconditions", {})
    probe = raw.get("probe") or pre.get("probe")
    if not probe or not probe.strip():
        raise CorpusError(f"{path}: missing or empty probe (top-level or in [preconditions])")
    t = Technique(
        id=raw["id"], name=raw["name"], category=raw["category"],
        description=raw.get("description", ""), references=raw.get("references", []),
        os=pre.get("os", ["linux"]), bins=pre.get("bins", []),
        canary_mode=pre.get("canary", ""),
        skip_baseline=raw.get("skip_baseline", False),
        timeout=int(pre.get("timeout", 0)),
        probe=probe,
        oracle=raw.get("oracle") or pre.get("oracle") or "stdout")
    if t.category not in CATEGORIES:
        raise CorpusError(f"{path}: unknown category {t.category}")
    if t.oracle not in ("stdout", "canary"):
        raise CorpusError(f"{path}: unknown oracle {t.oracle}")
    if t.canary_mode not in ("", "ipv6", "abstract"):
        raise CorpusError(f"{path}: unknown canary precondition {t.canary_mode}")
    for m in _TOKEN_RE.findall(t.probe):
        if m not in TOKENS:
            raise CorpusError(f"{path}: unknown token @@{m}@@")
    return t


def load_dir(path):
    path = Path(path)
    if not path.is_dir():
        raise CorpusError(f"techniques directory not found: {path}")
    techs, seen = [], set()
    for f in sorted(path.glob("*.toml")):
        t = _parse(f)
        if t.id in seen:
            raise CorpusError(f"duplicate technique id {t.id} in {f}")
        seen.add(t.id)
        techs.append(t)
    if not techs:
        raise CorpusError(f"no techniques found in {path}")
    return sorted(techs, key=lambda t: (CATEGORIES.index(t.category), t.id))


def default_dir():
    pkg = Path(__file__).resolve().parent.parent / "_data" / "techniques"
    if pkg.is_dir():
        return pkg
    return Path(__file__).resolve().parent.parent.parent / "techniques"
