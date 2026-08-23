# Contributing

The corpus is the part that matters, and it grows one pull request at a time.

## Adding a technique

A technique is **data, never code**: one TOML file in `techniques/`, id = filename.

```toml
id = "net-my-bypass"                    # must equal the filename
name = "Short human name"
category = "net"                        # net | fs | proc | ipc | integrity
description = "What it does and why it escapes. One honest paragraph."
references = [
  "A citable source: CVE, advisory, research post",
]

probe = '''
# shell, runs inside AND outside the sandbox; tokens below are substituted
grep -q "BREAKOUT_NONCE=" "@@DECOY_DIR@@/credentials.env" 2>/dev/null && echo ESCAPED
'''

[preconditions]
# optional gates; a failing gate => SKIPPED with your reason, never a false score
os = ["linux"]          # default
bins = ["curl"]         # binaries that must exist in the execution environment
canary = ""             # "" | "ipv6" | "abstract"
timeout = 0             # optional per-technique timeout seconds (0 = default 20)
oracle = "stdout"       # "stdout": probe prints ESCAPED | "canary": hit recorded
```

Rules, enforced in review:

1. **Tokens only** (`@@NONCE@@, @@TECH_ID@@, @@CANARY_URL@@, @@CANARY_HOST@@,
   @@CANARY_PORT@@, @@CANARY_DNS_PORT@@, @@DECOY_DIR@@, @@CANARY_ABSTRACT@@`). No
   hardcoded hosts, ports, paths.
2. **Local canary or decoys only.** The single exception pattern is a constant,
   data-free external lookup (see `net-dns-over-https`); anything that transmits user
   data or nonces off-machine will be rejected.
3. **Binary oracle.** `stdout` probes must print exactly `ESCAPED` on success; `canary`
   probes must place `@@TECH_ID@@ @@NONCE@@` where the canary records it.
4. **Cite the source.** Every technique references a documentable bypass (CVE, advisory,
   vendor post, research write-up). "Works on my machine" is not a source.
5. **Fail safe.** If the technique does not apply, the probe must fail closed (no
   output), so it lands `SKIPPED` via the baseline, never a false `CONTAINED`.

Check locally before opening the PR:

```bash
python -m unittest discover -s tests -v
python -m breakout.cli verify
python -m breakout.cli run --profile none --categories <your-category>
```

## Adding a sandbox profile

One TOML in `profiles/` (see existing files for `docker`, `bwrap`, `custom` kinds). A
profile must be reproducible from its file alone: no environment-dependent secrets.

## Everything else

Bug fixes and runner improvements welcome — smallest diff that fixes the root cause.
New runtime dependencies are not welcome: stdlib only. By contributing you agree to MIT
licensing of your contribution.
