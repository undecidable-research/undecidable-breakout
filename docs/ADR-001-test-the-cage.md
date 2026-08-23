# ADR-001: We test the cage, we do not add a thirty-first one

Date: 2026-08-22
Status: accepted

## Context

More than thirty open-source sandboxes compete to contain coding agents. None ships a
conformance suite; nobody publishes comparable enforcement measurements; the biggest
egress-control products were bypassed three separate times in 2026 (SOCKS5 null-byte
parser differential, DoH/DoT egress, virtual-host confusion). Configurations fail open
and nobody notices.

## Decision

Undecidable-Breakout is a **test harness**, not a sandbox:

- The unit of analysis is a containment *configuration* (wrapper + policy + kernel),
  not a model, not a product.
- Techniques are versioned **data** with sources and binary oracles, never code, so the
  corpus can grow by pull request and every result is reproducible.
- Every technique runs paired (outside for applicability, inside for containment), and
  non-applicable techniques are `SKIPPED` rather than scored — a scorecard must never
  reward a machine for lacking the ability to even try.
- Probes reach a local canary and tool-planted decoys; the only external traffic is
  constant, data-free reachability probes to public resolvers (the egress corpus). A
  tool that demonstrates exfiltration by exfiltrating is itself a weapon; this is a
  project constraint, not an implementation detail.
- We claim the negative only: *these techniques, in this configuration, on this kernel,
  were not stopped.* Safety in general is undecidable — hence the name.

## Alternatives rejected

- **Ship another sandbox** — crowded, and it would arrive without anyone able to verify
  it holds either.
- **Config scanner** — every 2026 bypass above passed configuration review; only
  execution inside the boundary catches them.
- **Model capability benchmark** (sandbox fixed, model variable) — already exists
  (`sandbox_escape_bench`); it measures the attacker, not the cage.

## Consequences

- Findings in third-party sandboxes are expected output and must flow through
  responsible disclosure (see `RESPONSIBLE_DISCLOSURE.md`).
- v0 probes are shell scripts; a hostile sandbox could forge `CONTAINED`. Accepted
  ceiling for v0; the upgrade path is the static binary runner.
- The leaderboard must carry the undecidability disclaimer at the top, always.
