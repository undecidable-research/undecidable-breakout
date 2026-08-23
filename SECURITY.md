# Security policy

## Reporting a vulnerability

Email the maintainer (see `RESPONSIBLE_DISCLOSURE.md` for the full coordinated-disclosure
process). Do not open a public issue for a vulnerability in Breakout itself or in a
sandbox you found broken with it.

## Scope of this tool

Undecidable-Breakout is a conformance suite for containment configurations you own or
are authorized to test. Probes target local canaries and decoy files it creates itself;
the one exception is the egress corpus, which makes constant, data-free reachability
probes to public DNS resolvers (no secret, and nothing about your system, is ever sent).

Known ceiling (deliberate, v0): probes are rendered shell scripts executed
inside the tested sandbox. The sandbox under test could, in theory, tamper with probe
execution and forge a `CONTAINED`. The paired baseline design and per-run nonces make
accidental false results unlikely; a hostile sandbox is out of scope for v0. Upgrade
path: the v1 static binary runner described in the decision memo.

Techniques and profiles are executable content: a technique's `probe` and a profile's
`custom.cmd` run as shell, on the host for the host/none/bwrap/custom kinds. Only load
corpus and profile files from a source you trust.

## Supported versions

| version | supported |
|---|---|
| 0.3.x | yes |
