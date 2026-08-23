# Responsible disclosure

Breakout executes documented escape techniques. Used against software you do not own,
its output is a weaponized finding. If you find a real containment bug in someone
else's sandbox — a wrapper, an egress proxy, a container runtime — disclose it
responsibly.

## Process

1. **Do not publish first.** Report privately to the maintainer of the affected project
   through their security channel (SECURITY.md, security email, GitHub private
   vulnerability reporting).
2. **Give them 90 days** from acknowledgement before any publication. Coordinate the
   date; move it later if they are actively fixing, not stalling.
3. **Include a minimal reproducer**, ideally as a Breakout technique file, and the exact
   configuration (profile, kernel, versions) where it reproduces.
4. **Credit fixes, not failures.** The goal is a fixed sandbox, not a public shaming.
   Offer draft advisory text; let them review for accuracy only, not for tone-laundering.
5. **CVEs are their call** (usually via their CNA). Never request a CVE to pressure a
   maintainer.

If a project has no security contact, wait the full 90 days from your first attempt,
then disclose with the reproducer and mitigation guidance included.

## Known related disclosures (context for the corpus)

- Claude Code sandbox-runtime SOCKS5 null-byte hostname differential (fixed 2026-04-01,
  sandbox-runtime 0.0.43; no CVE assigned; ~130 affected releases).
- CVE-2025-66479 — earlier bypass of the same egress proxy.
- CVE-2026-32946 / CVE-2026-32947 — Harden-Runner DNS over TCP / HTTPS (2026-03-18).
- BullFrog Actions virtual-hosting bypass (2026).
- Flatpak CVE-2026-34078 — full sandbox escape to host execution.

## For this project

Security issues in Breakout itself: open a GitHub private vulnerability report or email
the maintainer. We commit to a 90-day clock ourselves.
