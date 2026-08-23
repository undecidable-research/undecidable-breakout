# Changelog

## Unreleased

Correctness and honesty pass over the corpus, harness, and docs.

### Fixed
- `integrity-failopen-retry` was a false CONTAINED: the `failopen-wrapper` profile
  emitted a decorated `ESCAPED (...)` line the line-anchored oracle rejected, so the
  fail-open pattern the technique exists to catch was never detected. The wrapper now
  emits a bare `ESCAPED` marker; a unit test locks the wrapper↔oracle contract.
- `net-url-userinfo` could never fire — the `@` userinfo separator was eaten by token
  substitution (`example@@CANARY_HOST@@`), building an unresolvable host. Fixed to
  `@@@CANARY_HOST@@`; it now escapes on a loose profile and is contained on a tight
  one, so it is promoted into the accuracy harness (ground truth 91 → **94 checks**,
  30 → 31 ground-truthed techniques).
- `fs-sys-writable` always SKIPPED (its probe created a file at the sysfs root, which
  the kernel forbids universally); it now checks writability of real escape-relevant
  sysfs attributes non-destructively.
- `integrity-no-sandbox-indicator` no longer falls through to `ESCAPED` on a `stat`
  read error (fails closed); `fs-proc-pid1-cmdline` uses a correct `tr '\0'`.
- Report evidence redacts the planted decoy secret value and the host decoy path, so
  a shared `report.json`/`report.html` no longer trips secret scanners or leaks the
  OS username.
- `breakout diff` no longer counts a technique going to/from `SKIPPED` as an
  "improvement" (lost coverage is not a win).
- The runner restores the planted decoy env var after a run instead of leaving it in
  an in-process caller's environment.

### Changed
- Several `net`/`fs` technique descriptions reworded to state exactly what they prove
  (the HTTP L7 probes measure egress reachability carrying the trick bytes, not a
  proxy parser differential; `fs-proc-environ` measures env-scrubbing of an injected
  marker). README gains a hostile-sandbox / IDS / executable-content safety note and
  states selftest coverage honestly (31 of 45 techniques ground-truthed).

## 0.3.0 — 2026-08-22

Corpus 31 → 45 techniques, each new verdict either ground-truthed in the accuracy
harness or explicitly exempted, and a palette case study built from a real measured run.

### Added
- 14 techniques: writable `/etc`, `/proc/self/environ` secret leak, host-init
  visibility via `/proc/1/cmdline`, setuid-surface inventory, alternative IP-literal
  encodings, backslash-authority confusion, CRLF request-line injection, egress on a
  nonstandard DNS port (853/DoT), redirect-following egress, signals to a shared PID
  namespace, unprivileged user-namespace creation, **Docker-socket reachability**
  (the canonical escape), **SCM_RIGHTS file-descriptor passing**, and **DNS rebinding**
  (TTL flip after the allowlist check).
- Canary gained a tiny UDP DNS responder (for the rebinding technique) and now
  credits absolute-form request targets, so authority-confusion probes that actually
  reach it are scored instead of silently missed.
- A credential-shaped env var is planted into every launched context, so
  `fs-proc-environ` measures whether the boundary scrubs env secrets (Docker does not).
- `selftest` ground truth grows 48 → **91 assertions** (16 → 30 techniques, plus a
  `sock-exposed` fixture that proves the Docker-socket escape); CI now runs it on
  every push, holding the tool to the same standard it holds sandboxes. (Later raised
  to 94 assertions / 31 techniques — see Unreleased.)
- Unit-test coverage guard: a new technique must be ground-truthed or explicitly
  exempted, so nothing joins the corpus without a verification decision.
- README case-study charts, generated from the measured report in the five-grey
  palette (`scripts/make_charts.py`, committed to `docs/assets/`).

### Changed
- Docker contexts now default to `python:3.12-alpine` (python3 + busybox): a
  container that can actually run code, the realistic threat model — an empty Alpine
  cannot exercise the SSRF/parser-differential corpus at all.

### Fixed
- `probe_bins` retries once: a transient container-start hiccup can no longer read as
  "binary missing" and silently turn a real ESCAPED/CONTAINED into SKIPPED.

## 0.2.1 — 2026-08-22

Docs and report polish, one real scoring bug fixed.

### Added
- Redesigned self-contained HTML report and leaderboard page: summary score
  cards, score bars, category chips, evidence details.
- `run` prints an ASCII score bar per profile.
- README: badges, 60-second self-check path, determinism check, FAQ.
- `preflight()` is now applied to docker/bwrap/custom launchers: a wrapper that
  cannot even start (missing binary, bad config, daemon down) is SKIPPED with
  the reason instead of silently scoring CONTAINED on every technique.

### Fixed
- Custom/bwrap/none profiles on non-POSIX hosts now skip at context build with
  a single clear reason (was per-probe).
- Canary closes its sockets on stop (no more ResourceWarnings in tests).

## 0.2.0 — 2026-08-22

Corpus 16 → 31 techniques, new sandbox adapters, CI-measured leaderboard.

### Added
- 15 techniques: DNS over TCP (CVE-2026-32946 class), DNS tunneling,
  arbitrary-resolver egress, QUIC/UDP-443, ICMP channel, URL userinfo parser
  differential, IPv4-mapped IPv6 literals, hardlink escape, writable /sys,
  CAP_MKNOD device creation, LD_PRELOAD sanitization, ptrace attach, TIOCSTI,
  dangerous CapEff bits, kernel keyring visibility.
- `landlock` profile kind: bundled C helper (`breakout/sandboxes/landlock.c`)
  compiled on demand with `cc`; fails closed (exit 126) so an unsupported
  kernel yields SKIPPED, never unsandboxed execution.
- Profiles `landlock-strict`, `seatbelt-strict` (macOS-gated), `nono`, `fence`.
- Per-profile gates: `os = [...]` and `requires = [...]`; unavailable profiles
  are SKIPPED with the reason.
- Per-technique `timeout` in technique TOML.
- CI: `leaderboard.yml` (measures every measurable profile on ubuntu-24.04, commits
  the refreshed leaderboard) and `breakout-sarif.yml` (ESCAPED findings as SARIF
  annotations on PRs).

### Fixed
- Canary oracle no longer counts hits registered before a probe started
  (prevented baseline hits from polluting sandbox verdicts).
- Canary `stop()` deadlocked when called without `start()`.

## 0.1.0 — 2026-08-22

Initial release: paired runner, 16 techniques, 6 profiles, JSON/HTML/SARIF
reports, `diff` CI gate, leaderboard generator, `verify` self-check.
