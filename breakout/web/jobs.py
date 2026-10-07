"""Run manager for the `--allow-runs` localhost mode.

One run at a time, executed as a subprocess with an argv list (never a shell
string), output captured and capped. Disabled by default; the server only turns
it on when bound to loopback. The HTTP layer builds the argv from the same
validated parameters /compose uses, so nothing the client sends reaches a shell.
"""
import shlex
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

LOG_CAP = 64 * 1024        # keep the tail of a run's output, not an unbounded buffer
MAX_RECORDS = 50           # recent runs retained in memory
MAX_PENDING = 4            # queued + running ceiling, so a UI cannot pile work up


class RunManager:
    def __init__(self, reports_root, enabled=False, out_subdir="ui-runs"):
        self.enabled = enabled
        self.reports_root = Path(reports_root)
        self.out_subdir = out_subdir
        self._runs = {}
        self._order = deque()
        self._lock = threading.Lock()
        self._worker = None

    # ---- introspection -----------------------------------------------------
    def _public(self, rec):
        return {k: rec[k] for k in ("id", "status", "command", "out", "report",
                                    "created", "started", "finished", "exit_code",
                                    "error")}

    def get(self, rid):
        with self._lock:
            rec = self._runs.get(rid)
            if rec is None:
                return None
            pub = self._public(rec)
            pub["log"] = rec["log"]
        return pub

    def list(self):
        with self._lock:
            return [self._public(self._runs[r]) for r in reversed(self._order)
                    if r in self._runs]

    def _pending(self):
        return sum(1 for r in self._order
                   if self._runs.get(r, {}).get("status") in ("queued", "running"))

    # ---- submission --------------------------------------------------------
    def submit(self, plan):
        """plan: the dict from views.build_run (valid=True). Forces the output into
        the served reports directory so the result shows up in the frontend and no
        client-chosen path is ever written."""
        if not self.enabled:
            return None, "runs are disabled (start with --allow-runs on a loopback bind)"
        with self._lock:
            if self._pending() >= MAX_PENDING:
                return None, f"too many runs pending (limit {MAX_PENDING}); wait for one to finish"
            rid = time.strftime("%Y%m%dT%H%M%S") + f"-{len(self._order) % 1000:03d}"
            out_dir = self.reports_root / self.out_subdir / rid
            exec_argv = plan["_argv_with"](str(out_dir),
                                           cli=[sys.executable, "-m", "breakout.cli"])
            # the command string shown to the user uses the real out dir it ran with
            display = plan["_argv_with"](f"{self.reports_root.name}/{self.out_subdir}/{rid}")
            rec = {"id": rid, "status": "queued", "argv": exec_argv,
                   "command": shlex.join(display),
                   "out": f"{self.out_subdir}/{rid}",
                   "report": f"{self.out_subdir}/{rid}/report.json",
                   "created": _now(), "started": None, "finished": None,
                   "exit_code": None, "error": None, "log": ""}
            self._runs[rid] = rec
            self._order.append(rid)
            self._prune_locked()
            self._ensure_worker_locked()
        return self._public(rec), None

    def _prune_locked(self):
        while len(self._order) > MAX_RECORDS:
            old = self._order.popleft()
            if self._runs.get(old, {}).get("status") in ("queued", "running"):
                self._order.append(old)  # never drop live work
                break
            self._runs.pop(old, None)

    def _ensure_worker_locked(self):
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._loop, name="breakout-runs",
                                            daemon=True)
            self._worker.start()

    # ---- execution ---------------------------------------------------------
    def _next_queued(self):
        with self._lock:
            for rid in self._order:
                if self._runs[rid]["status"] == "queued":
                    return rid
        return None

    def _loop(self):
        while True:
            rid = self._next_queued()
            if rid is None:
                return
            self._execute(rid)

    def _execute(self, rid):
        with self._lock:
            rec = self._runs[rid]
            rec["status"] = "running"
            rec["started"] = _now()
            argv = list(rec["argv"])
        out_dir = self.reports_root / self.out_subdir / rid
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=str(Path.cwd()),
                                    text=True, bufsize=1)
        except OSError as e:
            self._finish(rid, None, f"could not start: {e}")
            return
        buf = ""
        with proc:
            for line in proc.stdout:
                buf = (buf + line)[-LOG_CAP:]
                with self._lock:
                    self._runs[rid]["log"] = buf
            code = proc.wait()
        self._finish(rid, code, None)

    def _finish(self, rid, code, error):
        with self._lock:
            rec = self._runs[rid]
            rec["exit_code"] = code
            rec["error"] = error
            rec["finished"] = _now()
            rec["status"] = "error" if error else ("done" if code == 0 else "failed")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")
