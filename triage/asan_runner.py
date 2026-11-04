#!/usr/bin/env python3
"""
triage/asan_runner.py

Milestone 2, part 2: an AddressSanitizer-based dynamic verification
harness.

Given a target's ASan-instrumented build (benchmarks/build.sh produces
<name>_asan.elf for every benchmark) and a PoC (triage/poc_generator.py),
this module:

  1. Runs the binary under `timeout 5s` with the PoC's argv/stdin.
  2. Captures stderr, where ASan writes its crash report.
  3. Parses the ASan report for the error class (e.g.
     heap-use-after-free, stack-buffer-overflow, SEGV), the faulting
     frame, and a short backtrace.
  4. Returns a verdict: CRASHED (and how) or NO_CRASH, which is the
     automated proof-of-exploitability signal the static analyzer in
     Milestone 1 cannot provide on its own.

Every subprocess run is hard-bounded by a 5-second timeout (via Python's
own subprocess timeout AND an external `timeout` wrapper, belt-and-
suspenders) so a hanging or infinite-looping target can never stall the
pipeline.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_TIMEOUT_SECONDS = 5

_ASAN_ERROR_RE = re.compile(r"ERROR: AddressSanitizer: (?P<kind>[A-Za-z0-9_-]+)")
_ASAN_SUMMARY_RE = re.compile(r"SUMMARY: AddressSanitizer: (?P<summary>.+)")
_ASAN_FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(?P<frame>.+?)\s+\S+:\d+")
_SIGNAL_RE = re.compile(r"AddressSanitizer: (SEGV|ABRT|BUS) on unknown address")


@dataclass
class CrashReport:
    binary: str
    argv: List[str]
    returncode: Optional[int]
    timed_out: bool
    crashed: bool
    asan_error_kind: Optional[str] = None
    asan_summary: Optional[str] = None
    backtrace: List[str] = field(default_factory=list)
    raw_stderr_tail: str = ""
    stdout: str = ""

    def to_dict(self) -> dict:
        return {
            "binary": self.binary,
            "argv": self.argv,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "crashed": self.crashed,
            "asan_error_kind": self.asan_error_kind,
            "asan_summary": self.asan_summary,
            "backtrace": self.backtrace,
            "raw_stderr_tail": self.raw_stderr_tail,
            "stdout": self.stdout,
        }

    @property
    def verdict(self) -> str:
        if self.timed_out:
            return "TIMEOUT"
        if self.crashed:
            return f"CRASHED ({self.asan_error_kind or 'unknown'})"
        return "NO_CRASH"


def _parse_asan_output(stderr: str) -> dict:
    kind = None
    summary = None
    backtrace: List[str] = []

    m = _ASAN_ERROR_RE.search(stderr)
    if m:
        kind = m.group("kind")
    else:
        m = _SIGNAL_RE.search(stderr)
        if m:
            kind = m.group(1)

    m = _ASAN_SUMMARY_RE.search(stderr)
    if m:
        summary = m.group("summary").strip()

    for line in stderr.splitlines():
        fm = _ASAN_FRAME_RE.match(line)
        if fm:
            backtrace.append(fm.group("frame"))
        if len(backtrace) >= 6:
            break

    return {"kind": kind, "summary": summary, "backtrace": backtrace}


def run_target(binary_path: str, argv: Optional[List[str]] = None,
                stdin: Optional[bytes] = None,
                timeout: int = DEFAULT_TIMEOUT_SECONDS) -> CrashReport:
    """Run `binary_path` under a hard timeout, feed it `argv`/`stdin`, and
    classify the result as a crash (with ASan diagnostics), a timeout, or
    a clean exit."""
    argv = argv or []
    cmd = [binary_path] + list(argv)
    if shutil.which("timeout"):
        cmd = ["timeout", f"{timeout}s"] + cmd

    # ASan defaults tuned for deterministic, parseable single-process runs.
    env = {
        "ASAN_OPTIONS": "abort_on_error=0:exitcode=99:detect_leaks=0:halt_on_error=1",
        "PATH": "/usr/bin:/bin:/usr/local/bin",
    }

    timed_out = False
    try:
        proc = subprocess.run(
            cmd,
            input=stdin if stdin is not None else b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout + 2,  # Python-level backstop above the `timeout` wrapper
        )
        returncode = proc.returncode
        stderr = proc.stderr.decode("utf-8", errors="replace")
        stdout = proc.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace") if exc.stderr else ""
        stdout = (exc.stdout or b"").decode("utf-8", errors="replace") if exc.stdout else ""

    # The external `timeout` wrapper exits 124 when it had to kill the
    # child for exceeding the deadline -- treat that the same as Python's
    # own TimeoutExpired.
    if not timed_out and returncode == 124:
        timed_out = True

    parsed = _parse_asan_output(stderr)
    # ASan's configured exitcode (99) OR death by signal (negative
    # returncode on POSIX, or classic 128+signal) both count as a crash.
    crashed = (not timed_out) and (
        returncode == 99
        or parsed["kind"] is not None
        or (returncode is not None and returncode < 0)
        or (returncode is not None and returncode >= 128)
    )

    return CrashReport(
        binary=binary_path,
        argv=argv,
        returncode=returncode,
        timed_out=timed_out,
        crashed=crashed,
        asan_error_kind=parsed["kind"],
        asan_summary=parsed["summary"],
        backtrace=parsed["backtrace"],
        raw_stderr_tail="\n".join(stderr.splitlines()[-40:]),
        stdout=stdout,
    )


def verify_command_injection(marker: str, report: CrashReport) -> bool:
    """For bug classes that are a *semantic* vulnerability rather than a
    memory-safety one (command injection), ASan cannot signal success by
    crashing -- the proof is that an attacker-appended shell command
    actually ran. This checks for the PoC's unique marker string in the
    target's stdout."""
    return marker in report.stdout


def exploit_confirmed(vuln_type: str, report: CrashReport, marker: Optional[str] = None) -> bool:
    """Single entry point combining both proof mechanisms this harness
    supports: a memory-safety crash caught by ASan, or (for injection-
    class bugs) a marker proving an attacker-controlled command executed."""
    if vuln_type == "command-injection" and marker:
        return verify_command_injection(marker, report)
    return report.crashed


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run an ASan-instrumented target with a PoC and classify the crash")
    parser.add_argument("binary", help="path to the ASan-instrumented ELF binary")
    parser.add_argument("poc_args", nargs="*", help="argv to pass to the target")
    parser.add_argument("--stdin", help="literal string to feed on stdin")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("-o", "--output", help="write the crash report JSON to this path")
    args = parser.parse_args(argv)

    stdin_bytes = args.stdin.encode() if args.stdin is not None else None
    report = run_target(args.binary, args.poc_args, stdin_bytes, args.timeout)

    text = json.dumps(report.to_dict(), indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
    else:
        print(text)
    print(f"VERDICT: {report.verdict}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
