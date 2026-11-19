#!/usr/bin/env python3
"""
triage/orchestrator.py

Ties the Milestone 2 pieces together: generate a PoC for a benchmark
(poc_generator), run it against the ASan build under a hard timeout
(asan_runner), and produce a single exploitability verdict per target.
Used by the pytest suite and by reports/ (Milestone 3) to build the
final audit report.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from triage.asan_runner import CrashReport, exploit_confirmed, run_target
from triage.poc_generator import PoC, benchmark_name_from_path, generate_poc

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR = os.path.join(REPO_ROOT, "build")


@dataclass
class TriageResult:
    benchmark: str
    poc: PoC
    report: CrashReport
    exploit_confirmed: bool

    def to_dict(self) -> dict:
        return {
            "benchmark": self.benchmark,
            "poc": self.poc.to_dict(),
            "runtime": self.report.to_dict(),
            "verdict": self.report.verdict,
            "exploit_confirmed": self.exploit_confirmed,
        }


def triage_benchmark(name: str, build_dir: str = BUILD_DIR, timeout: int = 5) -> TriageResult:
    """Full pipeline for one benchmark: use the stripped release build to
    generate/validate the static PoC strategy's naming, then actually
    execute the PoC against the ASan build to get a dynamic verdict."""
    asan_path = os.path.join(build_dir, f"{name}_asan.elf")
    poc = generate_poc(asan_path)
    stdin_bytes = poc.stdin
    report = run_target(asan_path, poc.argv, stdin_bytes, timeout=timeout)
    confirmed = exploit_confirmed(poc.vuln_type, report, poc.marker)
    return TriageResult(benchmark=name, poc=poc, report=report, exploit_confirmed=confirmed)
