import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_DIR = os.path.join(REPO_ROOT, "benchmarks")
BUILD_DIR = os.path.join(REPO_ROOT, "build")

sys.path.insert(0, REPO_ROOT)

BENCHMARK_NAMES = [
    "cve_sim_stack_overflow",
    "cve_sim_heap_uaf",
    "cve_sim_format_string",
    "cve_sim_integer_overflow",
    "cve_sim_command_injection",
    "cve_sim_off_by_one",
]


@pytest.fixture(scope="session", autouse=True)
def built_benchmarks():
    """Ensure every benchmark binary (stripped, _dbg, _asan) exists before
    any test runs, building them once per test session if missing."""
    missing = False
    for name in BENCHMARK_NAMES:
        for suffix in ("", "_dbg", "_asan"):
            if not os.path.exists(os.path.join(BUILD_DIR, f"{name}{suffix}.elf")):
                missing = True
    if missing:
        subprocess.run(["bash", os.path.join(BENCH_DIR, "build.sh")], check=True)
    return BUILD_DIR
