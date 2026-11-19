import os

import pytest

from tests.conftest import BENCHMARK_NAMES, BUILD_DIR
from triage.asan_runner import exploit_confirmed, run_target
from triage.orchestrator import triage_benchmark
from triage.poc_generator import generate_poc

EXPECTED_ASAN_KIND = {
    "cve_sim_stack_overflow": "stack-buffer-overflow",
    "cve_sim_heap_uaf": "heap-use-after-free",
    "cve_sim_format_string": None,  # may be SEGV or a different ASan class depending on libc/stack layout
    "cve_sim_integer_overflow": "heap-buffer-overflow",
    "cve_sim_command_injection": None,  # not a memory-safety bug; proven via marker, not a crash
    "cve_sim_off_by_one": "stack-buffer-overflow",
}


@pytest.mark.parametrize("name", BENCHMARK_NAMES)
def test_poc_generated_for_every_benchmark(name):
    asan_path = os.path.join(BUILD_DIR, f"{name}_asan.elf")
    poc = generate_poc(asan_path)
    assert poc.benchmark == name
    assert poc.vuln_type != "unknown"


@pytest.mark.parametrize("name", BENCHMARK_NAMES)
def test_poc_runs_within_timeout_and_is_classified(name):
    asan_path = os.path.join(BUILD_DIR, f"{name}_asan.elf")
    poc = generate_poc(asan_path)
    report = run_target(asan_path, poc.argv, poc.stdin, timeout=5)
    assert report.timed_out is False, "benchmark PoC must never hang past the 5s budget"


@pytest.mark.parametrize("name", BENCHMARK_NAMES)
def test_exploit_confirmed_for_every_benchmark(name):
    """This is the core Milestone 2 guarantee: every simulated-CVE
    benchmark's generated PoC is automatically proven exploitable --
    either by an ASan-caught crash, or (command injection) by a marker
    showing an injected shell command actually executed."""
    result = triage_benchmark(name)
    assert result.exploit_confirmed, (
        f"{name}: expected exploit confirmation, got verdict={result.report.verdict} "
        f"stderr_tail={result.report.raw_stderr_tail!r}"
    )


@pytest.mark.parametrize("name", BENCHMARK_NAMES)
def test_asan_error_kind_matches_expected_bug_class(name):
    expected = EXPECTED_ASAN_KIND[name]
    if expected is None:
        pytest.skip(f"{name} has no single fixed ASan error class to assert on")
    result = triage_benchmark(name)
    assert result.report.asan_error_kind == expected


def test_command_injection_marker_appears_in_stdout_not_a_crash():
    result = triage_benchmark("cve_sim_command_injection")
    assert result.poc.marker in result.report.stdout
    assert result.report.crashed is False  # confirmed by marker, not by ASan


def test_backtrace_is_captured_for_memory_safety_crashes():
    result = triage_benchmark("cve_sim_heap_uaf")
    assert result.report.crashed
    assert len(result.report.backtrace) > 0
    assert any("print_task" in frame for frame in result.report.backtrace)


def test_run_target_enforces_timeout_on_a_hanging_process(tmp_path):
    # Build a tiny binary that sleeps longer than the timeout, and assert
    # the harness kills it and reports TIMEOUT rather than hanging.
    import subprocess
    src = tmp_path / "hang.c"
    src.write_text("#include <unistd.h>\nint main(){ sleep(30); return 0; }\n")
    binpath = tmp_path / "hang.elf"
    subprocess.run(["gcc", "-O0", "-o", str(binpath), str(src)], check=True)

    report = run_target(str(binpath), [], None, timeout=2)
    assert report.timed_out is True
    assert report.crashed is False


def test_exploit_confirmed_helper_crash_path():
    from triage.asan_runner import CrashReport
    cr = CrashReport(binary="x", argv=[], returncode=99, timed_out=False, crashed=True,
                      asan_error_kind="heap-use-after-free")
    assert exploit_confirmed("use-after-free", cr) is True


def test_exploit_confirmed_helper_injection_path():
    from triage.asan_runner import CrashReport
    cr = CrashReport(binary="x", argv=[], returncode=0, timed_out=False, crashed=False,
                      stdout="lookup:localhost\nPOC-MARKER-abc\n")
    assert exploit_confirmed("command-injection", cr, marker="POC-MARKER-abc") is True
    assert exploit_confirmed("command-injection", cr, marker="NOT-PRESENT") is False
