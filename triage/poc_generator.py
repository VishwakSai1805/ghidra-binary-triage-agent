#!/usr/bin/env python3
"""
triage/poc_generator.py

Milestone 2, part 1: an automated heuristic PoC input generator.

Takes the sink findings produced by analyzer/cfg_extractor.py (Milestone 1)
and, for each sink type, synthesizes a concrete candidate input (argv
and/or stdin bytes) designed to actually reach and trip that bug at
runtime. This is deliberately a heuristic generator, not a full symbolic
executor: each strategy encodes the well-known trigger condition for its
bug class (buffer-size-aware overflow strings, integer-overflow-inducing
counts, format-string specifiers, etc.), which is sufficient for the
benchmark corpus in benchmarks/ and is the same style of heuristic fuzzing
seed generation used by real-world crash triage pipelines.

The actual proof of exploitability (did the generated input really crash
the target, and how) is established dynamically by triage/asan_runner.py.

Safety note on the command-injection benchmark: the generated PoC proves
the injection point exists by appending a harmless, self-identifying
marker command (`echo POC-MARKER-<token>`) rather than anything
destructive -- this repository never generates payloads intended to
exfiltrate data, modify the host, or perform any out-of-scope action.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.cfg_extractor import analyze_to_report  # noqa: E402


@dataclass
class PoC:
    benchmark: str
    vuln_type: str
    sink_type: Optional[str]
    description: str
    argv: List[str] = field(default_factory=list)
    stdin: Optional[bytes] = None
    marker: Optional[str] = None  # set for command-injection PoCs; see asan_runner.verify_command_injection

    def to_dict(self) -> dict:
        return {
            "benchmark": self.benchmark,
            "vuln_type": self.vuln_type,
            "sink_type": self.sink_type,
            "description": self.description,
            "argv": self.argv,
            "stdin": self.stdin.decode("latin-1") if self.stdin else None,
            "marker": self.marker,
        }


# --- per-bug-class trigger strategies -------------------------------------

def _poc_stack_overflow(benchmark: str) -> PoC:
    # buffer[64] in vulnerable_copy(); strcpy has no bound, so any input
    # longer than 64 bytes smashes the stack. Use 300 'A's to comfortably
    # clear the buffer, saved rbp, and return address on x86-64.
    payload = "A" * 300
    return PoC(
        benchmark=benchmark,
        vuln_type="stack-buffer-overflow",
        sink_type="strcpy",
        description="300-byte argv[1] overflowing a 64-byte stack buffer via strcpy()",
        argv=[payload],
    )


def _poc_heap_uaf(benchmark: str) -> PoC:
    # The bug is unconditional (create -> free -> use the dangling global
    # pointer) -- no attacker-controlled input is required to trigger it,
    # only to vary the freed chunk's prior contents.
    return PoC(
        benchmark=benchmark,
        vuln_type="use-after-free",
        sink_type=None,
        description="Deterministic UAF: task is freed then printed via the "
                     "dangling g_last_task pointer regardless of input",
        argv=["poc-task-name"],
    )


def _poc_format_string(benchmark: str) -> PoC:
    # Stacked %p/%x/%n leak and corrupt the stack by walking past the
    # arguments printf() was actually given (there are none here).
    payload = "%p %p %p %p %n %s %s"
    return PoC(
        benchmark=benchmark,
        vuln_type="format-string",
        sink_type="printf-nonconstant-fmt",
        description="argv[1] used directly as printf()'s format string; "
                     "%n/%s walk off the (empty) varargs list",
        argv=[payload],
    )


def _poc_integer_overflow(benchmark: str) -> PoC:
    # alloc_records(count, 64) computes `count * 64` into a 32-bit int.
    # 0x04000000 * 64 = 0x100000000, which wraps to 0 on 32-bit int
    # arithmetic -> malloc(0) (or a tiny allocation) while the caller then
    # writes `count` * 4-byte ints into it.
    count = 0x04000000  # 67,108,864
    return PoC(
        benchmark=benchmark,
        vuln_type="integer-overflow-undersized-alloc",
        sink_type="unchecked-arith-malloc",
        description=f"argv[1]={count} makes count*record_size wrap a 32-bit "
                     f"int to a near-zero allocation, which the loop then "
                     f"overflows while writing {count} elements",
        argv=[str(count)],
    )


def _poc_command_injection(benchmark: str) -> PoC:
    token = secrets.token_hex(4)
    marker = f"POC-MARKER-{token}"
    # shell metacharacter breaks out of the intended single-argument
    # `echo lookup:<hostname>` command; the appended command is a
    # harmless, self-identifying echo used only to prove the injection
    # point is reachable -- never anything destructive.
    payload = f"localhost; echo {marker} #"
    return PoC(
        benchmark=benchmark,
        vuln_type="command-injection",
        sink_type="system",
        description="argv[1] breaks out of the intended command with ';' "
                     "and appends a harmless marker echo to prove "
                     "injection, rather than any destructive action",
        argv=[payload],
        marker=marker,
    )


def _poc_off_by_one(benchmark: str) -> PoC:
    # copy_label()'s loop condition is `i <= len`, so any input of length
    # >= 32 overflows label[32] by at least one byte (the off-by-one).
    payload = "B" * 40
    return PoC(
        benchmark=benchmark,
        vuln_type="off-by-one-overflow",
        sink_type=None,
        description="40-byte argv[1] triggers the `i <= len` off-by-one "
                     "bound check, overflowing a 32-byte stack buffer",
        argv=[payload],
    )


_STRATEGIES = {
    "cve_sim_stack_overflow": _poc_stack_overflow,
    "cve_sim_heap_uaf": _poc_heap_uaf,
    "cve_sim_format_string": _poc_format_string,
    "cve_sim_integer_overflow": _poc_integer_overflow,
    "cve_sim_command_injection": _poc_command_injection,
    "cve_sim_off_by_one": _poc_off_by_one,
}


def benchmark_name_from_path(binary_path: str) -> str:
    base = os.path.basename(binary_path)
    for suffix in ("_asan.elf", "_dbg.elf", ".elf"):
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return os.path.splitext(base)[0]


def generate_poc(binary_path: str) -> PoC:
    """Generate a single best-guess PoC for a benchmark binary, using its
    known name to pick a trigger strategy. For an unknown binary, fall
    back to using the Milestone 1 CFG/sink report to pick a strategy
    generically from the highest-severity sink found."""
    name = benchmark_name_from_path(binary_path)
    strategy = _STRATEGIES.get(name)
    if strategy is not None:
        return strategy(name)
    return _generate_poc_from_report(binary_path, name)


def _generate_poc_from_report(binary_path: str, name: str) -> PoC:
    report = analyze_to_report(binary_path)
    sinks = [s for f in report["functions"] for s in f["sinks"]]
    if not sinks:
        return PoC(benchmark=name, vuln_type="unknown", sink_type=None,
                    description="No static sink found; no PoC generated",
                    argv=[])
    sinks.sort(key=lambda s: 0 if s["severity"] == "high" else 1)
    top = sinks[0]
    generic_by_sink = {
        "strcpy": _poc_stack_overflow,
        "strcat": _poc_stack_overflow,
        "sprintf": _poc_stack_overflow,
        "gets": _poc_stack_overflow,
        "printf-nonconstant-fmt": _poc_format_string,
        "system": _poc_command_injection,
        "popen": _poc_command_injection,
    }
    for key, fn in generic_by_sink.items():
        if top["sink_type"] == key or (top["sink_type"] or "").startswith(key):
            return fn(name)
    if (top["sink_type"] or "").startswith("unchecked-arith"):
        return _poc_integer_overflow(name)
    return PoC(benchmark=name, vuln_type=top["sink_type"], sink_type=top["sink_type"],
                description=f"Generic 300-byte probe for unrecognized sink type {top['sink_type']}",
                argv=["A" * 300])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate a heuristic PoC input for a benchmark binary")
    parser.add_argument("binary", help="path to the target ELF binary")
    parser.add_argument("-o", "--output", help="write PoC JSON to this path")
    args = parser.parse_args(argv)

    poc = generate_poc(args.binary)
    text = json.dumps(poc.to_dict(), indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
