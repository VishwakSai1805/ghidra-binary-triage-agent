# Automated ELF Binary Vulnerability Triage, CFG Extractor & PoC Crash Generator

An end-to-end pipeline that takes a raw x86-64 ELF binary — symbols or not
— and automatically produces a **proven**, not guessed, vulnerability
report: static disassembly and control-flow analysis finds candidate bugs,
a heuristic generator synthesizes an input to trigger each one, and an
AddressSanitizer harness actually runs it to confirm exploitability, all
before a patch-advisor and SARIF/Markdown report writer turn the result
into something a human (or GitHub Code Scanning) can act on.

```
6/6 benchmark vulnerabilities: statically found, dynamically confirmed exploitable, with remediation generated.
```

## Why this exists

Static analyzers are fast but noisy — they flag *possible* bugs. Fuzzers
find *real* crashes but need hours of CPU and no insight into *why*. This
project closes that loop on a small, fast scale: static analysis tells you
**where to look and why**, then automated dynamic verification tells you
**whether it's actually exploitable**, in milliseconds per target, with
zero human triage in between.

## Architecture

```
┌──────────────────────┐
│ benchmarks/*.c        │  6 simulated-CVE C programs
│ + build.sh            │  → compiled 3 ways each (stripped / -g / ASan)
└───────────┬───────────┘
            │ build/*.elf
            ▼
┌──────────────────────────────────────────────────────────────────┐
│ Milestone 1 — analyzer/cfg_extractor.py                           │
│                                                                    │
│  ELF (pyelftools) ──► .text bytes + .symtab + PLT relocations     │
│       │                                                           │
│       ▼                                                           │
│  Function recovery  (symtab, or endbr64 heuristic when stripped)  │
│       │                                                           │
│       ▼                                                           │
│  Capstone disassembly ──► basic-block split ──► networkx DiGraph  │
│       │                                                           │
│       ▼                                                           │
│  Sink detection: strcpy/strcat/sprintf/gets/system/popen,         │
│  non-constant-format printf (register back-tracing), unchecked    │
│  malloc-size arithmetic ──► CFG path from entry to each sink      │
└───────────────────────────────┬──────────────────────────────────┘
                                 │ sink report (JSON)
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│ Milestone 2 — triage/                                             │
│                                                                    │
│  poc_generator.py   per-sink-class trigger strategy ──► PoC input │
│       │                                                           │
│       ▼                                                           │
│  asan_runner.py     run build/<x>_asan.elf under `timeout 5s`,    │
│                      feed the PoC, capture stdout/stderr,         │
│                      parse ASan's crash report                    │
│       │                                                           │
│       ▼                                                           │
│  orchestrator.py    verdict: CRASHED(kind) / NO_CRASH / TIMEOUT   │
│                      + marker-based proof for non-crashing bugs   │
│                      (command injection)                          │
└───────────────────────────────┬──────────────────────────────────┘
                                 │ exploit_confirmed: bool, per target
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│ Milestone 3 — reports/                                            │
│                                                                    │
│  patch_advisor.py    vuln class ──► CWE + concrete remediation    │
│  report_generator.py addr2line source attribution + SARIF 2.1.0   │
│                       + reports/security_audit_report.md          │
└────────────────────────────────────────────────────────────────┘
```

## Detection benchmark

Six hand-written C programs in `benchmarks/`, each the textbook shape of
a historical CVE class, compiled stripped / with debug symbols / under
ASan. The pipeline is run against all 18 resulting binaries.

| Benchmark | CWE | Bug class | Static detection | Dynamic proof |
|---|---|---|---|---|
| `cve_sim_stack_overflow` | CWE-121 | Stack buffer overflow (`strcpy`) | ✅ sink flagged | ✅ ASan `stack-buffer-overflow` |
| `cve_sim_heap_uaf` | CWE-416 | Heap use-after-free | — (needs dynamic proof) | ✅ ASan `heap-use-after-free` |
| `cve_sim_format_string` | CWE-134 | Uncontrolled format string | ✅ non-constant `printf` flagged | ✅ ASan crash under `%n`/`%s` probe |
| `cve_sim_integer_overflow` | CWE-190 | Integer overflow → undersized alloc | ✅ unchecked `malloc` arithmetic flagged | ✅ ASan `heap-buffer-overflow` |
| `cve_sim_command_injection` | CWE-78 | OS command injection (`system`) | ✅ sink flagged | ✅ injected marker command observed in stdout |
| `cve_sim_off_by_one` | CWE-193 | Off-by-one stack overflow | — (bounds bug, no call-sink) | ✅ ASan `stack-buffer-overflow` |

**Result: 6/6 exploits automatically confirmed**, with zero false positives
on the deliberately-included constant-format `printf()` calls the analyzer
is tested against (see `tests/test_cfg_extractor.py::test_no_false_positive_sink_on_constant_format_strings`).

The static analyzer also works on **stripped** binaries (no `.symtab`) by
recovering function boundaries from the `endbr64` CET-prologue marker
modern GCC emits — every sink test above is run against both the stripped
and debug-symbol builds.

## Quick start

```bash
pip install -r requirements.txt
./benchmarks/build.sh                 # compiles all 18 benchmark binaries into build/
pytest -q --tb=short                  # 55 passed, 6 skipped
python3 reports/report_generator.py   # regenerates the SARIF + Markdown report
```

Run any stage standalone:

```bash
# static CFG + sink report for one binary
python3 analyzer/cfg_extractor.py build/cve_sim_stack_overflow_dbg.elf

# generate a PoC for a benchmark and run it under ASan
python3 triage/poc_generator.py build/cve_sim_stack_overflow_asan.elf
python3 triage/asan_runner.py build/cve_sim_stack_overflow_asan.elf "$(python3 -c "print('A'*300)")"
```

## Repository layout

```
benchmarks/     6 simulated-CVE C programs + build.sh (stripped / -g / ASan builds)
analyzer/       Milestone 1: ELF parsing, CFG construction, sink detection
triage/         Milestone 2: PoC generation + ASan crash verification harness
reports/        Milestone 3: patch advisor + SARIF/Markdown report generator
tests/          pytest suite covering all three milestones (55 tests)
```

## Design notes & limitations

- **Heuristic, not symbolic.** The PoC generator encodes known trigger
  conditions per bug class rather than running a symbolic/concolic
  executor. This is sufficient for the benchmark corpus here and mirrors
  how real crash-triage pipelines seed fuzzers, but it will not invent a
  novel trigger for a bug shape it hasn't been taught.
- **ASan proves memory-safety bugs; it can't signal injection bugs.**
  Command injection is a semantic bug, not a memory-safety one, so its
  "exploit confirmed" signal comes from observing a harmless,
  self-identifying marker command execute via the injection point, not
  from a crash. This repository never generates destructive payloads —
  every PoC is either a bounded test string or a no-op marker echo.
- **Static analysis is a triage aid, not a soundness proof.** The sink
  detector does simple intraprocedural reachability and short
  backward register tracing (e.g. proving a `printf` format pointer
  traces back to a `lea ..., [rip+...]` string literal vs. a variable);
  it does not do full data-flow or inter-procedural taint analysis.
- Every dynamic run is hard-bounded to 5 seconds (both the external
  `timeout` wrapper and a Python-level backstop), so a hanging target can
  never stall the pipeline — verified in
  `tests/test_triage.py::test_run_target_enforces_timeout_on_a_hanging_process`.

## Tech stack

Python 3 · [Capstone](https://www.capstone-engine.org/) (disassembly) ·
[pyelftools](https://github.com/eliben/pyelftools) (ELF parsing) ·
[networkx](https://networkx.org/) (CFG graphs) · GCC + AddressSanitizer
(dynamic verification) · `addr2line`/binutils (source attribution) ·
pytest (55-test suite) · SARIF 2.1.0 (machine-readable output)
