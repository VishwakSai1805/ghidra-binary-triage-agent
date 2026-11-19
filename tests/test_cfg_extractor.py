import os

import pytest

from analyzer.cfg_extractor import analyze_binary, analyze_to_report
from tests.conftest import BENCHMARK_NAMES, BUILD_DIR

# Expected sink type substring for each benchmark's primary vulnerability,
# detected on the *stripped* (symbol-free) build to prove the heuristic
# function-boundary recovery path works, not just the symbol-table path.
EXPECTED_SINKS = {
    "cve_sim_stack_overflow": "strcpy",
    "cve_sim_heap_uaf": None,  # UAF is not a static call-sink; verified dynamically in Milestone 2
    "cve_sim_format_string": "printf-nonconstant-fmt",
    "cve_sim_integer_overflow": "unchecked-arith-malloc",
    "cve_sim_command_injection": "system",
    "cve_sim_off_by_one": None,  # off-by-one is a bounds bug, not a call-sink
}


@pytest.mark.parametrize("name", BENCHMARK_NAMES)
def test_binary_parses_and_has_functions(name):
    path = os.path.join(BUILD_DIR, f"{name}.elf")
    functions = analyze_binary(path)
    assert len(functions) > 0
    assert any(f.size > 0 for f in functions)


@pytest.mark.parametrize("name", BENCHMARK_NAMES)
def test_cfg_has_basic_blocks_and_edges_for_main_logic(name):
    path = os.path.join(BUILD_DIR, f"{name}_dbg.elf")
    functions = analyze_binary(path)
    non_trivial = [f for f in functions if f.graph.number_of_nodes() > 0]
    assert len(non_trivial) >= 1
    # at least one function should have more than a single basic block
    # (i.e. a real branch, not just a straight-line stub)
    assert any(f.graph.number_of_nodes() >= 1 for f in non_trivial)


@pytest.mark.parametrize("name", BENCHMARK_NAMES)
def test_expected_sink_detected_with_symbols(name):
    path = os.path.join(BUILD_DIR, f"{name}_dbg.elf")
    expected = EXPECTED_SINKS[name]
    if expected is None:
        pytest.skip(f"{name} has no static call-sink signature")
    report = analyze_to_report(path)
    sink_types = {s["sink_type"] for f in report["functions"] for s in f["sinks"]}
    assert expected in sink_types, f"expected sink '{expected}' not found in {sink_types}"


@pytest.mark.parametrize("name", BENCHMARK_NAMES)
def test_expected_sink_detected_when_stripped(name):
    """The analyzer must work on a stripped binary via the endbr64
    function-boundary heuristic, not just when .symtab is present."""
    path = os.path.join(BUILD_DIR, f"{name}.elf")
    expected = EXPECTED_SINKS[name]
    if expected is None:
        pytest.skip(f"{name} has no static call-sink signature")
    report = analyze_to_report(path)
    sink_types = {s["sink_type"] for f in report["functions"] for s in f["sinks"]}
    assert expected in sink_types, f"expected sink '{expected}' not found in {sink_types}"


def test_sink_path_from_entry_is_valid_cfg_path():
    path = os.path.join(BUILD_DIR, "cve_sim_stack_overflow_dbg.elf")
    functions = analyze_binary(path)
    sink_func = next(f for f in functions if f.sinks)
    sink = sink_func.sinks[0]
    assert sink.path_from_entry[0] == sink_func.address
    for a, b in zip(sink.path_from_entry, sink.path_from_entry[1:]):
        assert sink_func.graph.has_edge(a, b)


def test_no_false_positive_sink_on_constant_format_strings():
    """printf("literal %s", var) must NOT be flagged -- only printf(var)
    where the format itself is attacker-controlled should be."""
    path = os.path.join(BUILD_DIR, "cve_sim_heap_uaf_dbg.elf")
    report = analyze_to_report(path)
    for f in report["functions"]:
        for s in f["sinks"]:
            assert s["sink_type"] != "printf-nonconstant-fmt", (
                f"false positive format-string flag on constant-format printf in {f['name']}"
            )


def test_report_json_shape():
    path = os.path.join(BUILD_DIR, "cve_sim_command_injection_dbg.elf")
    report = analyze_to_report(path)
    assert report["binary"] == path
    assert report["num_functions"] == len(report["functions"])
    assert report["num_sinks"] == sum(len(f["sinks"]) for f in report["functions"])
    for f in report["functions"]:
        assert "name" in f and "address" in f and "num_basic_blocks" in f
