import os

from reports.patch_advisor import advice_for_vuln_type
from reports.report_generator import build_markdown, build_sarif, collect_all_findings
from tests.conftest import BENCHMARK_NAMES


def test_patch_advice_exists_for_every_benchmark_vuln_type():
    expected_types = [
        "stack-buffer-overflow", "use-after-free", "format-string",
        "integer-overflow-undersized-alloc", "command-injection",
        "off-by-one-overflow",
    ]
    for vt in expected_types:
        advice = advice_for_vuln_type(vt)
        assert advice.cwe.startswith("CWE-")
        assert advice.recommendation


def test_collect_all_findings_covers_every_benchmark():
    findings = collect_all_findings()
    assert len(findings) == len(BENCHMARK_NAMES)
    assert {f["benchmark"] for f in findings} == set(BENCHMARK_NAMES)
    for f in findings:
        assert f["exploit_confirmed"] is True
        assert f["cwe"].startswith("CWE-")
        assert f["patch_recommendation"]


def test_sarif_output_shape():
    findings = collect_all_findings()
    sarif = build_sarif(findings)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"]
    assert len(run["results"]) == len(findings)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids


def test_markdown_report_contains_every_benchmark_and_no_sandbox_paths():
    findings = collect_all_findings()
    md = build_markdown(findings)
    for name in BENCHMARK_NAMES:
        assert name in md
    # the report must not leak this build environment's absolute paths
    assert "/home/user/" not in md
    assert "/tmp/" not in md


def test_report_files_are_written(tmp_path, monkeypatch):
    import reports.report_generator as rg
    monkeypatch.setattr(rg, "REPORTS_DIR", str(tmp_path))
    rg.main()
    assert os.path.exists(tmp_path / "security_audit.sarif")
    assert os.path.exists(tmp_path / "security_audit_report.md")
