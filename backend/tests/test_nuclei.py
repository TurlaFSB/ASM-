import json
from backend.scanner.vuln import _read_findings, _summarize


def test_read_findings_and_summary(tmp_path):
    p = tmp_path / "out.jsonl"
    p.write_text(
        json.dumps({"host": "h", "template-id": "CVE-2021-1", "matched-at": "http://h/x",
                    "info": {"name": "n", "severity": "high",
                             "classification": {"cve-id": ["CVE-2021-1"], "cvss-score": 8.1}}}) + "\n"
        + "not json\n"
        + json.dumps({"host": "h", "template-id": "t2", "info": {"name": "m", "severity": "medium"}}) + "\n"
        + '{"host": "truncated by timeo'   # partial last line after a kill
    )
    f = _read_findings(str(p))
    assert [x["template_id"] for x in f] == ["CVE-2021-1", "t2"]
    assert f[0]["cve_id"] == "CVE-2021-1"
    r = {"findings": f}
    _summarize(r)
    assert r["total"] == 2 and r["severity_counts"] == {"high": 1, "medium": 1}


def test_read_findings_missing_file():
    assert _read_findings("/nonexistent") == []
