import json
import os

import pytest

from backend.scanner import screenshot
from backend.tests.test_notifications import db, client, mk_scan  # noqa: F401 (fixtures)

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32
RUN = "run-0123456789ab"


def make_run(tmp_path, entries, files):
    run = tmp_path / RUN
    (run / "screens").mkdir(parents=True)
    for name in files:
        (run / "screens" / name).write_bytes(PNG)
    (run / "index.json").write_text(json.dumps(entries))
    return run


@pytest.fixture()
def shots(tmp_path, monkeypatch):
    monkeypatch.setenv("SCREENSHOT_DIR", str(tmp_path))
    return tmp_path


def with_run(db, name=RUN):
    scan = mk_scan(db)
    scan.module_results = {"screenshot_run": name}
    db.commit()
    return scan


# ---------------------------------------------------------------- index building

def test_index_matches_urls_and_labels_strangers(tmp_path):
    run = tmp_path / RUN
    shots = [{"file": str(run / "screens" / "https.app.example.com.8443.png"), "name": "https.app.example.com.8443.png"},
             {"file": str(run / "screens" / "http.other.test.png"), "name": "http.other.test.png"}]
    idx = screenshot.build_index(shots, ["https://app.example.com:8443"], str(run))
    by_file = {e["file"]: e for e in idx}
    a = by_file["screens/https.app.example.com.8443.png"]
    assert a["url"] == "https://app.example.com:8443" and a["host"] == "app.example.com:8443"
    b = by_file["screens/http.other.test.png"]
    assert b["url"] is None and b["host"] == "other.test"


def test_index_is_capped(tmp_path):
    shots = [{"file": str(tmp_path / f"{i:04}.png"), "name": f"{i:04}.png"} for i in range(screenshot.MAX_INDEXED + 20)]
    assert len(screenshot.build_index(shots, [], str(tmp_path))) == screenshot.MAX_INDEXED


def test_run_writes_index_and_reports_run_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(screenshot, "SCREENSHOT_DIR", str(tmp_path))

    def run(cmd, timeout=None):
        out = cmd[cmd.index("-d") + 1]
        os.makedirs(os.path.join(out, "screens"))
        open(os.path.join(out, "screens", "https.a.test.png"), "wb").write(PNG)
        import subprocess
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(screenshot, "_run_with_process_group_cleanup", run)
    r = screenshot.run_eyewitness(["https://a.test"])
    assert r["run"].startswith("run-")
    written = json.loads(open(os.path.join(r["output_dir"], "index.json")).read())
    assert written == r["index"] and written[0]["url"] == "https://a.test"


# ---------------------------------------------------------------- API

def test_list_and_fetch(client, db, shots):
    make_run(shots, [{"host": "a.test", "url": "https://a.test", "file": "screens/a.png"}], ["a.png"])
    scan = with_run(db)
    r = client.get(f"/scans/{scan.id}/screenshots").json()
    assert r["screenshots"] == [{"id": 0, "host": "a.test", "url": "https://a.test"}]
    img = client.get(f"/scans/{scan.id}/screenshots/0")
    assert img.status_code == 200 and img.headers["content-type"] == "image/png" and img.content == PNG
    assert img.headers["x-content-type-options"] == "nosniff"


def test_no_screenshots_is_an_empty_list_not_an_error(client, db, shots):
    scan = mk_scan(db)
    assert client.get(f"/scans/{scan.id}/screenshots").json()["screenshots"] == []
    assert client.get(f"/scans/{scan.id}/screenshots/0").status_code == 404
    assert client.get("/scans/9999/screenshots").status_code == 404


def test_cleaned_up_folder_is_empty(client, db, shots):
    scan = with_run(db)                                  # run folder was never created / already pruned
    assert client.get(f"/scans/{scan.id}/screenshots").json()["screenshots"] == []


@pytest.mark.parametrize("rel", ["../outside.png", "/etc/passwd", "screens/../../outside.png", "screens/a.txt", "screens/missing.png"])
def test_path_tricks_are_refused(client, db, shots, rel):
    (shots / "outside.png").write_bytes(PNG)
    make_run(shots, [{"host": "x", "url": None, "file": rel}], ["a.png"])
    (shots / RUN / "screens" / "a.txt").write_text("secret")
    scan = with_run(db)
    assert client.get(f"/scans/{scan.id}/screenshots/0").status_code == 404


@pytest.mark.parametrize("bad", ["../etc", "run-ZZZ", "run-0123456789abc", "/abs", ""])
def test_run_name_must_be_a_run_folder(client, db, shots, bad):
    scan = with_run(db, bad)
    assert client.get(f"/scans/{scan.id}/screenshots").json()["screenshots"] == []


def test_symlink_escape_is_refused(client, db, shots, tmp_path_factory):
    outside = tmp_path_factory.mktemp("o") / "secret.png"
    outside.write_bytes(PNG)
    run = make_run(shots, [{"host": "x", "url": None, "file": "screens/link.png"}], [])
    os.symlink(outside, run / "screens" / "link.png")
    scan = with_run(db)
    assert client.get(f"/scans/{scan.id}/screenshots/0").status_code == 404


def test_bad_ids_and_corrupt_index(client, db, shots):
    run = make_run(shots, [{"host": "a", "url": None, "file": "screens/a.png"}], ["a.png"])
    scan = with_run(db)
    assert client.get(f"/scans/{scan.id}/screenshots/5").status_code == 404
    assert client.get(f"/scans/{scan.id}/screenshots/-1").status_code == 404
    (run / "index.json").write_text("not json")
    assert client.get(f"/scans/{scan.id}/screenshots").json()["screenshots"] == []


def test_pipeline_records_run_folder_name_only():
    from backend import pipeline_stages as ps
    from backend.scan_profiles import get_profile
    mr = {}
    ps.collect_web_results({"dirbuster": {"module_status": "ok", "hosts": {}}, "screenshot": {"screenshots": [{}], "module_status": "ok", "run": RUN, "index": [{"x": 1}]}},
                           get_profile("standard"), True, {"hosts": {}}, mr)
    assert mr["screenshot_run"] == RUN and "index" not in mr and mr["screenshot"] == "ok"
    mr2 = {}
    ps.collect_web_results({"dirbuster": {"module_status": "ok", "hosts": {}}}, get_profile("standard"), True, {"hosts": {}}, mr2)
    assert "screenshot_run" not in mr2
