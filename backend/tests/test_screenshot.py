import os
import subprocess

from backend.scanner import screenshot


def _fake_run(calls):
    def run(cmd, timeout=None):
        out = cmd[cmd.index("-d") + 1]
        calls.append(out)
        assert not os.path.exists(out), "EyeWitness must be given a directory that does not exist yet"
        os.makedirs(os.path.join(out, "screens"))
        open(os.path.join(out, "screens", "a.png"), "wb").close()
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return run


def test_each_run_uses_a_fresh_subdirectory_and_ignores_old_pictures(tmp_path, monkeypatch):
    monkeypatch.setattr(screenshot, "SCREENSHOT_DIR", str(tmp_path))
    (tmp_path / "old.png").write_bytes(b"x")           # left behind by an earlier scan
    calls = []
    monkeypatch.setattr(screenshot, "_run_with_process_group_cleanup", _fake_run(calls))

    first = screenshot.run_eyewitness(["https://a.test"])
    second = screenshot.run_eyewitness(["https://a.test"])

    assert calls[0] != calls[1] and all(c.startswith(str(tmp_path)) for c in calls)
    assert [s["name"] for s in first["screenshots"]] == ["a.png"]       # old.png is not counted
    assert [s["name"] for s in second["screenshots"]] == ["a.png"]
    assert first["output_dir"] == calls[0]
    assert first["module_status"] == "ok"


def test_failure_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(screenshot, "SCREENSHOT_DIR", str(tmp_path))
    monkeypatch.setattr(screenshot, "_run_with_process_group_cleanup",
                        lambda cmd, timeout=None: subprocess.CompletedProcess(cmd, 1, "", "boom"))
    r = screenshot.run_eyewitness(["https://a.test"])
    assert r["module_status"] == "failed" and r["screenshots"] == []
