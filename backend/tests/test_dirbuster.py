from backend.scanner.dirbuster import compute_budget, _salvage, _parse_ferox_json


def test_budget_scales_with_requests_and_rate():
    assert compute_budget(2500, 10) == 340        # 250s + 30 + 60 slack
    assert compute_budget(2500, 100) == 120       # floor
    assert compute_budget(40000, 10, 2, cap=900) == 900   # capped


def test_salvage_bytes_and_none():
    assert _salvage(None) == ""
    assert _salvage(b'{"type":"response"}\n') == '{"type":"response"}\n'
    assert len(_parse_ferox_json(_salvage(b'{"type":"response","url":"http://h/a","status":200}\n{"type":"statistics"}'))) == 1


def test_ferox_cmd_scans_directory_listings():
    # regression: MS3 serves "Index of /" on port 80; without this flag feroxbuster skips the
    # wordlist and only reports links extracted from the listing
    from backend.scanner.dirbuster import _ferox_cmd
    cmd = _ferox_cmd("http://h", "/w.txt", "php", 10, 8)
    assert "--scan-dir-listings" in cmd and "--insecure" in cmd and "--rate-limit" in cmd
