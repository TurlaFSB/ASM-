from backend.scanner.dirbuster import compute_budget, _salvage, _parse_ferox_json


def test_budget_scales_with_requests_and_rate():
    assert compute_budget(2500, 10) == 340        # 250s + 30 + 60 slack
    assert compute_budget(2500, 100) == 120       # floor
    assert compute_budget(40000, 10, 2, cap=900) == 900   # capped


def test_salvage_bytes_and_none():
    assert _salvage(None) == ""
    assert _salvage(b'{"type":"response"}\n') == '{"type":"response"}\n'
    assert len(_parse_ferox_json(_salvage(b'{"type":"response","url":"http://h/a","status":200}\n{"type":"statistics"}'))) == 1
