from backend.scanner.dirbuster import compute_process_timeout, _salvage, _parse_ferox_json


def test_timeout_scales_with_wordlist_and_rate():
    assert compute_process_timeout(2500, 10, False) == 310     # 250s + 60s slack
    assert compute_process_timeout(2500, 100, False) == 120    # floor
    assert compute_process_timeout(4700, 10, True, cap=900) == 900  # capped


def test_salvage_bytes_and_none():
    assert _salvage(None) == ""
    assert _salvage(b'{"type":"response"}\n') == '{"type":"response"}\n'
    assert len(_parse_ferox_json(_salvage(b'{"type":"response","url":"http://h/a","status":200}\n{"type":"statistics"}'))) == 1
