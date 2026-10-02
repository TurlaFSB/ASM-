from backend.scanner.portscan import build_nmap_cmd, parse_nmap_xml


def test_no_min_rate_and_sane_cap():
    cmd = build_nmap_cmd("192.168.16.128", 10)
    assert "--min-rate" not in cmd
    assert cmd[cmd.index("--max-rate") + 1] == "500"
    assert cmd[-1] == "192.168.16.128"


def test_host_timeout_generous():
    cmd = build_nmap_cmd("example.com", 10)
    assert int(cmd[cmd.index("--host-timeout") + 1].rstrip("s")) >= 300


def test_parse_open_ports():
    xml = ('<?xml version="1.0"?><nmaprun><host><ports>'
           '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="6.6"/></port>'
           '<port protocol="tcp" portid="23"><state state="closed"/></port>'
           '</ports></host></nmaprun>')
    ports = parse_nmap_xml(xml)
    assert [p["port"] for p in ports] == [22]


def test_top_ports_plus_extras_uses_nmap_frequency_table(tmp_path):
    from backend.scanner.portscan import EXTRA_PORTS, _port_args, top_tcp_ports
    svc = tmp_path / "nmap-services"
    svc.write_text("# comment\nhttp 80/tcp 0.48\nssh 22/tcp 0.18\ndomain 53/udp 0.30\nsmtp 25/tcp 0.13\n")
    assert top_tcp_ports(2, [str(svc)]) == [80, 22]                    # tcp only, by frequency
    rows = "\n".join(f"svc{i} {i}/tcp {1 - i / 100000:.6f}" for i in range(1, 1201))
    big = tmp_path / "big"; big.write_text(rows)
    a = _port_args("1000+", [str(big)])
    ports = {int(x) for x in a[1].split(",")}
    assert a[0] == "-p" and set(EXTRA_PORTS) <= ports and 1 in ports and len(ports) >= 1000


def test_top_ports_plus_falls_back_when_table_missing(tmp_path):
    from backend.scanner.portscan import _port_args
    assert _port_args("1000+", [str(tmp_path / "nope")]) == ["--top-ports", "1000"]


def test_version_intensity_is_clamped_and_replaces_light_flag():
    cmd = build_nmap_cmd("h", 10, "100", 60, version_intensity=5)
    assert cmd[cmd.index("--version-intensity") + 1] == "5" and "--version-light" not in cmd
    assert build_nmap_cmd("h", 10, "100", 60, version_intensity=99)[
        build_nmap_cmd("h", 10, "100", 60, version_intensity=99).index("--version-intensity") + 1] == "9"


def test_profiles_scan_depth_ladder():
    from backend.scan_profiles import PROFILES
    assert [PROFILES[n].nmap_version_intensity for n in ("quick", "standard", "deep")] == [2, 5, 7]
    assert PROFILES["standard"].nmap_ports == "1000+"
