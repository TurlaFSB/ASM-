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
