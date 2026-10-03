import datetime
import http.server
import ssl
import threading

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend import safe_http
from backend.safe_http import pinned_post, resolve_public_ips


def _cert(tmp_path, name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .sign(key, hashes.SHA256()))
    crt, k = tmp_path / "c.pem", tmp_path / "k.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    return str(crt), str(k)


@pytest.fixture()
def tls_server(tmp_path):
    seen = {}
    sni = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            seen["host"], seen["body"] = self.headers.get("Host"), self.rfile.read(n)
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *a): pass

    crt, key = _cert(tmp_path, "hooks.example.test")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.sni_callback = lambda sock, name, c: sni.__setitem__("name", name)
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], crt, seen, sni
    srv.shutdown()


def test_connects_to_pinned_ip_but_verifies_and_sends_original_hostname(tls_server):
    port, crt, seen, sni = tls_server
    # DNS "resolves" to loopback only for the test; a hostile resolver cannot be consulted again.
    resolver = lambda url: ("hooks.example.test", port, ["127.0.0.1"])
    r = pinned_post(f"https://hooks.example.test:{port}/x", b"{}", {"Content-Type": "application/json"},
                    timeout=5, resolver=resolver, verify=crt)
    assert r.status_code == 200
    assert seen["host"] == f"hooks.example.test:{port}"
    assert sni["name"] == "hooks.example.test"


def test_certificate_must_match_original_hostname(tls_server):
    port, crt, _, _ = tls_server
    resolver = lambda url: ("other.example.test", port, ["127.0.0.1"])
    with pytest.raises(requests.exceptions.SSLError):
        pinned_post(f"https://other.example.test:{port}/x", b"{}", {}, timeout=5, resolver=resolver, verify=crt)


def test_falls_through_to_next_address(tls_server):
    port, crt, seen, _ = tls_server
    # first address refuses the connection, second is the real server
    resolver = lambda url: ("hooks.example.test", port, ["127.0.0.2", "127.0.0.1"])
    r = pinned_post(f"https://hooks.example.test:{port}/x", b"{}", {}, timeout=5, resolver=resolver, verify=crt)
    assert r.status_code == 200


def test_resolution_uses_single_lookup_and_rejects_private(monkeypatch):
    calls = []

    def fake(host, port, proto=None):
        calls.append(host)
        return [(2, 1, 6, "", ("10.0.0.5", port))]

    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake)
    with pytest.raises(ValueError):
        resolve_public_ips("https://rebind.example/x")
    assert calls == ["rebind.example"]


def test_mixed_public_and_private_answers_rejected(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo",
                        lambda h, p, proto=None: [(2, 1, 6, "", ("8.8.8.8", p)), (2, 1, 6, "", ("169.254.169.254", p))])
    with pytest.raises(ValueError):
        resolve_public_ips("https://mixed.example/x")


def test_post_never_follows_redirect_and_blocks_before_connecting(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda h, p, proto=None: [(2, 1, 6, "", ("127.0.0.1", p))])
    with pytest.raises(ValueError):
        pinned_post("https://evil.example/x", b"{}", {}, timeout=1)
