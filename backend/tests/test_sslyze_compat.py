"""sslyze declares `cryptography<47` but ASM runs it with a newer, patched cryptography (see requirements-sslyze.txt).
That combination is outside sslyze's own metadata, so this test proves it on every run with a REAL TLS scan, and
fails loudly if a future cryptography or sslyze release breaks it."""
import datetime
import socket
import ssl
import threading

import cryptography
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.scanner.sslyze_scan import run_sslyze


def _self_signed(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    c, k = tmp_path / "c.pem", tmp_path / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    return str(c), str(k)


@pytest.fixture()
def tls_server(tmp_path):
    cert, key = _self_signed(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    srv.settimeout(0.2)
    stop = threading.Event()

    def handle(conn):
        try:
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.settimeout(2)
                s.recv(1024)
        except (OSError, ssl.SSLError):
            pass

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield srv.getsockname()[1]
    stop.set()
    t.join(2)
    srv.close()


def test_runs_with_the_patched_cryptography():
    assert int(cryptography.__version__.split(".")[0]) >= 50, "requirements.txt pins the patched cryptography"


def test_sslyze_completes_a_real_scan_with_it(tls_server):
    out = run_sslyze([("localhost", tls_server)])
    assert out["module_status"].startswith("ok"), out
    assert isinstance(out["findings"], list)
