#!/usr/bin/env python3
"""Test PKI for the trust features (never use these keys for real work).

  python tests/fake_tsa.py certs <dir>           writes ca.pem, tsa.pem, examiner.p12 (password "test")
  python tests/fake_tsa.py serve <dir> [port]    RFC 3161 time-stamping server on 127.0.0.1 (prints the URL)

Used by the test suites of both profiles because the real TSAs are not reachable from CI sandboxes.
"""

from __future__ import annotations

import datetime as dt
import http.server
import sys
import threading
from pathlib import Path

from asn1crypto import keys, tsp, x509
from cryptography import x509 as cx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PASSWORD = b"test"


def _name(cn: str) -> cx.Name:
    return cx.Name([cx.NameAttribute(NameOID.COMMON_NAME, cn), cx.NameAttribute(NameOID.ORGANIZATION_NAME, "Rakvor TEST")])


def _cert(subject, issuer, key, issuer_key, ca=False, eku=None):
    now = dt.datetime.now(dt.UTC)
    b = (
        cx.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(cx.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(cx.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if eku:
        b = b.add_extension(cx.ExtendedKeyUsage([eku]), critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def make_certs(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = _cert(_name("Rakvor TEST CA"), _name("Rakvor TEST CA"), ca_key, ca_key, ca=True)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa = _cert(_name("Rakvor TEST TSA"), ca.subject, tsa_key, ca_key, eku=ExtendedKeyUsageOID.TIME_STAMPING)
    ex_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ex = _cert(_name("Ana Ruiz (TEST examiner)"), ca.subject, ex_key, ca_key)
    pem = serialization.Encoding.PEM
    (out / "ca.pem").write_bytes(ca.public_bytes(pem))
    (out / "tsa.pem").write_bytes(tsa.public_bytes(pem))
    (out / "tsa.key").write_bytes(tsa_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (out / "examiner.p12").write_bytes(
        pkcs12.serialize_key_and_certificates(b"examiner", ex_key, ex, [ca], serialization.BestAvailableEncryption(PASSWORD))
    )


def serve(cert_dir: Path, port: int = 0) -> tuple[http.server.HTTPServer, str]:
    from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper

    tsa_cert = x509.Certificate.load(cx.load_pem_x509_certificate((cert_dir / "tsa.pem").read_bytes()).public_bytes(serialization.Encoding.DER))
    key = serialization.load_pem_private_key((cert_dir / "tsa.key").read_bytes(), password=None)
    tsa_key = keys.PrivateKeyInfo.load(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    stamper = DummyTimeStamper(tsa_cert=tsa_cert, tsa_key=tsa_key)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            resp = stamper.request_tsa_response(tsp.TimeStampReq.load(body)).dump()
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def log_message(self, *args):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/tsr"


if __name__ == "__main__":
    cmd, d = sys.argv[1], Path(sys.argv[2])
    if cmd == "certs":
        make_certs(d)
        print(d / "examiner.p12")
    elif cmd == "serve":
        if not (d / "tsa.pem").exists():
            make_certs(d)
        srv, url = serve(d, int(sys.argv[3]) if len(sys.argv) > 3 else 0)
        print(url, flush=True)
        threading.Event().wait()
