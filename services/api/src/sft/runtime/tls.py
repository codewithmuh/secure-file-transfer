"""TLS on the API's public port (encryption and keys 2.2, #184).

The load balancer's target group sends HTTPS to the pods' port 8000; the operator API's port-forward
reaches its 8000 the same way. `PUBLIC_TLS` picks the certificate:

- `generated`, in AWS: at start the process makes an ECDSA P-256 key and a self-signed certificate
  for its host name, valid a year, and keeps the key in memory only. The load balancer doesn't
  validate target certificates, so this encrypts the hop without authenticating it; security
  groups and network policies decide who reaches the pod (2.2). A restart makes a new one.
- `files`: a certificate and key from files, such as a cluster issuer's mounted Secret, or the
  self-signed issuer of the end-to-end TLS test.
- `off`: plain HTTP, only for the local stack, where the browser talks to localhost.

Either way the context allows TLS 1.2 and 1.3 only, and in 1.2 only forward-secret AEAD suites:
the load balancer offers TLS 1.0 and up to targets, so the pod enforces the minimum (2.2). The
internal port (probes, metrics, the target group's health check) stays plain HTTP.
"""

from __future__ import annotations

import contextlib
import datetime
import os
import socket
import ssl
import sys
import tempfile
from collections.abc import Iterator
from typing import Final, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

TlsMode = Literal["off", "generated", "files"]

CIPHERS_TLS12: Final = "ECDHE+AESGCM:ECDHE+CHACHA20"
"""TLS 1.2's suites: ECDHE key exchange and AEAD only. TLS 1.3's are all AEAD already."""
VALIDITY: Final = datetime.timedelta(days=365)


def server_context(
    mode: TlsMode, *, cert_file: str | None = None, key_file: str | None = None
) -> ssl.SSLContext | None:
    """The public listener's TLS context, or None for plain HTTP."""
    if mode == "off":
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(CIPHERS_TLS12)
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    context.options |= ssl.OP_NO_RENEGOTIATION
    context.set_alpn_protocols(["http/1.1"])
    if mode == "files":
        if cert_file is None or key_file is None:
            raise ValueError("PUBLIC_TLS=files needs a certificate and a key file")
        context.load_cert_chain(cert_file, key_file)
    else:
        cert_pem, key_pem = self_signed(socket.gethostname())
        _load_from_memory(context, cert_pem, key_pem)
    return context


def self_signed(host: str) -> tuple[bytes, bytes]:
    """A new ECDSA P-256 key and a self-signed certificate for `host`, as PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64] or "sft")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + VALIDITY)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host or "sft")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return certificate.public_bytes(serialization.Encoding.PEM), key_pem


def _load_from_memory(context: ssl.SSLContext, cert_pem: bytes, key_pem: bytes) -> None:
    """`load_cert_chain` takes only paths. On Linux the PEM goes through an anonymous in-memory
    file, so the key never touches a disk; elsewhere (a laptop's tests) through a private
    temporary file, removed at once."""
    with _pem_path(cert_pem + key_pem) as path:
        context.load_cert_chain(path)


@contextlib.contextmanager
def _pem_path(pem: bytes) -> Iterator[str]:
    if sys.platform == "linux":
        fd = os.memfd_create("sft-tls", os.MFD_CLOEXEC)
        try:
            os.write(fd, pem)
            yield f"/proc/self/fd/{fd}"
        finally:
            os.close(fd)
        return
    with tempfile.TemporaryDirectory(prefix="sft-tls-") as directory:  # mode 0700
        path = os.path.join(directory, "chain.pem")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as out:
            out.write(pem)
        yield path
