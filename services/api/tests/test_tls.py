"""TLS on the public port (#184, encryption and keys 2.2), end to end over real sockets.

The load balancer forwards HTTPS to port 8000 and doesn't validate the target's certificate; its
health check is plain HTTP on 8001. These tests stand in for it: a client that accepts any
certificate reaches the API over TLS 1.2 or 1.3 and is refused below, the internal port answers
plain HTTP, and with a certificate from a (self-signed) issuer a client that trusts only that
issuer verifies the pod.
"""

import asyncio
import datetime
import socket
import ssl
import warnings
from pathlib import Path

import httpx2 as httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import SecretStr, ValidationError

from api_settings import API_SETTINGS
from sft.api.server import ApiServer
from sft.core.settings import Settings
from sft.runtime.tls import CIPHERS_TLS12, self_signed, server_context
from test_server import DATABASE_URL, free_ports, wait_until_ready


def tls_settings(**tls: str) -> Settings:
    public, internal = free_ports(2)
    return Settings(
        bind_host="127.0.0.1",
        public_port=public,
        internal_port=internal,
        shutdown_drain_seconds=1,
        database_url=SecretStr(DATABASE_URL),
        **API_SETTINGS,  # type: ignore[arg-type]
        **tls,  # type: ignore[arg-type]
    )


def like_the_load_balancer() -> ssl.SSLContext:
    """A client that, like the load balancer, doesn't check the target's certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def handshake(port: int, context: ssl.SSLContext, server_hostname: str | None = None) -> str:
    """Open a TLS connection and return the protocol version it agreed."""
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname=server_hostname) as tls,
    ):
        return str(tls.version())


@pytest.mark.anyio
async def test_the_public_port_serves_tls_with_a_generated_certificate() -> None:
    s = tls_settings(public_tls="generated")
    server = ApiServer(s)
    run = asyncio.create_task(server.run(handle_signals=False))
    internal = f"http://127.0.0.1:{s.internal_port}"
    try:
        async with httpx.AsyncClient() as plain:
            await wait_until_ready(plain, internal)  # the health port stays plain HTTP
            assert (await plain.get(f"{internal}/healthz")).status_code == 200
            with pytest.raises(httpx.TransportError):  # no plain HTTP on the public port
                await plain.get(f"http://127.0.0.1:{s.public_port}/v1/me")
        async with httpx.AsyncClient(verify=like_the_load_balancer()) as edge:
            r = await edge.get(f"https://127.0.0.1:{s.public_port}/v1/me")
            assert r.status_code == 401  # through TLS to the API itself
        assert await asyncio.to_thread(handshake, s.public_port, like_the_load_balancer()) in {
            "TLSv1.2",
            "TLSv1.3",
        }
        # The load balancer offers TLS 1.0 and up to targets: the pod refuses anything below 1.2.
        old = like_the_load_balancer()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # TLS 1.1 is, which is the point
            old.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            old.maximum_version = ssl.TLSVersion.TLSv1_1
        with pytest.raises((ssl.SSLError, ConnectionError)):
            await asyncio.to_thread(handshake, s.public_port, old)
    finally:
        server.shutdown()
    assert await run == 0


def issuer_and_leaf(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A self-signed issuer (the stand-in for a cluster issuer) and a certificate it issued for
    the API's in-cluster name."""
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sft test issuer")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.sft.svc")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.sft.svc")]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_file, cert_file, key_file = tmp_path / "ca.pem", tmp_path / "tls.crt", tmp_path / "tls.key"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_file, cert_file, key_file


@pytest.mark.anyio
async def test_a_certificate_from_an_issuer_verifies_end_to_end(tmp_path: Path) -> None:
    ca_file, cert_file, key_file = issuer_and_leaf(tmp_path)
    s = tls_settings(
        public_tls="files", public_tls_cert_file=str(cert_file), public_tls_key_file=str(key_file)
    )
    server = ApiServer(s)
    run = asyncio.create_task(server.run(handle_signals=False))
    try:
        async with httpx.AsyncClient() as plain:
            await wait_until_ready(plain, f"http://127.0.0.1:{s.internal_port}")
        trusting = ssl.create_default_context(cafile=str(ca_file))
        version = await asyncio.to_thread(handshake, s.public_port, trusting, "api.sft.svc")
        assert version in {"TLSv1.2", "TLSv1.3"}
        # A client that trusts only the system's roots can't verify it.
        with pytest.raises(ssl.SSLCertVerificationError):
            await asyncio.to_thread(
                handshake, s.public_port, ssl.create_default_context(), "api.sft.svc"
            )
    finally:
        server.shutdown()
    assert await run == 0


def test_tls_12_offers_only_forward_secret_aead_suites() -> None:
    context = server_context("generated")
    assert context is not None
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    tls12 = [c for c in context.get_ciphers() if c["protocol"] == "TLSv1.2"]
    assert tls12
    assert all(c["kea"] == "kx-ecdhe" and c["aead"] for c in tls12), tls12
    assert CIPHERS_TLS12 == "ECDHE+AESGCM:ECDHE+CHACHA20"


def test_off_is_plain_http() -> None:
    assert server_context("off") is None


def test_the_generated_certificate_is_ecdsa_p256_and_not_a_ca() -> None:
    cert_pem, key_pem = self_signed("api-7d9f-abcde")
    certificate = x509.load_pem_x509_certificate(cert_pem)
    public = certificate.public_key()
    assert isinstance(public, ec.EllipticCurvePublicKey)
    assert public.curve.name == "secp256r1"
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ["api-7d9f-abcde"]
    assert b"PRIVATE KEY" in key_pem


def test_tls_files_go_with_files_mode() -> None:
    with pytest.raises(ValidationError, match="PUBLIC_TLS=files needs"):
        tls_settings(public_tls="files", public_tls_cert_file="/tls/tls.crt")
    with pytest.raises(ValidationError, match="need PUBLIC_TLS=files"):
        tls_settings(public_tls="generated", public_tls_key_file="/tls/tls.key")
