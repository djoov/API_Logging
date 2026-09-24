"""PHASE 2: a tiny local certificate authority for the lab (HTTPS between Windows and Kali).

The CA private key never leaves the host that created it. Each API server gets its own
certificate whose SubjectAltName lists the IPs/hostnames clients use to reach it; clients
trust only the lab CA (ca.pem). Nothing here disables or weakens certificate verification.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CERT = "ca.pem"
CA_KEY = "ca.key"


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),  # lab only: uvicorn needs to read it unattended
    ))
    if os.name == "posix":
        path.chmod(0o600)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def create_ca(out_dir: Path, common_name: str = "API Observability Lab CA", days: int = 365) -> Path:
    """Create ca.pem/ca.key in out_dir. Refuses to overwrite an existing CA."""
    cert_path, key_path = out_dir / CA_CERT, out_dir / CA_KEY
    if cert_path.exists() or key_path.exists():
        raise FileExistsError(f"CA already exists in {out_dir}; delete it explicitly to recreate")

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_key(key_path, key)
    _write_cert(cert_path, cert)
    return cert_path


def load_ca(ca_dir: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    cert_path, key_path = ca_dir / CA_CERT, ca_dir / CA_KEY
    if not cert_path.exists() or not key_path.exists():
        raise FileNotFoundError(f"no CA in {ca_dir}; create it first (make_certs.py ca)")
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("unexpected CA key type")
    return cert, key


def create_server_cert(
    ca_dir: Path,
    out_dir: Path,
    name: str,
    ips: list[str],
    dns_names: list[str] | None = None,
    days: int = 365,
) -> tuple[Path, Path]:
    """Issue <out_dir>/<name>.pem and <name>.key, valid for the given IPs/hostnames."""
    if not ips and not dns_names:
        raise ValueError("a server certificate needs at least one --ip or --dns")
    ca_cert, ca_key = load_ca(ca_dir)
    key = ec.generate_private_key(ec.SECP256R1())

    san: list[x509.GeneralName] = [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    san += [x509.DNSName(d) for d in dns_names or []]
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path = out_dir / f"{name}.pem", out_dir / f"{name}.key"
    _write_key(key_path, key)
    _write_cert(cert_path, cert)
    return cert_path, key_path


def describe_cert(path: Path) -> str:
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in san.get_values_for_type(x509.IPAddress)] + san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    return (f"{path.name}: subject={cert.subject.rfc4514_string()} issuer={cert.issuer.rfc4514_string()} "
            f"valid_until={cert.not_valid_after_utc:%Y-%m-%d} san={names}")
