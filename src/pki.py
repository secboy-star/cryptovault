from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def create_ca():
    """Create a demo root CA and return its private key and certificate in memory."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoVault CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CryptoVault Root CA"),
    ])
    now = datetime.now(timezone.utc)
    usage = x509.KeyUsage(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True,
        crl_sign=True, encipher_only=False, decipher_only=False,
    )
    return key, (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(usage, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256()))


def issue_certificate(ca_key, ca_cert, cn, is_server=False):
    """Issue a demo TLS certificate and return its key and certificate in memory."""
    if ca_key.public_key().public_numbers() != ca_cert.public_key().public_numbers():
        raise ValueError("The issuer key must match the CA certificate")
    if not ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("The issuer certificate must be a CA")
    if not ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
        raise ValueError("The issuer certificate must allow certificate signing")
    now = datetime.now(timezone.utc)
    if not ca_cert.not_valid_before_utc <= now < ca_cert.not_valid_after_utc:
        raise ValueError("The issuer certificate must be valid")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    usage = ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH
    issuer_id = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now)
        .not_valid_after(min(now + timedelta(days=365), ca_cert.not_valid_after_utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_id), False))
    if is_server:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False)
    return key, builder.sign(ca_key, hashes.SHA256())
