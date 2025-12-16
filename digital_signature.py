from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone

def generate_keys():
    """
    Generate a new RSA key pair (private and public keys).
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_self_signed_cert(private_key):
    """
    Generate a self-signed X.509 certificate.
    Args:
        private_key: The RSA private key.
    Returns:
        x509.Certificate: The self-signed certificate.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    return cert

def sign_message(private_key, message):
    """
    Sign a message using the private key.
    Args:
        private_key: The RSA private key.
        message: The message to sign (string).
    Returns:
        bytes: The digital signature.
    """
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    """
    Verify a digital signature using the public key.
    Args:
        public_key: The RSA public key.
        message: The original message (string).
        signature: The signature to verify (bytes).
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

if __name__ == "__main__":
    # Generate key pair
    private_key, public_key = generate_keys()
    print("Key pair generated successfully.")

    # Generate self-signed certificate
    cert = generate_self_signed_cert(private_key)
    print("Self-signed certificate generated successfully.")

    # Save certificate to file
    with open("self_signed_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Certificate saved to self_signed_cert.pem")

    # Save private key to file
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("Private key saved to private_key.pem")

    # Sign a message
    message = "Hello, world!"
    signature = sign_message(private_key, message)
    print(f"Message '{message}' signed successfully.")

    # Verify the signature
    is_valid = verify_signature(public_key, message, signature)
    print(f"Signature verification for correct message: {is_valid}")

    # Verify with wrong message
    wrong_message = "Hello, wrong world!"
    is_valid_wrong = verify_signature(public_key, wrong_message, signature)
    print(f"Signature verification for wrong message: {is_valid_wrong}")
