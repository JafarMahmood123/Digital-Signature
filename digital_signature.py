from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

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
