# Digital Signature

A Python implementation of digital signatures using RSA cryptography. This project demonstrates key generation, message signing, and signature verification with secure cryptographic practices.

## Features

- **RSA Key Pair Generation**: Creates secure 2048-bit RSA private and public keys
- **Message Signing**: Signs messages using PSS padding and SHA-256 hashing
- **Signature Verification**: Verifies signatures to ensure message integrity and authenticity
- **Cryptographic Best Practices**: Implements industry-standard security measures

## Requirements

- Python 3.6+
- `cryptography` library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/JafarMahmood123/Digital-Signature.git
cd Digital-Signature
```

2. Install dependencies:
```bash
pip install cryptography
```

## Usage

### Basic Example

```python
from digital_signature import generate_keys, sign_message, verify_signature

# Generate key pair
private_key, public_key = generate_keys()

# Sign a message
message = "Hello, world!"
signature = sign_message(private_key, message)

# Verify the signature
is_valid = verify_signature(public_key, message, signature)
print(f"Signature valid: {is_valid}")  # True

# Verify with wrong message
wrong_message = "Hello, wrong world!"
is_valid_wrong = verify_signature(public_key, wrong_message, signature)
print(f"Wrong message valid: {is_valid_wrong}")  # False
```

### Running the Demo

Execute the script directly to see a demonstration:

```bash
python digital_signature.py
```

This will generate keys, sign a test message, and demonstrate verification with both correct and incorrect messages.

## Security Notes

- This implementation uses RSA with 2048-bit keys and PSS padding for enhanced security
- SHA-256 is used for hashing
- Private keys should be kept secure and never shared
- For production use, consider hardware security modules and additional validation

## Project Structure

- `digital_signature.py`: Main implementation with key generation, signing, and verification functions
- `digital_signature_report.md`: Detailed technical report and analysis
- `README.md`: This file

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source. Please refer to the license file if included.

## References

- [RSA Cryptography](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Python Cryptography Library](https://cryptography.io/)
