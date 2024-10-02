# Program Name: RSA Encryption and Decryption
# Author: Andres,Tristan Joseph V. and Herrera, Dylan Joshua Mhiles M.
# Date: Created: 2023-09-19; Last Modified: 2023-09-25
# Version: 1.0
# Purpose: This program implements the RSA algorithm for encrypting and decrypting messages using a generated public and private key pair.


# System Requirements
# Hardware:
 - CPU: Minimum dual-core processor
 - RAM: 4 GB
 - Storage: At least 100 MB free space
 - Internet connection recommended for downloading libraries (e.g., sympy) and updates.
 - Keyboard and mouse for user input.


# Software:
- Operating System: Windows, macOS, or Linux
- Python Version: 3.6 or higher
- Libraries: sympy, secrets and random (included in Python Standard Library)
- Visual studio code

# Functional Description
# Input:
# - Plaintext message (string) to be encrypted.
# - Ciphertext (integer) for decryption.
# - private key and public key

# Processing:
 1. Generate two large prime numbers (p and q).
 2. Compute n = p * q and phi = (p - 1) * (q - 1).
 3. Select a common public exponent e (commonly 65537).
 4. Compute private exponent d as the modular inverse of e modulo phi.
 5. Convert plaintext to an integer and encrypt it using the public key.
 6. Decrypt the ciphertext using the private key to retrieve the original plaintext.
 
# Output:
# - Encrypted data (integer) representing the ciphertext.
# - Decrypted data (string) representing the original plaintext message.
# - to be able to produce quality encrypted and decrypted message.

# Security Considerations
# Vulnerability Assessment:
# - Potential exposure of private key if not securely managed.
# - Risk of plaintext length exceeding n during encryption.
# - Slow process to
# 
# Mitigation Strategies:
# - Use secure storage for private keys.
# - Validate plaintext size before encryption.
# 
# Testing:
# - Conduct unit tests on key generation, encryption, and decryption functions.
# - Review code for common vulnerabilities (e.g., timing attacks).

# Usage Instructions
# Installation:
 1. Install Python 3.6 or higher.
 2. Install required libraries if needed (e.g., pip install sympy and pip install random).
 3. Use of notepad or install Visual Studio Code

# Configuration:
# - No specific configuration required; defaults are used.

# Execution:
# - Run the program from the command line or terminal using: python rsa_program.py

# Error Handling
# Error Codes:
- ValueError: Indicates plaintext is too long for the key size.
- KeyError: Indicates issues with key generation or retrieval.
- Htm or Html(frontend) unable to output correct procedure

# 
# Recovery Procedures:
 - Ensure plaintext length is within limits before encryption.
 - Verify key generation process if keys are not retrievable.

# Maintenance Log
# Date: 2023-09-25
# Changes: Initial release of the RSA encryption and decryption program.
 - Configure it to be able to encrypt and decrypt messages 
 - Slight changes in the design when we improve the front end 
 Author: Tristan Joseph V.Andres


