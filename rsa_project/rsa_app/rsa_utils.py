import random
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Name, NameAttribute, CertificateBuilder
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

# Function to generate RSA key pairs
def generate_keypair(length):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=length,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

# Function to create an X.509 certificate
def create_x509_certificate(private_key, public_key):
    subject = issuer = Name([NameAttribute(NameOID.COMMON_NAME, u"Example CA")])
    certificate = CertificateBuilder(
        subject_name=subject,
        issuer_name=issuer,
        public_key=public_key,
        serial_number=random.randint(1, 1000000),
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=365),
    ).sign(private_key, hashes.SHA256(), default_backend())
    return certificate

# Encrypt plaintext with chunking
def encrypt(public_key, plaintext):
    max_chunk_size = 190  # Adjust based on key size and hash algorithm
    plaintext_bytes = plaintext.encode('utf-8')
    chunks = [plaintext_bytes[i:i + max_chunk_size] for i in range(0, len(plaintext_bytes), max_chunk_size)]
    
    ciphertext = b''
    for chunk in chunks:
        ciphertext += public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    return ciphertext

# Decrypt function
def decrypt(private_key, ciphertext):
    max_chunk_size = 256  # Same as the RSA key size in bytes
    decrypted_chunks = []
    
    for i in range(0, len(ciphertext), max_chunk_size):
        chunk = ciphertext[i:i + max_chunk_size]
        plaintext_bytes = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(plaintext_bytes)
    
    return b''.join(decrypted_chunks).decode('utf-8')

# Example usage
if __name__ == "__main__":
    public_key, private_key = None, None

    action = input("Generate an RSA key pair and X.509 certificate? (yes/no): ").strip().lower()
    if action == 'no':
        print("Thank you for using this app.")
    elif action == 'yes':
        public_key, private_key = generate_keypair(2048)
        certificate = create_x509_certificate(private_key, public_key)

        with open("public_key.pem", "wb") as public_key_file:
            public_key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        with open("private_key.pem", "wb") as private_key_file:
            private_key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("certificate.pem", "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

        print("X.509 certificate, public key, and private key generated and saved.")

        while True:
            message = input("Enter the plaintext message to encrypt: ")
            try:
                encrypted = encrypt(public_key, message)
                print(f"Encrypted Output (hex): {encrypted.hex()}")

                while True:
                    try:
                        ciphertext = bytes.fromhex(input("Enter the ciphertext to decrypt (hex format): "))
                        decrypted = decrypt(private_key, ciphertext)
                        print(f"Decrypted Output: {decrypted}")
                        break
                    except (ValueError, TypeError):
                        print("Wrong ciphertext. Please enter a valid hex ciphertext.")
            except Exception as e:
                print(f"Error: {e}")

            while True:
                another_action = input('Do you want to generate a new RSA key pair or enter a new plaintext message? (newkey/plaintext/exit): ').strip().lower()
                if another_action == 'exit':
                    print("Thank you for using this app.")
                    exit()
                elif another_action == 'newkey':
                    public_key, private_key = generate_keypair(2048)
                    certificate = create_x509_certificate(private_key, public_key)
                    print("New X.509 certificate generated.")
                    break
                elif another_action == 'plaintext':
                    break
                else:
                    print("Invalid input. Please try again.")
    else:
        print("Invalid input. Please type 'yes' or 'no'.")
