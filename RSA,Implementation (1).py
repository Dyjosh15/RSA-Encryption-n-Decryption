import random
import secrets
from sympy import isprime, mod_inverse

def generate_prime_candidate(length):
    while True:
        num = secrets.randbits(length)
        num |= (1 << length - 1) | 1  # Ensure the number is odd
        if isprime(num):
            return num

def generate_keypair(length):
    p = generate_prime_candidate(length)
    q = generate_prime_candidate(length)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Commonly used prime
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    plaintext_bytes = plaintext.encode('utf-8')
    plaintext_int = int.from_bytes(plaintext_bytes, byteorder='big')
    if plaintext_int >= n:
        raise ValueError("Plaintext message is too long for the key size.")
    cipher_int = pow(plaintext_int, e, n)
    return cipher_int

def decrypt(private_key, ciphertext):
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, byteorder='big')
    return plaintext_bytes.decode('utf-8')

# Example usage
if __name__ == "__main__":
    public_key, private_key = None, None

    action = input("Generate an RSA key pair? (yes/no): ").strip().lower()
    if action == 'no':
        print("Thank you for using this app.")
    elif action == 'yes':
        public_key, private_key = generate_keypair(2048)
        print(f"Public Key: {public_key}")
        print(f"Private Key: {private_key}")

        while True:
            message = input("Enter the plaintext message to encrypt: ")
            try:
                encrypted = encrypt(public_key, message)
                print(f"Encrypted Output: {encrypted}")

                while True:
                    try:
                        ciphertext = int(input("Enter the ciphertext to decrypt: "))
                        decrypted = decrypt(private_key, ciphertext)
                        print(f"Decrypted Output: {decrypted}")
                        break  # Exit loop after successful decryption
                    except (ValueError, TypeError):
                        print("Wrong ciphertext. Please enter a valid integer ciphertext.")
            except Exception as e:
                print(f"Error: {e}")

            while True:
                another_action = input('Do you want to generate a new RSA key pair or enter a new plaintext message? (newkey/plaintext/exit): ').strip().lower()
                if another_action == 'exit':
                    print("Thank you for using this app.")
                    exit()
                elif another_action == 'newkey':
                    public_key, private_key = generate_keypair(2048)
                    print(f"New Public Key: {public_key}")
                    print(f"New Private Key: {private_key}")
                    break  # Exit to the main loop
                elif another_action == 'plaintext':
                    break  # Exit to re-prompt for message without extra processing
                else:
                    print("Invalid input. Please try again.")
    else:
        print("Invalid input. Please type 'yes' or 'no'.")
