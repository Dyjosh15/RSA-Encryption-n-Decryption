from django.shortcuts import render
from .rsa_utils import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def index(request):
    error_message = ""

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'generate_key':
            # Generate RSA key pair
            public_key, private_key = generate_keypair(2048)

            # Serialize the public key to PEM (X.509) format
            public_key_serialized = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo  # X.509 format
            ).decode('utf-8')

            # Serialize the private key to PEM (PKCS8) format
            private_key_serialized = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,  # PKCS8 format
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            # Store serialized keys in session
            request.session['public_key'] = public_key_serialized
            request.session['private_key'] = private_key_serialized

        elif action == 'encrypt':
            message = request.POST.get('message')
            public_key_pem = request.session.get('public_key')

            if public_key_pem and message:
                try:
                    # Load the public key from PEM
                    public_key = serialization.load_pem_public_key(
                        public_key_pem.encode('utf-8'),
                        backend=default_backend()
                    )

                    # Encrypt the message
                    encrypted = encrypt(public_key, message)

                    # Store the encrypted message in session (base64-encoded to make it safe for storage/display)
                    encrypted_base64 = base64.b64encode(encrypted).decode('utf-8')
                    request.session['encrypted'] = encrypted_base64

                except Exception as e:
                    error_message = f"Encryption error: {str(e)}"

        elif action == 'decrypt':
            encrypted_base64 = request.POST.get('ciphertext')
            private_key_pem = request.session.get('private_key')

            if private_key_pem and encrypted_base64:
                try:
                    # Load the private key from PEM
                    private_key = serialization.load_pem_private_key(
                        private_key_pem.encode('utf-8'),
                        password=None,
                        backend=default_backend()
                    )

                    # Decode base64 ciphertext
                    encrypted = base64.b64decode(encrypted_base64)

                    # Decrypt the message
                    decrypted = decrypt(private_key, encrypted)
                    request.session['decrypted'] = decrypted

                except Exception as e:
                    error_message = f"Decryption error: {str(e)}"
            else:
                error_message = "Please provide a valid ciphertext for decryption."

        return render(request, 'index.html', {
            'public_key': request.session.get('public_key'),
            'private_key': request.session.get('private_key'),
            'encrypted': request.session.get('encrypted'),
            'decrypted': request.session.get('decrypted'),
            'error_message': error_message,
        })

    # Fetch stored values for rendering the template
    return render(request, 'index.html', {
        'public_key': request.session.get('public_key'),
        'private_key': request.session.get('private_key'),
        'encrypted': request.session.get('encrypted'),
        'decrypted': request.session.get('decrypted'),
        'error_message': error_message,
    })
