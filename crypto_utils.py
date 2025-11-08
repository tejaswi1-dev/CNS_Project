import os
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# --- Key Derivation ---
def derive_aes_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(master_password.encode())

# --- AES-GCM Encryption/Decryption ---
def encrypt_aes(key: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_aes(key: bytes, token: str) -> str:
    data = base64.b64decode(token)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()

# --- Ed25519 Key Generation / Signing ---
def generate_ed25519_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def sign_message(priv: Ed25519PrivateKey, message: bytes) -> str:
    signature = priv.sign(message)
    return base64.b64encode(signature).decode()

def verify_signature(pub: Ed25519PublicKey, message: bytes, signature: str) -> bool:
    try:
        pub.verify(base64.b64decode(signature), message)
        return True
    except:
        return False

# --- Serialization Helpers ---
def serialize_public_key(pub: Ed25519PublicKey) -> str:
    return base64.b64encode(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

def deserialize_public_key(pub_b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
