import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

ph = PasswordHasher()

def hash_master_password(password):
    """Hash using Argon2."""
    return ph.hash(password)

def verify_master_password(hashed_password, password):
    """Verify against Argon2 hash."""
    try:
        return ph.verify(hashed_password, password)
    except (VerifyMismatchError, InvalidHash):
        return False
    except Exception as e:
        print(f"Unexpected error during verification: {e}")
        return False

def derive_encryption_key(master_password, salt):
    """Derive 256-bit key via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(master_password.encode())

def encrypt_data(data_bytes, encryption_key):
    """Encrypt with AES-GCM."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(encryption_key)
    return nonce, aesgcm.encrypt(nonce, data_bytes, None)

def decrypt_data(nonce, ciphertext, encryption_key):
    """Decrypt AES-GCM data."""
    try:
        return AESGCM(encryption_key).decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None
