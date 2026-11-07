import os
from pathlib import Path
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from django.conf import settings

KEY_DIR = getattr(settings, 'BASE_DIR', Path('.'))
KEY_PATH = KEY_DIR / 'dsa_private_key.pem'


def get_or_create_dsa_key():
    """
    Retrieves the system's persistent DSA private key, or generates a new 1024-bit
    DSA key pair if one does not already exist.
    """
    if os.path.exists(KEY_PATH):
        try:
            with open(KEY_PATH, 'rb') as f:
                return DSA.import_key(f.read())
        except Exception:
            pass

    key = DSA.generate(1024)
    try:
        with open(KEY_PATH, 'wb') as f:
            f.write(key.export_key(format='PEM'))
    except Exception:
        pass
    return key


def generate_dsa_signature(student_username, quiz_id, score, percentage, timestamp_str):
    """
    Signs the quiz submission payload using Digital Signature Algorithm (DSA)
    with SHA-256 in accordance with FIPS 186-3.
    Returns the signature formatted as a hexadecimal string.
    """
    key = get_or_create_dsa_key()
    payload = f"student:{student_username}|quiz:{quiz_id}|score:{score}|percentage:{percentage:.2f}|time:{timestamp_str}"
    hash_obj = SHA256.new(payload.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature.hex()


def verify_dsa_signature(student_username, quiz_id, score, percentage, timestamp_str, hex_signature):
    """
    Verifies the integrity and authenticity of the quiz submission payload
    against the DSA public key.
    """
    try:
        key = get_or_create_dsa_key()
        pub_key = key.publickey()
        payload = f"student:{student_username}|quiz:{quiz_id}|score:{score}|percentage:{percentage:.2f}|time:{timestamp_str}"
        hash_obj = SHA256.new(payload.encode('utf-8'))
        verifier = DSS.new(pub_key, 'fips-186-3')
        raw_sig = bytes.fromhex(hex_signature)
        verifier.verify(hash_obj, raw_sig)
        return True
    except (ValueError, TypeError, Exception):
        return False
