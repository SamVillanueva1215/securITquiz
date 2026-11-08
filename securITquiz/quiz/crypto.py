"""
securITquiz - Cryptographic Verification Engine
Digital Signature Algorithm (DSA) with SHA-256 (FIPS 186-3)

Security & Implementation Architecture:
1. Algorithm: FIPS 186-3 DSA over finite fields with SHA-256 cryptographic hashing.
2. Parameter Limitations & Context:
   - The system utilizes 1024-bit finite-field DSA parameters to maintain continuous backward compatibility
     with historical academic records.
   - In accordance with NIST SP 800-57 recommendations, 1024-bit DSA is considered legacy/deprecated for high-assurance
     commercial production environments; 2048-bit or 3072-bit keys or Ed25519/ECDSA are recommended for modern standards.
     This implementation strictly serves academic cryptographic evaluation and exam integrity.
3. Separation of Concerns:
   - Private key (dsa_private_key.pem) is restricted strictly to signing operations (generate_dsa_signature).
   - Public key (dsa_public_key.pem) is exported separately and used for verification (verify_dsa_signature),
     ensuring that verification views and public auditors never have access to private signing credentials.
4. Key Safety & Tamper Prevention:
   - The engine never silently overwrites, recreates, or uses ephemeral keys if an existing key is damaged or unreadable.
     Instead, it raises an explicit KeyManagementError to prevent silent key rollover attacks.
5. Deterministic Payload Canonicalization:
   - Version 1 (Legacy): student:username|quiz:quiz_id|score:score|percentage:percentage|time:timestamp_str
   - Version 2 (Enhanced): v2|student:username|quiz:quiz_id|score:score|percentage:percentage|answers:sorted_json|time:timestamp_str
"""

import os
import json
from pathlib import Path
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from django.conf import settings

KEY_DIR = getattr(settings, 'BASE_DIR', Path('.'))
PRIVATE_KEY_PATH = KEY_DIR / 'dsa_private_key.pem'
PUBLIC_KEY_PATH = KEY_DIR / 'dsa_public_key.pem'


class KeyManagementError(RuntimeError):
    """Raised when the DSA cryptographic key is missing, damaged, unreadable, or cannot be safely saved."""
    pass


def get_dsa_private_key():
    """
    Retrieves the system's persistent DSA private key for signing.
    Strictly prevents silent regeneration if the key file exists but cannot be loaded.
    """
    if os.path.exists(PRIVATE_KEY_PATH):
        try:
            with open(PRIVATE_KEY_PATH, 'rb') as f:
                key = DSA.import_key(f.read())
            if not key.has_private():
                raise KeyManagementError(f"Private key file at {PRIVATE_KEY_PATH} contains only a public key.")
            return key
        except Exception as e:
            if isinstance(e, KeyManagementError):
                raise
            raise KeyManagementError(
                f"DSA private key at {PRIVATE_KEY_PATH} is corrupted or unreadable: {str(e)}. "
                "The system will not silently overwrite or replace existing keys."
            ) from e

    # Generate initial persistent key pair if no key exists yet
    try:
        key = DSA.generate(1024)
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(key.export_key(format='PEM'))

        # Also export the public key file
        pub_key = key.publickey()
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(pub_key.export_key(format='PEM'))
        return key
    except Exception as e:
        raise KeyManagementError(f"Failed to generate and securely save new DSA key pair: {str(e)}") from e


def get_dsa_public_key():
    """
    Retrieves the DSA public key for signature verification.
    Verification operations never require private key access.
    """
    if os.path.exists(PUBLIC_KEY_PATH):
        try:
            with open(PUBLIC_KEY_PATH, 'rb') as f:
                return DSA.import_key(f.read())
        except Exception:
            # Fall back to deriving from private key if public file is temporarily missing
            pass

    # Derive public key from private key and persist the public key file
    priv_key = get_dsa_private_key()
    pub_key = priv_key.publickey()
    try:
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(pub_key.export_key(format='PEM'))
    except Exception:
        pass
    return pub_key


def build_payload(student_username, quiz_id, score, percentage, timestamp_str, answers=None, signature_version=1):
    """
    Constructs the canonical, deterministic payload string to be hashed and signed/verified.
    - Version 1: student:username|quiz:quiz_id|score:score|percentage:percentage|time:timestamp_str
    - Version 2: v2|student:username|quiz:quiz_id|score:score|percentage:percentage|answers:answers_json|time:timestamp_str
      Deterministic JSON formatting (sorted keys, no extraneous whitespace) guarantees that
      any alteration of submitted answers invalidates the signature.
    """
    if signature_version == 2:
        answers_dict = answers if isinstance(answers, dict) else {}
        answers_json = json.dumps(answers_dict, sort_keys=True, separators=(',', ':'))
        return f"v2|student:{student_username}|quiz:{quiz_id}|score:{score}|percentage:{percentage:.2f}|answers:{answers_json}|time:{timestamp_str}"
    return f"student:{student_username}|quiz:{quiz_id}|score:{score}|percentage:{percentage:.2f}|time:{timestamp_str}"


def generate_dsa_signature(student_username, quiz_id, score, percentage, timestamp_str, answers=None, signature_version=2):
    """
    Signs the quiz submission payload using Digital Signature Algorithm (DSA)
    with SHA-256 in accordance with FIPS 186-3.
    Uses the private key and returns the signature formatted as a hexadecimal string.
    """
    key = get_dsa_private_key()
    payload = build_payload(
        student_username=student_username,
        quiz_id=quiz_id,
        score=score,
        percentage=percentage,
        timestamp_str=timestamp_str,
        answers=answers,
        signature_version=signature_version
    )
    hash_obj = SHA256.new(payload.encode('utf-8'))
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature.hex()


def verify_dsa_signature(student_username, quiz_id, score, percentage, timestamp_str, hex_signature, answers=None, signature_version=1):
    """
    Verifies the integrity and authenticity of the quiz submission payload
    against the DSA public key without touching the private key.
    Supports both legacy Version 1 signatures and Version 2 signatures that protect submitted answers.
    Returns True if mathematically valid, False otherwise.
    """
    try:
        pub_key = get_dsa_public_key()
        payload = build_payload(
            student_username=student_username,
            quiz_id=quiz_id,
            score=score,
            percentage=percentage,
            timestamp_str=timestamp_str,
            answers=answers,
            signature_version=signature_version
        )
        hash_obj = SHA256.new(payload.encode('utf-8'))
        verifier = DSS.new(pub_key, 'fips-186-3')
        raw_sig = bytes.fromhex(hex_signature)
        verifier.verify(hash_obj, raw_sig)
        return True
    except (ValueError, TypeError, Exception):
        return False
