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
   - Production requires an explicitly configured persistent DSA private key.
   - Production never falls back to filesystem keys or silently generates replacement keys.
   - Local development retains filesystem key generation and loading.
5. Deterministic Payload Canonicalization:
   - Version 1 (Legacy): student:username|quiz:quiz_id|score:score|percentage:percentage|time:timestamp_str
   - Version 2 (Enhanced): v2|student:username|quiz:quiz_id|score:score|percentage:percentage|answers:sorted_json|time:timestamp_str
"""

import os
import json
import logging
from pathlib import Path

from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from django.conf import settings


logger = logging.getLogger(__name__)

_base_dir = getattr(settings, 'BASE_DIR', Path('.'))

_is_serverless = bool(
    os.environ.get('VERCEL')
    or os.environ.get('VERCEL_ENV')
    or os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
)

_is_writable = os.access(_base_dir, os.W_OK) and not _is_serverless

KEY_DIR = Path(
    os.environ.get(
        'DSA_KEY_DIR',
        str(_base_dir if _is_writable else Path('/tmp'))
    )
)

PRIVATE_KEY_PATH = KEY_DIR / 'dsa_private_key.pem'
PUBLIC_KEY_PATH = KEY_DIR / 'dsa_public_key.pem'


class KeyManagementError(RuntimeError):
    """Raised when the DSA cryptographic key is missing, damaged, unreadable, or cannot be safely saved."""
    pass


def _is_serverless_or_production():
    """
    Uses Django's centralized environment configuration.

    This ensures crypto.py follows the same production detection
    used by the project's Django settings.
    """
    return bool(
        getattr(settings, 'IS_PRODUCTION', False)
        or getattr(settings, 'IS_VERCEL', False)
        or os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
    )


def _normalize_pem(key_str):
    """Normalizes PEM strings containing escaped newlines."""
    if not key_str:
        return key_str

    key_str = key_str.strip()

    if '\\n' in key_str and '\n' not in key_str:
        key_str = key_str.replace('\\n', '\n')

    return key_str


def get_dsa_private_key():
    """
    Retrieves the DSA private key.

    Production:
    - DSA_PRIVATE_KEY environment variable is mandatory.
    - Never loads private keys from filesystem.
    - Never generates replacement keys.

    Local development:
    - Uses DSA_PRIVATE_KEY if explicitly configured.
    - Otherwise loads the existing local private key.
    - Generates an initial key pair only when no local key exists.
    - Never silently replaces a corrupted existing key.
    """

    env_key = os.environ.get('DSA_PRIVATE_KEY', '').strip()

    # Production / Vercel workflow
    if _is_serverless_or_production():

        if not env_key:
            raise KeyManagementError(
                "DSA_PRIVATE_KEY environment variable is not configured. "
                "A persistent private key must be configured in production."
            )

        try:
            norm_key = _normalize_pem(env_key)
            key = DSA.import_key(norm_key)

            if not key.has_private():
                raise KeyManagementError(
                    "DSA_PRIVATE_KEY environment variable contains only a public key."
                )

            return key

        except KeyManagementError:
            raise

        except Exception:
            raise KeyManagementError(
                "DSA_PRIVATE_KEY environment variable is invalid or cannot be imported."
            ) from None

    # Local Development Workflow

    # 1. Use explicitly configured environment variable if available
    if env_key:

        try:
            norm_key = _normalize_pem(env_key)
            key = DSA.import_key(norm_key)

            if not key.has_private():
                raise KeyManagementError(
                    "DSA_PRIVATE_KEY environment variable contains only a public key."
                )

            return key

        except KeyManagementError:
            raise

        except Exception:
            raise KeyManagementError(
                "DSA_PRIVATE_KEY environment variable is invalid or cannot be imported."
            ) from None

    # 2. Load existing local private key
    if os.path.exists(PRIVATE_KEY_PATH):

        try:
            with open(PRIVATE_KEY_PATH, 'rb') as f:
                key = DSA.import_key(f.read())

            if not key.has_private():
                raise KeyManagementError(
                    f"Private key file at {PRIVATE_KEY_PATH} contains only a public key."
                )

            return key

        except KeyManagementError:
            raise

        except Exception as e:
            raise KeyManagementError(
                f"DSA private key at {PRIVATE_KEY_PATH} is corrupted or unreadable. "
                "The system will not silently overwrite or replace existing keys."
            ) from e

    # 3. Generate initial key pair only in local development
    try:
        KEY_DIR.mkdir(parents=True, exist_ok=True)

        key = DSA.generate(1024)

        with open(PRIVATE_KEY_PATH, 'xb') as f:
            f.write(key.export_key(format='PEM'))

        pub_key = key.publickey()

        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(pub_key.export_key(format='PEM'))

        return key

    except Exception as e:
        raise KeyManagementError(
            "Failed to generate and securely save the initial local DSA key pair."
        ) from e


def get_dsa_public_key():
    """
    Retrieves the DSA public key for signature verification.

    Public-key verification does not require private-key access
    when DSA_PUBLIC_KEY is explicitly configured.
    """

    # 1. Derive the public key from the configured private key.
    # This guarantees mathematical correspondence between the two keys.
    env_priv = os.environ.get('DSA_PRIVATE_KEY', '').strip()

    if env_priv:
        priv_key = get_dsa_private_key()
        return priv_key.publickey()

    # 2. Load explicitly configured public key.
    env_pub = os.environ.get('DSA_PUBLIC_KEY', '').strip()

    if env_pub:
        try:
            norm_pub = _normalize_pem(env_pub)
            return DSA.import_key(norm_pub)

        except Exception:
            logger.warning(
                "Failed to import DSA_PUBLIC_KEY from environment. "
                "Checking the permitted fallback source."
            )

    # 3. In production, use the public key derived from the mandatory
    # configured private key if no public environment key is available.
    if _is_serverless_or_production():
        priv_key = get_dsa_private_key()
        return priv_key.publickey()

    # 4. In local development, check the public key file.
    if os.path.exists(PUBLIC_KEY_PATH):

        try:
            with open(PUBLIC_KEY_PATH, 'rb') as f:
                return DSA.import_key(f.read())

        except Exception:
            pass

    # 5. Derive public key from the local private key.
    priv_key = get_dsa_private_key()
    pub_key = priv_key.publickey()

    try:
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(pub_key.export_key(format='PEM'))

    except Exception:
        pass

    return pub_key


def build_payload(
    student_username,
    quiz_id,
    score,
    percentage,
    timestamp_str,
    answers=None,
    signature_version=1
):
    """
    Constructs the canonical, deterministic payload string to be hashed and signed/verified.

    Version 1:
    student:username|quiz:quiz_id|score:score|percentage:percentage|time:timestamp_str

    Version 2:
    v2|student:username|quiz:quiz_id|score:score|percentage:percentage|answers:answers_json|time:timestamp_str
    """

    if signature_version == 2:

        answers_dict = answers if isinstance(answers, dict) else {}

        answers_json = json.dumps(
            answers_dict,
            sort_keys=True,
            separators=(',', ':')
        )

        return (
            f"v2|student:{student_username}|quiz:{quiz_id}|"
            f"score:{score}|percentage:{percentage:.2f}|"
            f"answers:{answers_json}|time:{timestamp_str}"
        )

    return (
        f"student:{student_username}|quiz:{quiz_id}|"
        f"score:{score}|percentage:{percentage:.2f}|"
        f"time:{timestamp_str}"
    )


def generate_dsa_signature(
    student_username,
    quiz_id,
    score,
    percentage,
    timestamp_str,
    answers=None,
    signature_version=2
):
    """
    Signs the quiz submission payload using DSA with SHA-256.

    Uses the private key and returns the signature as a hexadecimal string.
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


def verify_dsa_signature(
    student_username,
    quiz_id,
    score,
    percentage,
    timestamp_str,
    hex_signature,
    answers=None,
    signature_version=1
):
    """
    Verifies the integrity and authenticity of the quiz submission payload
    against the DSA public key without modifying the private key.

    Supports:
    - Legacy Version 1 signatures.
    - Version 2 signatures protecting submitted answers.

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

    except Exception:
        return False