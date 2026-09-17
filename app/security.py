"""
Security Engine for Question Paper Management System.
Includes:
- Pure Python AES-256 Encryption & Decryption
- SHA-256 Data Integrity Hashing
- HMAC-SHA256 Digital Signatures
- PBKDF2 Password Hashing
- 2FA / OTP Generation and Verification
- Access Control Tokens
"""

import os
import hashlib
import hmac
import secrets
import base64
import time
from typing import Tuple, Dict, Optional

# --- Pure Python AES-256 Implementation (Zero External Dependencies) ---

# S-box and Inverse S-box
SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
)

INV_SBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
)

RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

def _sub_word(word: list) -> list:
    return [SBOX[b] for b in word]

def _rot_word(word: list) -> list:
    return word[1:] + word[:1]

def _key_expansion(key: bytes) -> list:
    # Key length: 32 bytes (AES-256) -> 14 rounds, 60 4-byte words
    key_symbols = list(key)
    w = [key_symbols[i:i+4] for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = w[i-1][:]
        if i % 8 == 0:
            temp = [SBOX[b] for b in _rot_word(temp)]
            temp[0] ^= RCON[i // 8]
        elif i % 8 == 4:
            temp = [SBOX[b] for b in temp]
        word = [w[i-8][j] ^ temp[j] for j in range(4)]
        w.append(word)
    return w

def _add_round_key(state: list, round_key: list):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[c][r]

def _sub_bytes(state: list):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def _inv_sub_bytes(state: list):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]

def _shift_rows(state: list):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def _inv_shift_rows(state: list):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p

def _mix_columns(state: list):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        state[1][c] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        state[2][c] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        state[3][c] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)

def _inv_mix_columns(state: list):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
        state[1][c] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
        state[2][c] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
        state[3][c] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)

def _encrypt_block(block: bytes, expanded_key: list) -> bytes:
    state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
    _add_round_key(state, expanded_key[0:4])

    for round in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, expanded_key[round*4:(round+1)*4])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, expanded_key[14*4:15*4])

    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)

def _decrypt_block(block: bytes, expanded_key: list) -> bytes:
    state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
    _add_round_key(state, expanded_key[14*4:15*4])

    for round in range(13, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, expanded_key[round*4:(round+1)*4])
        _inv_mix_columns(state)

    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, expanded_key[0:4])

    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)

# --- AES-256 CBC Mode with PKCS#7 Padding & HMAC-SHA256 Authentication ---

def encrypt_aes256_cbc(plaintext: bytes, master_key_bytes: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext using AES-256-CBC with PKCS7 padding.
    Returns: (iv, ciphertext, hmac_signature)
    """
    # Key derivation: 32 bytes AES key, 32 bytes HMAC key
    key = hashlib.sha256(master_key_bytes + b"aes_enc_key").digest()
    hmac_key = hashlib.sha256(master_key_bytes + b"hmac_auth_key").digest()
    
    iv = secrets.token_bytes(16)
    expanded_key = _key_expansion(key)

    # PKCS7 Padding
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)

    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]
    ciphertext_blocks = []
    prev_block = iv

    for block in blocks:
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        enc = _encrypt_block(xored, expanded_key)
        ciphertext_blocks.append(enc)
        prev_block = enc

    ciphertext = b"".join(ciphertext_blocks)
    sig = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

    return iv, ciphertext, sig

def decrypt_aes256_cbc(iv: bytes, ciphertext: bytes, sig: bytes, master_key_bytes: bytes) -> bytes:
    """
    Verifies HMAC and decrypts AES-256-CBC ciphertext.
    """
    key = hashlib.sha256(master_key_bytes + b"aes_enc_key").digest()
    hmac_key = hashlib.sha256(master_key_bytes + b"hmac_auth_key").digest()

    # Authenticate before decryption
    expected_sig = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ValueError("HMAC Signature Verification Failed! Ciphertext altered or key invalid.")

    expanded_key = _key_expansion(key)
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    plaintext_blocks = []
    prev_block = iv

    for block in blocks:
        dec = _decrypt_block(block, expanded_key)
        xored = bytes(a ^ b for a, b in zip(dec, prev_block))
        plaintext_blocks.append(xored)
        prev_block = block

    padded = b"".join(plaintext_blocks)
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding.")
    if padded[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding integrity check failed.")

    return padded[:-pad_len]

# --- High Level Security APIs ---

MASTER_VAULT_KEY = b"SECURE_EXAM_QUESTION_PAPER_VAULT_KEY_2026_MASTER"

def hash_data(data: bytes) -> str:
    """Returns SHA-256 hex fingerprint of data."""
    return hashlib.sha256(data).hexdigest()

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Generates PBKDF2-HMAC-SHA256 hash for user passwords."""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return dk.hex(), salt.hex()

def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return hmac.compare_digest(dk.hex(), stored_hash)

# Active OTP Store: {username: {"otp": "123456", "expires_at": float_timestamp}}
OTP_STORE: Dict[str, dict] = {}

def generate_otp(username: str) -> str:
    """Generates a 6-digit OTP valid for 5 minutes."""
    otp = f"{secrets.randbelow(1000000):06d}"
    OTP_STORE[username] = {
        "otp": otp,
        "expires_at": time.time() + 300 # 5 mins
    }
    return otp

def verify_otp(username: str, code: str) -> bool:
    entry = OTP_STORE.get(username)
    if not entry:
        return False
    if time.time() > entry["expires_at"]:
        del OTP_STORE[username]
        return False
    if hmac.compare_digest(entry["otp"], code.strip()):
        del OTP_STORE[username]
        return True
    return False

def encrypt_question_paper(content_str: str) -> Tuple[str, str, str, str]:
    """
    Encrypts string content with AES-256.
    Returns: (b64_iv, b64_ciphertext, b64_hmac, sha256_hash)
    """
    raw_bytes = content_str.encode('utf-8')
    sha256_fingerprint = hash_data(raw_bytes)
    iv, ciphertext, sig = encrypt_aes256_cbc(raw_bytes, MASTER_VAULT_KEY)
    
    return (
        base64.b64encode(iv).decode(),
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(sig).decode(),
        sha256_fingerprint
    )

def decrypt_question_paper(b64_iv: str, b64_ciphertext: str, b64_hmac: str) -> Tuple[str, str]:
    """
    Decrypts question paper.
    Returns: (decrypted_content_str, verify_sha256_hash)
    """
    iv = base64.b64decode(b64_iv)
    ciphertext = base64.b64decode(b64_ciphertext)
    sig = base64.b64decode(b64_hmac)

    raw_bytes = decrypt_aes256_cbc(iv, ciphertext, sig, MASTER_VAULT_KEY)
    sha256_fingerprint = hash_data(raw_bytes)
    return raw_bytes.decode('utf-8'), sha256_fingerprint
