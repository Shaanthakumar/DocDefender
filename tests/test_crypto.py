import pytest
from core.crypto_steg import (
    generate_sha256,
    verify_document_hash,
    construct_payload,
    encrypt_payload,
    decrypt_payload,
    MAGIC_HEADER
)
from Crypto.Random import get_random_bytes

def test_sha256_hash():
    data = b"Confidential Corporate Strategy 2026"
    hash1 = generate_sha256(data)
    assert len(hash1) == 64
    assert verify_document_hash(data, hash1) is True
    assert verify_document_hash(data, "0" * 64) is False

def test_aes_gcm_encrypt_decrypt():
    payload = construct_payload(doc_id="doc-12345", employee_id=101, doc_hash="a"*64)
    key = get_random_bytes(32)
    
    encrypted = encrypt_payload(payload, key)
    assert encrypted.startswith(MAGIC_HEADER)
    
    success, decrypted, msg = decrypt_payload(encrypted, key)
    assert success is True
    assert decrypted["doc_id"] == "doc-12345"
    assert decrypted["employee_id"] == 101

def test_aes_gcm_wrong_key():
    payload = construct_payload(doc_id="doc-999", employee_id=202)
    key1 = get_random_bytes(32)
    key2 = get_random_bytes(32)
    
    encrypted = encrypt_payload(payload, key1)
    success, decrypted, msg = decrypt_payload(encrypted, key2)
    
    assert success is False
    assert decrypted is None
    assert "failed" in msg.lower() or "verification" in msg.lower()

def test_aes_gcm_tampered_ciphertext():
    payload = construct_payload(doc_id="doc-tamper", employee_id=303)
    key = get_random_bytes(32)
    encrypted = bytearray(encrypt_payload(payload, key))
    
    # Flip last byte in ciphertext
    encrypted[-1] ^= 0xFF
    
    success, decrypted, msg = decrypt_payload(bytes(encrypted), key)
    assert success is False
    assert decrypted is None

def test_unique_nonces():
    payload = construct_payload(doc_id="doc-nonce", employee_id=101)
    key = get_random_bytes(32)
    enc1 = encrypt_payload(payload, key)
    enc2 = encrypt_payload(payload, key)
    
    # Nonce is bytes 7..19
    nonce1 = enc1[7:19]
    nonce2 = enc2[7:19]
    assert nonce1 != nonce2
