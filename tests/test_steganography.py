import pytest
import numpy as np
import cv2
from core.crypto_steg import (
    construct_payload,
    encrypt_payload,
    decrypt_payload,
    embed_lsb_watermark,
    extract_lsb_watermark,
    embed_dct_watermark,
    extract_dct_watermark,
    calculate_psnr
)
from Crypto.Random import get_random_bytes

def test_lsb_embedding_extraction():
    key = get_random_bytes(32)
    payload = construct_payload(doc_id="doc-lsb-001", employee_id=505)
    encrypted_payload = encrypt_payload(payload, key)

    # Create dummy 200x200 RGB image
    img = np.random.randint(50, 200, (200, 200, 3), dtype=np.uint8)
    
    watermarked_img = embed_lsb_watermark(img, encrypted_payload)
    extracted_encrypted = extract_lsb_watermark(watermarked_img)
    
    success, decrypted, msg = decrypt_payload(extracted_encrypted, key)
    assert success is True
    assert decrypted["doc_id"] == "doc-lsb-001"
    assert decrypted["employee_id"] == 505

def test_lsb_psnr_quality():
    key = get_random_bytes(32)
    payload = construct_payload(doc_id="doc-lsb-psnr", employee_id=101)
    encrypted_payload = encrypt_payload(payload, key)

    img = np.full((300, 300, 3), 128, dtype=np.uint8)
    watermarked_img = embed_lsb_watermark(img, encrypted_payload)
    
    psnr = calculate_psnr(img, watermarked_img)
    assert psnr > 40.0, f"PSNR should exceed 40 dB, got {psnr:.2f} dB"

def test_dct_embedding_extraction():
    key = get_random_bytes(32)
    payload = construct_payload(doc_id="doc-dct-001", employee_id=707)
    encrypted_payload = encrypt_payload(payload, key)

    # Create dummy 512x512 image (64x64 blocks = 4096 bits capacity)
    img = np.full((512, 512, 3), 150, dtype=np.uint8)
    # Add texture to allow frequency transformations
    noise = np.random.randint(-20, 20, (512, 512, 3), dtype=np.int16)
    img = np.clip(img.astype(np.int16) + noise, 0, 255).astype(np.uint8)

    watermarked_img = embed_dct_watermark(img, encrypted_payload)
    extracted_encrypted = extract_dct_watermark(watermarked_img)
    
    success, decrypted, msg = decrypt_payload(extracted_encrypted, key)
    assert success is True
    assert decrypted["doc_id"] == "doc-dct-001"
    assert decrypted["employee_id"] == 707

def test_lsb_insufficient_capacity():
    key = get_random_bytes(32)
    payload = construct_payload(doc_id="doc-overflow", employee_id=999)
    encrypted_payload = encrypt_payload(payload, key)

    # Very small 5x5 image
    tiny_img = np.zeros((5, 5, 3), dtype=np.uint8)
    with pytest.raises(ValueError, match="capacity insufficient"):
        embed_lsb_watermark(tiny_img, encrypted_payload)
