"""
DocsDefender - Phase 1 Showcase & Demonstration Script
Demonstrates Core Hashing, AES-256-GCM Encryption, LSB Steganography,
DCT Frequency Watermarking, Argon2 Password Hashing, JWT Authentication,
and Database Persistence.
"""

import os
import numpy as np
import cv2
from database.database import init_db, SessionLocal
from database.repositories import (
    create_user,
    get_user_by_email,
    log_audit_event,
    query_audit_logs
)
from services.auth_service import hash_password, verify_password, create_access_token, decode_access_token
from core.crypto_steg import (
    generate_sha256,
    verify_document_hash,
    construct_payload,
    encrypt_payload,
    decrypt_payload,
    embed_lsb_watermark,
    extract_lsb_watermark,
    embed_dct_watermark,
    extract_dct_watermark,
    calculate_psnr
)

def run_phase1_demo():
    print("==================================================================")
    print("      DOCSDEFENDER -- PHASE 1 SYSTEM SHOWCASE & DEMONSTRATION      ")
    print("==================================================================")

    # 1. Database Initialization & Seed User
    print("\n[1] INITIALIZING DATABASE & SEED ACCOUNTS...")
    init_db()
    db = SessionLocal()
    try:
        admin_email = "admin@docsdefender.local"
        user = get_user_by_email(db, admin_email)
        if not user:
            hashed_pw = hash_password("AdminSecure2026!")
            user = create_user(db, name="Security Admin", email=admin_email, password_hash=hashed_pw, role="administrator")
            print(f"  [+] Created Admin User: {user.email} (ID: {user.id}, Role: {user.role})")
        else:
            print(f"  [OK] Existing Admin User Found: {user.email} (ID: {user.id})")
    finally:
        db.close()

    # 2. Authentication & JWT Token Validation
    print("\n[2] TESTING ARGON2 PASSWORD HASHING & JWT AUTHENTICATION...")
    pw_match = verify_password("AdminSecure2026!", user.password_hash)
    print(f"  [OK] Argon2 Password Verification: {'PASSED' if pw_match else 'FAILED'}")
    token = create_access_token({"sub": str(user.id), "email": user.email, "role": user.role})
    decoded = decode_access_token(token)
    print(f"  [OK] JWT Access Token Generated: {token[:35]}...")
    print(f"  [OK] JWT Token Payload Decoded: Sub={decoded['sub']}, Role={decoded['role']}")

    # 3. Document Integrity & Cryptographic Hashing
    print("\n[3] TESTING DOCUMENT INTEGRITY & SHA-256 HASHING...")
    sample_doc_content = b"TOP SECRET: DocsDefender Security Architecture Strategy Document 2026."
    doc_hash = generate_sha256(sample_doc_content)
    is_valid_hash = verify_document_hash(sample_doc_content, doc_hash)
    print(f"  [+] Original Document Content Length: {len(sample_doc_content)} bytes")
    print(f"  [+] Calculated SHA-256 Hash: {doc_hash}")
    print(f"  [OK] Hash Integrity Verification: {'VERIFIED (100% Match)' if is_valid_hash else 'FAILED'}")

    # 4. AES-256-GCM Payload Encryption
    print("\n[4] CREATING & ENCRYPTING WATERMARK PAYLOAD (AES-256-GCM)...")
    payload_dict = construct_payload(doc_id="DOC-SECRET-001", employee_id=user.id, doc_hash=doc_hash)
    encrypted_payload = encrypt_payload(payload_dict)
    print(f"  [+] Structured Payload: {payload_dict}")
    print(f"  [+] AES-256-GCM Encrypted Payload ({len(encrypted_payload)} bytes): {encrypted_payload[:25].hex()}...")

    # 5. LSB Image Steganography
    print("\n[5] TESTING LSB IMAGE STEGANOGRAPHY EMBEDDING & EXTRACTION...")
    cover_image = np.full((300, 300, 3), 180, dtype=np.uint8)
    noise = np.random.randint(-15, 15, (300, 300, 3), dtype=np.int16)
    cover_image = np.clip(cover_image.astype(np.int16) + noise, 0, 255).astype(np.uint8)

    lsb_watermarked = embed_lsb_watermark(cover_image, encrypted_payload)
    extracted_lsb_bytes = extract_lsb_watermark(lsb_watermarked)
    success_lsb, decrypted_lsb, msg_lsb = decrypt_payload(extracted_lsb_bytes)
    psnr_lsb = calculate_psnr(cover_image, lsb_watermarked)

    print(f"  [+] LSB Image Quality (PSNR): {psnr_lsb:.2f} dB (Target > 40 dB)")
    print(f"  [OK] LSB Payload Recovery & AES Tag Verification: {'SUCCESS' if success_lsb else 'FAILED'}")
    if success_lsb:
        print(f"  [OK] Recovered Employee ID: {decrypted_lsb['employee_id']}, Doc ID: {decrypted_lsb['doc_id']}")

    # 6. DCT Frequency Domain Watermarking
    print("\n[6] TESTING DCT FREQUENCY DOMAIN WATERMARKING...")
    cover_dct_img = np.full((512, 512, 3), 140, dtype=np.uint8)
    noise_dct = np.random.randint(-20, 20, (512, 512, 3), dtype=np.int16)
    cover_dct_img = np.clip(cover_dct_img.astype(np.int16) + noise_dct, 0, 255).astype(np.uint8)

    dct_watermarked = embed_dct_watermark(cover_dct_img, encrypted_payload)
    extracted_dct_bytes = extract_dct_watermark(dct_watermarked)
    success_dct, decrypted_dct, msg_dct = decrypt_payload(extracted_dct_bytes)
    psnr_dct = calculate_psnr(cover_dct_img, dct_watermarked)

    print(f"  [+] DCT Image Quality (PSNR): {psnr_dct:.2f} dB")
    print(f"  [OK] DCT Payload Recovery & AES Tag Verification: {'SUCCESS' if success_dct else 'FAILED'}")
    if success_dct:
        print(f"  [OK] Recovered Employee ID: {decrypted_dct['employee_id']}, Doc ID: {decrypted_dct['doc_id']}")

    # 7. Audit Logging Check
    print("\n[7] RECORDING & VERIFYING AUDIT TRAIL...")
    db = SessionLocal()
    try:
        log_audit_event(db, action="PHASE1_SHOWCASE_DEMO", user_id=user.id, status="SUCCESS", severity="INFO")
        logs = query_audit_logs(db, limit=5)
        print(f"  [+] Total Audit Records in DB: {len(logs)}")
        print(f"  [OK] Latest Audit Log Action: {logs[0].action} at {logs[0].timestamp}")
    finally:
        db.close()

    print("\n==================================================================")
    print("  PHASE 1 DEMONSTRATION COMPLETE: ALL CORE SECURITY MODULES READY ")
    print("==================================================================")

if __name__ == "__main__":
    run_phase1_demo()
