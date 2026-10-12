import os
import pytest
import numpy as np
import cv2
from database.database import init_db, SessionLocal
from database.repositories import create_user, get_user_by_email
from services.auth_service import hash_password
from services.document_service import process_and_store_document
from core.forensic_engine import analyze_leaked_evidence
from config.settings import TEMP_DIR

@pytest.fixture(scope="module")
def setup_forensic_db():
    init_db()
    db = SessionLocal()
    inv = get_user_by_email(db, "investigator_test@docsdefender.local")
    if not inv:
        inv = create_user(db, "Test Investigator", "investigator_test@docsdefender.local", hash_password("pass"), "investigator")
    emp = get_user_by_email(db, "suspect_test@docsdefender.local")
    if not emp:
        emp = create_user(db, "Suspect Employee", "suspect_test@docsdefender.local", hash_password("pass"), "employee")
    inv_id, emp_id, emp_name = inv.id, emp.id, emp.name
    db.close()
    return inv_id, emp_id, emp_name

def test_forensic_extraction_and_attribution(setup_forensic_db):
    inv_id, emp_id, emp_name = setup_forensic_db
    db = SessionLocal()
    try:
        # 1. Create and watermark document owned by suspect
        dummy_img = np.full((300, 300, 3), 150, dtype=np.uint8)
        _, img_encoded = cv2.imencode(".png", dummy_img)
        file_bytes = img_encoded.tobytes()

        doc = process_and_store_document(
            db=db,
            file_name="leaked_target.png",
            file_bytes=file_bytes,
            description="Confidential Target Image",
            classification="Confidential",
            owner_id=emp_id,
            assigned_user_ids=[],
            watermark_strategy="lsb"
        )

        # 2. Simulate leaked photo file
        leaked_path = doc.protected_file_path

        # 3. Run Forensic Extraction
        success, report = analyze_leaked_evidence(db, leaked_path, investigator_id=inv_id)

        assert success is True
        assert report["extraction_status"] == "VERIFIED"
        assert report["attributed_employee_id"] == emp_id
        assert report["attributed_employee_name"] == emp_name
        assert report["document_id"] == doc.id
        assert report["confidence_score"] == "100.0%"
    finally:
        db.close()

def test_forensic_unwatermarked_image_failure(setup_forensic_db):
    inv_id, _, _ = setup_forensic_db
    db = SessionLocal()
    try:
        # Create unwatermarked clean image
        clean_img = np.full((200, 200, 3), 100, dtype=np.uint8)
        clean_path = str(TEMP_DIR / "clean_unwatermarked.png")
        cv2.imwrite(clean_path, clean_img)

        success, report = analyze_leaked_evidence(db, clean_path, investigator_id=inv_id)
        assert success is False
        assert report["extraction_status"] == "FAILED"
        assert report["attributed_employee_id"] == "Unidentified"
    finally:
        db.close()
