import os
import pytest
import numpy as np
import cv2
from database.database import init_db, SessionLocal
from database.repositories import create_user, get_user_by_email, has_document_permission
from services.auth_service import hash_password
from services.document_service import process_and_store_document, get_protected_document_pages
from core.document_processor import validate_uploaded_file

@pytest.fixture(scope="module")
def setup_db():
    init_db()
    db = SessionLocal()
    admin = get_user_by_email(db, "admin_doc_test@docsdefender.local")
    if not admin:
        admin = create_user(db, "Doc Admin", "admin_doc_test@docsdefender.local", hash_password("pass"), "administrator")
    emp = get_user_by_email(db, "emp_doc_test@docsdefender.local")
    if not emp:
        emp = create_user(db, "Doc Employee", "emp_doc_test@docsdefender.local", hash_password("pass"), "employee")
    admin_id, emp_id = admin.id, emp.id
    db.close()
    return admin_id, emp_id

def test_file_validation():
    valid, msg = validate_uploaded_file("report.pdf", 1024, b"%PDF-1.4 test content")
    assert valid is True

    # Test file without extension but valid PDF magic bytes
    valid_no_ext, _ = validate_uploaded_file("Student Feedback", 1024, b"%PDF-1.5 test content")
    assert valid_no_ext is True

    valid_err, msg_err = validate_uploaded_file("malicious.exe", 1024, b"test")
    assert valid_err is False
    assert "Unsupported" in msg_err

def test_document_ingestion_and_retrieval(setup_db):
    admin_id, emp_id = setup_db
    db = SessionLocal()
    try:
        # Create dummy PNG image bytes
        dummy_img = np.full((300, 300, 3), 200, dtype=np.uint8)
        _, img_encoded = cv2.imencode(".png", dummy_img)
        file_bytes = img_encoded.tobytes()

        doc = process_and_store_document(
            db=db,
            file_name="strategy_plan.png",
            file_bytes=file_bytes,
            description="Q4 Strategy Plan",
            classification="Top Secret",
            owner_id=admin_id,
            assigned_user_ids=[emp_id],
            watermark_strategy="lsb"
        )

        assert doc.id is not None
        assert doc.name == "strategy_plan.png"
        assert doc.classification == "Top Secret"
        assert os.path.exists(doc.protected_file_path)

        # Check permissions
        assert has_document_permission(db, doc.id, admin_id) is True
        assert has_document_permission(db, doc.id, emp_id) is True
        assert has_document_permission(db, doc.id, 9999) is False

        # Retrieve page images
        pages = get_protected_document_pages(db, doc.id, emp_id)
        assert len(pages) == 1
        assert pages[0].shape[:2] == (300, 300)
    finally:
        db.close()

def test_downloaded_watermarked_copy_extraction(setup_db):
    admin_id, emp_id = setup_db
    db = SessionLocal()
    try:
        from services.document_service import generate_watermarked_copy_for_user
        from core.forensic_engine import analyze_leaked_evidence
        from config.settings import TEMP_DIR

        dummy_img = np.full((300, 300, 3), 180, dtype=np.uint8)
        _, img_encoded = cv2.imencode(".png", dummy_img)

        doc = process_and_store_document(
            db=db,
            file_name="financial_forecast.png",
            file_bytes=img_encoded.tobytes(),
            description="Confidential Forecast",
            classification="Top Secret",
            owner_id=admin_id,
            assigned_user_ids=[emp_id],
            watermark_strategy="lsb"
        )

        # Generate downloaded copy for employee
        dl_bytes, dl_name, dl_mime = generate_watermarked_copy_for_user(
            db=db,
            doc_id=doc.id,
            user_id=emp_id
        )
        assert len(dl_bytes) > 0

        # Save downloaded copy to temp path (as if leaked)
        leaked_test_path = str(TEMP_DIR / f"leaked_by_employee_{emp_id}.png")
        with open(leaked_test_path, "wb") as f:
            f.write(dl_bytes)

        # Run forensic extraction on the downloaded copy
        success, report = analyze_leaked_evidence(db, leaked_test_path, investigator_id=admin_id)

        assert success is True
        assert report["extraction_status"] == "VERIFIED"
        assert report["attributed_employee_id"] == emp_id
        assert report["document_id"] == doc.id
    finally:
        db.close()
