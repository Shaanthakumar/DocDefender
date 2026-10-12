import os
import json
import shutil
import cv2
import numpy as np
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session

from config.settings import EVIDENCE_DIR, REPORTS_DIR
from database.repositories import (
    get_document_by_id,
    get_user_by_id,
    create_leak_report
)
from core.crypto_steg import (
    generate_file_sha256,
    extract_lsb_watermark,
    extract_dct_watermark,
    decrypt_payload
)
from core.document_processor import extract_text_watermark
from services.audit_logger import AuditLogger

def analyze_leaked_evidence(
    db: Session,
    file_path: str,
    investigator_id: int
) -> Tuple[bool, Dict[str, Any]]:
    """
    Forensic Extraction & Leak Attribution Pipeline:
    1. Compute evidence file SHA-256 hash
    2. Try LSB extraction
    3. Try DCT extraction
    4. Try Text ZW extraction
    5. Decrypt payload & verify AES-256-GCM authentication tag
    6. Correlate with DB (User & Document)
    7. Store evidence copy & LeakReport
    8. Generate JSON and Markdown Forensic Reports
    """
    if not os.path.exists(file_path):
        return False, {"error": "Evidence file does not exist."}

    evidence_hash = generate_file_sha256(file_path)
    file_ext = os.path.splitext(file_path)[1].lower()

    # Copy evidence to evidence storage
    evidence_filename = f"LEAK_{evidence_hash[:16]}{file_ext}"
    evidence_dest_path = str(EVIDENCE_DIR / evidence_filename)
    shutil.copy2(file_path, evidence_dest_path)

    extraction_method = "UNKNOWN"
    decrypted_payload = None
    extraction_status = "FAILED"
    error_detail = ""

    # Attempt extraction based on file type
    if file_ext in (".png", ".jpg", ".jpeg"):
        img = cv2.imread(file_path)
        if img is not None:
            # 1. Try LSB
            try:
                lsb_bytes = extract_lsb_watermark(img)
                ok, payload, msg = decrypt_payload(lsb_bytes)
                if ok:
                    decrypted_payload = payload
                    extraction_method = "LSB Steganography"
                    extraction_status = "VERIFIED"
            except Exception as e:
                error_detail += f"[LSB: {str(e)}] "

            # 2. Try DCT if LSB failed
            if not decrypted_payload:
                try:
                    dct_bytes = extract_dct_watermark(img)
                    ok, payload, msg = decrypt_payload(dct_bytes)
                    if ok:
                        decrypted_payload = payload
                        extraction_method = "DCT Frequency Domain Watermark"
                        extraction_status = "VERIFIED"
                except Exception as e:
                    error_detail += f"[DCT: {str(e)}]"

    elif file_ext == ".txt":
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                text_content = f.read()
            text_bytes = extract_text_watermark(text_content)
            if text_bytes:
                ok, payload, msg = decrypt_payload(text_bytes)
                if ok:
                    decrypted_payload = payload
                    extraction_method = "Zero-Width Unicode Text Watermark"
                    extraction_status = "VERIFIED"
        except Exception as e:
            error_detail = str(e)

    elif file_ext == ".pdf":
        try:
            import fitz
            pdf_doc = fitz.open(file_path)
            # 1. Try direct embedded image objects first (exact bit-level fidelity)
            for page in pdf_doc:
                for img_info in page.get_images():
                    xref = img_info[0]
                    base_img = pdf_doc.extract_image(xref)
                    img_np = cv2.imdecode(np.frombuffer(base_img["image"], np.uint8), cv2.IMREAD_COLOR)
                    if img_np is not None:
                        try:
                            lsb_bytes = extract_lsb_watermark(img_np)
                            ok, payload, msg = decrypt_payload(lsb_bytes)
                            if ok:
                                decrypted_payload = payload
                                extraction_method = "LSB Steganography (PDF Embedded Image)"
                                extraction_status = "VERIFIED"
                                break
                        except Exception:
                            pass

                        if not decrypted_payload:
                            try:
                                dct_bytes = extract_dct_watermark(img_np)
                                ok, payload, msg = decrypt_payload(dct_bytes)
                                if ok:
                                    decrypted_payload = payload
                                    extraction_method = "DCT Frequency Domain (PDF Embedded Image)"
                                    extraction_status = "VERIFIED"
                                    break
                            except Exception:
                                pass
                if decrypted_payload:
                    break

            # 2. If not found, try rendered pages
            if not decrypted_payload:
                from core.document_processor import render_pdf_to_images
                with open(file_path, "rb") as f:
                    pdf_bytes = f.read()
                page_images = render_pdf_to_images(pdf_bytes)
                for p_idx, p_img in enumerate(page_images):
                    try:
                        dct_bytes = extract_dct_watermark(p_img)
                        ok, payload, msg = decrypt_payload(dct_bytes)
                        if ok:
                            decrypted_payload = payload
                            extraction_method = f"DCT Frequency Domain (Rendered PDF Page {p_idx + 1})"
                            extraction_status = "VERIFIED"
                            break
                    except Exception as e:
                        error_detail += f"[PDF-P{p_idx+1}: {str(e)}] "
            pdf_doc.close()
        except Exception as e:
            error_detail += f"[PDF: {str(e)}]"

    # Database Correlation
    doc_id = None
    employee_id = None
    doc_name = "Unknown Document"
    employee_name = "Unattributed User"
    employee_email = "Unknown Email"
    confidence_score = 0.0

    if decrypted_payload and extraction_status == "VERIFIED":
        confidence_score = 1.0  # Cryptographic tag verified
        doc_id = decrypted_payload.get("doc_id")
        employee_id = decrypted_payload.get("employee_id")

        if doc_id:
            doc_rec = get_document_by_id(db, doc_id)
            if doc_rec:
                doc_name = doc_rec.name

        if employee_id:
            user_rec = get_user_by_id(db, employee_id)
            if user_rec:
                employee_name = user_rec.name
                employee_email = user_rec.email

    # Store LeakReport in DB
    report_db = create_leak_report(
        db=db,
        document_id=doc_id,
        leaked_file_path=evidence_dest_path,
        evidence_hash=evidence_hash,
        extracted_user_id=employee_id,
        confidence_score=confidence_score,
        extraction_status=extraction_status,
        metadata={
            "extraction_method": extraction_method,
            "investigator_id": investigator_id,
            "decrypted_payload": decrypted_payload,
            "error_detail": error_detail
        }
    )

    report_result = {
        "report_id": report_db.id,
        "evidence_file": evidence_filename,
        "evidence_hash": evidence_hash,
        "extraction_status": extraction_status,
        "extraction_method": extraction_method,
        "confidence_score": f"{confidence_score * 100:.1f}%",
        "document_id": doc_id or "Unidentified",
        "document_name": doc_name,
        "attributed_employee_id": employee_id or "Unidentified",
        "attributed_employee_name": employee_name,
        "attributed_employee_email": employee_email,
        "watermark_payload": decrypted_payload,
        "timestamp": datetime.utcnow().isoformat(),
        "error_detail": error_detail
    }

    # Save JSON and Markdown report files
    json_path = str(REPORTS_DIR / f"forensic_report_{report_db.id}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_result, f, indent=2)

    md_path = str(REPORTS_DIR / f"forensic_report_{report_db.id}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# DocsDefender Forensic Leak Attribution Report\n\n")
        f.write(f"- **Report ID**: `{report_db.id}`\n")
        f.write(f"- **Extraction Status**: `{extraction_status}`\n")
        f.write(f"- **Confidence Score**: `{confidence_score * 100:.1f}%`\n")
        f.write(f"- **Extraction Method**: `{extraction_method}`\n")
        f.write(f"- **Attributed Employee**: `{employee_name}` ({employee_email}, ID: {employee_id})\n")
        f.write(f"- **Document Leaked**: `{doc_name}` (ID: {doc_id})\n")
        f.write(f"- **Evidence SHA-256 Hash**: `{evidence_hash}`\n\n")

    AuditLogger.log_action(
        action="FORENSIC_EXTRACTION_PERFORMED",
        user_id=investigator_id,
        document_id=doc_id,
        status="SUCCESS" if extraction_status == "VERIFIED" else "WARNING",
        severity="CRITICAL" if extraction_status == "VERIFIED" else "INFO",
        metadata=report_result,
        db=db
    )

    return (extraction_status == "VERIFIED"), report_result
