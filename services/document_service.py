import os
import uuid
import cv2
import numpy as np
from typing import List, Tuple, Optional
from sqlalchemy.orm import Session

from config.settings import PROTECTED_DIR
from database.models import Document, User
from database.repositories import (
    create_document,
    get_document_by_id,
    grant_document_permission,
    has_document_permission,
    get_user_by_id
)
from core.crypto_steg import (
    generate_sha256,
    construct_payload,
    encrypt_payload,
    embed_lsb_watermark,
    embed_dct_watermark
)
from core.document_processor import (
    validate_uploaded_file,
    render_pdf_to_images,
    save_images_as_pdf,
    watermark_image_pages,
    embed_text_watermark,
    apply_visible_watermark_stamp
)
from services.audit_logger import AuditLogger

def process_and_store_document(
    db: Session,
    file_name: str,
    file_bytes: bytes,
    description: str,
    classification: str,
    owner_id: int,
    assigned_user_ids: List[int],
    watermark_strategy: str = "lsb"
) -> Document:
    """
    Complete Document Ingestion Pipeline:
    1. Validation
    2. Original SHA-256 hash generation
    3. Payload creation & AES-256-GCM encryption
    4. Invisible watermarking (LSB or DCT)
    5. Protected file storage
    6. Database metadata & permission persistence
    7. Audit logging
    """
    is_valid, err_msg = validate_uploaded_file(file_name, len(file_bytes), file_bytes)
    if not is_valid:
        raise ValueError(err_msg)

    ext = os.path.splitext(file_name)[1].lower()
    if not ext:
        if file_bytes.startswith(b"%PDF"):
            ext = ".pdf"
        elif file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            ext = ".png"
        elif file_bytes.startswith(b"\xff\xd8\xff"):
            ext = ".jpg"
        else:
            ext = ".txt"

    doc_id = str(uuid.uuid4())
    original_hash = generate_sha256(file_bytes)

    # 1. Create encrypted payload
    payload = construct_payload(doc_id=doc_id, employee_id=owner_id, doc_hash=original_hash)
    encrypted_payload = encrypt_payload(payload)

    # 2. Watermark document based on file type
    protected_filename = f"{doc_id}{ext}"
    protected_path = str(PROTECTED_DIR / protected_filename)

    visible_stamp = f"CONFIDENTIAL | {classification.upper()} | DOC: {doc_id[:8]}"

    if ext == ".pdf":
        page_images = render_pdf_to_images(file_bytes)
        watermarked_pages = watermark_image_pages(
            page_images,
            encrypted_payload,
            strategy=watermark_strategy,
            visible_stamp_text=visible_stamp
        )
        save_images_as_pdf(watermarked_pages, protected_path)

    elif ext in (".png", ".jpg", ".jpeg"):
        img_np = cv2.imdecode(np.frombuffer(file_bytes, np.uint8), cv2.IMREAD_COLOR)
        if watermark_strategy.lower() == "dct":
            h, w = img_np.shape[:2]
            if h < 512 or w < 512:
                img_np = cv2.resize(img_np, (max(512, w), max(512, h)), interpolation=cv2.INTER_CUBIC)

        img_stamped = apply_visible_watermark_stamp(img_np, visible_stamp)
        if watermark_strategy.lower() == "dct":
            w_img = embed_dct_watermark(img_stamped, encrypted_payload)
        else:
            w_img = embed_lsb_watermark(img_stamped, encrypted_payload)

        # Output PNG to avoid lossy compression destroying spatial watermark
        if ext in (".jpg", ".jpeg"):
            protected_filename = f"{doc_id}.png"
            protected_path = str(PROTECTED_DIR / protected_filename)
        cv2.imwrite(protected_path, w_img)

    elif ext == ".txt":
        text_str = file_bytes.decode("utf-8", errors="replace")
        w_text = embed_text_watermark(text_str, encrypted_payload)
        header = f"=== CONFIDENTIAL | {classification.upper()} | DOC ID: {doc_id[:8]} ===\n\n"
        with open(protected_path, "w", encoding="utf-8") as f:
            f.write(header + w_text)

    # 3. Store in DB
    doc = create_document(
        db=db,
        doc_id=doc_id,
        name=file_name,
        description=description,
        classification=classification,
        original_hash=original_hash,
        protected_file_path=protected_path,
        owner_id=owner_id,
        processing_status="processed"
    )

    # 4. Assign Permissions
    for uid in set([owner_id] + assigned_user_ids):
        grant_document_permission(db, doc_id=doc.id, user_id=uid, granted_by=owner_id)

    # 5. Audit Logging
    AuditLogger.log_action(
        action="DOCUMENT_UPLOADED",
        user_id=owner_id,
        document_id=doc.id,
        status="SUCCESS",
        metadata={
            "file_name": file_name,
            "classification": classification,
            "hash": original_hash,
            "watermark_strategy": watermark_strategy,
            "assigned_users_count": len(assigned_user_ids)
        },
        db=db
    )

    return doc

def get_protected_document_pages(db: Session, doc_id: str, user_id: int) -> List[np.ndarray]:
    """Retrieve document page images for protected viewer rendering."""
    if not has_document_permission(db, doc_id, user_id):
        raise PermissionError("User is not authorized to view this document.")

    doc = get_document_by_id(db, doc_id)
    if not doc or not os.path.exists(doc.protected_file_path):
        raise FileNotFoundError("Protected document file not found.")

    ext = os.path.splitext(doc.protected_file_path)[1].lower()

    if ext == ".pdf":
        with open(doc.protected_file_path, "rb") as f:
            pdf_bytes = f.read()
        return render_pdf_to_images(pdf_bytes)
    elif ext in (".png", ".jpg", ".jpeg"):
        img = cv2.imread(doc.protected_file_path)
        return [img] if img is not None else []
    elif ext == ".txt":
        with open(doc.protected_file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        # Render text onto an image canvas for consistent document viewing with visible overlay
        h, w = 800, 600
        canvas = np.full((h, w, 3), 255, dtype=np.uint8)
        y = 40
        for line in text.split("\n")[:30]:
            cv2.putText(canvas, line[:60], (30, y), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1, cv2.LINE_AA)
            y += 25
        return [canvas]
    return []

def generate_watermarked_copy_for_user(
    db: Session,
    doc_id: str,
    user_id: int,
    watermark_strategy: str = "lsb"
) -> Tuple[bytes, str, str]:
    """
    Generate an employee-personalized watermarked copy for download or export.
    Returns (file_bytes: bytes, filename: str, mime_type: str).
    """
    doc = get_document_by_id(db, doc_id)
    if not doc or not os.path.exists(doc.protected_file_path):
        raise FileNotFoundError("Protected document not found.")

    user = get_user_by_id(db, user_id)
    user_name = user.name if user else f"User {user_id}"

    # Build personalized encrypted payload
    payload = construct_payload(doc_id=doc.id, employee_id=user_id, doc_hash=doc.original_hash)
    encrypted_payload = encrypt_payload(payload)

    stamp_text = f"CONFIDENTIAL | ASSIGNED TO: {user_name} (ID: {user_id}) | DOC: {doc.id[:8]}"
    ext = os.path.splitext(doc.protected_file_path)[1].lower()

    if ext == ".pdf":
        with open(doc.protected_file_path, "rb") as f:
            pdf_bytes = f.read()
        page_images = render_pdf_to_images(pdf_bytes)
        watermarked_pages = watermark_image_pages(
            page_images,
            encrypted_payload,
            strategy=watermark_strategy,
            visible_stamp_text=stamp_text
        )
        temp_pdf = str(PROTECTED_DIR / f"temp_{uuid.uuid4()}.pdf")
        save_images_as_pdf(watermarked_pages, temp_pdf)
        with open(temp_pdf, "rb") as f:
            out_bytes = f.read()
        try:
            os.remove(temp_pdf)
        except OSError:
            pass
        return out_bytes, f"PROTECTED_{doc.name}", "application/pdf"

    elif ext in (".png", ".jpg", ".jpeg"):
        img_np = cv2.imread(doc.protected_file_path)
        if img_np is None:
            raise ValueError("Unable to read image file.")

        h, w = img_np.shape[:2]
        if watermark_strategy.lower() == "dct" and (h < 512 or w < 512):
            img_np = cv2.resize(img_np, (max(512, w), max(512, h)), interpolation=cv2.INTER_CUBIC)

        img_stamped = apply_visible_watermark_stamp(img_np, stamp_text)
        if watermark_strategy.lower() == "dct":
            w_img = embed_dct_watermark(img_stamped, encrypted_payload)
        else:
            w_img = embed_lsb_watermark(img_stamped, encrypted_payload)

        ok, enc_png = cv2.imencode(".png", w_img)
        base_name = os.path.splitext(doc.name)[0]
        return enc_png.tobytes(), f"PROTECTED_{base_name}.png", "image/png"

    elif ext == ".txt":
        with open(doc.protected_file_path, "r", encoding="utf-8", errors="replace") as f:
            text_str = f.read()
        w_text = embed_text_watermark(text_str, encrypted_payload)
        header = f"=== CONFIDENTIAL | ASSIGNED TO: {user_name.upper()} (ID: {user_id}) | DOC: {doc.id[:8]} ===\n\n"
        final_text = header + w_text
        return final_text.encode("utf-8"), f"PROTECTED_{doc.name}", "text/plain"

    else:
        with open(doc.protected_file_path, "rb") as f:
            return f.read(), f"PROTECTED_{doc.name}", "application/octet-stream"
