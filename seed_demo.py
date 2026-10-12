"""
DocsDefender - Seed Demo Data Script
Populates the database with initial accounts (Administrator, Employee 1, Employee 2, Investigator),
sample confidential documents, and baseline audit logs for end-to-end demonstration.
"""

import os
import cv2
import numpy as np
import fitz  # PyMuPDF
from database.database import init_db, SessionLocal
from database.repositories import (
    create_user,
    get_user_by_email
)
from services.auth_service import hash_password
from services.document_service import process_and_store_document
from config.settings import BASE_DIR

SAMPLE_DOCS_DIR = BASE_DIR / "sample_documents"
SAMPLE_DOCS_DIR.mkdir(parents=True, exist_ok=True)

def create_sample_files():
    """Create sample PDF, PNG, and TXT files in sample_documents/."""
    # 1. Sample PNG
    png_path = str(SAMPLE_DOCS_DIR / "executive_strategy.png")
    if not os.path.exists(png_path):
        img = np.full((600, 800, 3), 245, dtype=np.uint8)
        cv2.putText(img, "DOCSDEFENDER CONFIDENTIAL STRATEGY 2026", (40, 80), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (150, 0, 0), 2)
        cv2.putText(img, "Target Growth: 45% Enterprise DLP Market Share", (40, 150), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (30, 30, 30), 1)
        cv2.putText(img, "Restricted Access - Do Not Copy or Photograph", (40, 220), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 200), 1)
        cv2.imwrite(png_path, img)

    # 2. Sample PDF
    pdf_path = str(SAMPLE_DOCS_DIR / "architecture_plan.pdf")
    if not os.path.exists(pdf_path):
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)  # A4
        page.insert_text((50, 80), "DOCSDEFENDER SYSTEM ARCHITECTURE", fontsize=18, color=(0.1, 0.3, 0.8))
        page.insert_text((50, 130), "Classification: TOP SECRET", fontsize=14, color=(0.9, 0.1, 0.1))
        page.insert_text((50, 180), "Component Overview:", fontsize=12, color=(0.1, 0.1, 0.1))
        page.insert_text((70, 210), "- Streamlit Enterprise UI Dashboard", fontsize=11, color=(0.2, 0.2, 0.2))
        page.insert_text((70, 235), "- FastAPI RESTful Security Backend", fontsize=11, color=(0.2, 0.2, 0.2))
        page.insert_text((70, 260), "- AES-256-GCM + LSB/DCT Watermarking Engine", fontsize=11, color=(0.2, 0.2, 0.2))
        page.insert_text((70, 285), "- YOLOv8n Computer Vision Behavioral Guard", fontsize=11, color=(0.2, 0.2, 0.2))
        doc.save(pdf_path)
        doc.close()

    # 3. Sample TXT
    txt_path = str(SAMPLE_DOCS_DIR / "confidential_memo.txt")
    if not os.path.exists(txt_path):
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("CONFIDENTIAL MEMORANDUM\n\nTo: Executive Board\nFrom: Chief Information Security Officer\nSubject: Security Audit Results\n\nDocsDefender has successfully mitigated all exfiltration vectors during Red Team testing.\n")

def seed_database():
    """Seed initial demo accounts and sample documents."""
    print("[+] Initializing database tables...")
    init_db()
    db = SessionLocal()

    try:
        # Seed Accounts
        accounts = [
            ("Security Admin", "admin@docsdefender.local", "AdminSecure2026!", "administrator"),
            ("Alice Johnson (Employee 1)", "employee1@docsdefender.local", "EmployeePass2026!", "employee"),
            ("Bob Smith (Employee 2)", "employee2@docsdefender.local", "EmployeePass2026!", "employee"),
            ("Carol Vance (Investigator)", "investigator@docsdefender.local", "InvestigatorPass2026!", "investigator"),
        ]

        users = {}
        for name, email, pw, role in accounts:
            u = get_user_by_email(db, email)
            if not u:
                pw_hash = hash_password(pw)
                u = create_user(db, name=name, email=email, password_hash=pw_hash, role=role)
                print(f"  [+] Created Account: {email} ({role})")
            else:
                print(f"  [OK] Account Exists: {email} ({role})")
            users[role] = u

        admin_id = users["administrator"].id
        emp1_id = users["employee"].id

        # Seed Documents
        png_path = str(SAMPLE_DOCS_DIR / "executive_strategy.png")
        if os.path.exists(png_path):
            with open(png_path, "rb") as f:
                p_bytes = f.read()
            doc1 = process_and_store_document(
                db=db,
                file_name="executive_strategy.png",
                file_bytes=p_bytes,
                description="2026 Executive Financial Strategy & Market Projections",
                classification="Top Secret",
                owner_id=admin_id,
                assigned_user_ids=[emp1_id],
                watermark_strategy="lsb"
            )
            print(f"  [+] Seeded Protected Document: {doc1.name} (Doc ID: {doc1.id[:8]}...)")

        pdf_path = str(SAMPLE_DOCS_DIR / "architecture_plan.pdf")
        if os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            doc2 = process_and_store_document(
                db=db,
                file_name="architecture_plan.pdf",
                file_bytes=pdf_bytes,
                description="DocsDefender System Architecture Blueprint",
                classification="Confidential",
                owner_id=admin_id,
                assigned_user_ids=[emp1_id],
                watermark_strategy="dct"
            )
            print(f"  [+] Seeded Protected Document: {doc2.name} (Doc ID: {doc2.id[:8]}...)")

        print("[OK] Demo Database Seed Complete!")

    finally:
        db.close()

if __name__ == "__main__":
    create_sample_files()
    seed_database()
