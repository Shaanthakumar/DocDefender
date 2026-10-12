import os
import streamlit as st
import pandas as pd
from database.database import SessionLocal
from database.repositories import list_documents, list_users, get_document_by_id
from services.document_service import process_and_store_document, generate_watermarked_copy_for_user
from config.settings import PROTECTED_DIR
from ui.components import render_header, render_badge

def render_document_management():
    render_header("Document Management & Watermarking Pipeline", "Upload, watermark, classify, and manage employee access permissions")

    current_user = st.session_state.get("user", {})
    admin_id = current_user.get("id", 1)

    db = SessionLocal()
    try:
        users = list_users(db)
        employee_options = {f"{u.name} ({u.email}, ID: {u.id})": u.id for u in users if u.role.lower() == "employee"}

        tab1, tab2 = st.tabs(["📤 Upload & Watermark Document", "📁 Protected Document Repository"])

        with tab1:
            st.markdown("#### Confidential Document Ingestion Form")
            with st.form("upload_doc_form", clear_on_submit=True):
                file = st.file_uploader("Select Document File (PDF, PNG, JPEG, TXT)", type=["pdf", "png", "jpg", "jpeg", "txt"])
                doc_name = st.text_input("Document Display Name (Optional, defaults to original filename)", placeholder="e.g. Q4 Executive Financial Strategy")
                description = st.text_area("Description / Context", placeholder="Optional details about document content...")

                col1, col2 = st.columns(2)
                with col1:
                    classification = st.selectbox("Security Classification", ["Confidential", "Top Secret", "Secret", "Public"])
                with col2:
                    watermark_strategy = st.selectbox("Invisible Watermark Strategy", ["LSB Steganography (Spatial)", "DCT Frequency Domain (Resilient)"])

                selected_employees = st.multiselect("Assign Access Permissions to Employees", list(employee_options.keys()))

                submit = st.form_submit_button("Process, Watermark & Save Document", use_container_width=True)

                if submit:
                    if not file:
                        st.error("Please select a document file to upload.")
                    else:
                        file_bytes = file.read()
                        actual_ext = os.path.splitext(file.name)[1].lower()

                        # Determine display name and ensure extension matches uploaded file
                        display_name = doc_name.strip() if doc_name and doc_name.strip() else file.name
                        if actual_ext and not display_name.lower().endswith(actual_ext):
                            file_name_for_storage = f"{display_name}{actual_ext}"
                        else:
                            file_name_for_storage = display_name

                        assigned_ids = [employee_options[k] for k in selected_employees]
                        strategy_code = "dct" if "DCT" in watermark_strategy else "lsb"

                        try:
                            with st.spinner("Processing document: Generating SHA-256 hash, encrypting payload & embedding invisible watermark..."):
                                doc = process_and_store_document(
                                    db=db,
                                    file_name=file_name_for_storage,
                                    file_bytes=file_bytes,
                                    description=description,
                                    classification=classification,
                                    owner_id=admin_id,
                                    assigned_user_ids=assigned_ids,
                                    watermark_strategy=strategy_code
                                )
                            st.success(f"Document '{doc.name}' successfully processed and watermarked! (Doc ID: {doc.id[:8]}...)")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Document processing failed: {str(e)}")

        with tab2:
            st.markdown("#### Protected Document Inventory & Storage Location")
            st.info(f"📂 **Encrypted Storage Location on Disk**: `{PROTECTED_DIR}`\n\nAll ingested documents are invisibly watermarked, encrypted with AES-256-GCM, and stored safely in this server directory.")

            docs = list_documents(db)
            if docs:
                data = []
                for d in docs:
                    data.append({
                        "Doc ID": d.id[:8] + "...",
                        "Name": d.name,
                        "Classification": d.classification,
                        "Storage Path": os.path.basename(d.protected_file_path),
                        "SHA-256 Hash": d.original_hash[:16] + "...",
                        "Upload Date": d.upload_date.strftime("%Y-%m-%d %H:%M"),
                        "Status": d.processing_status,
                        "Permissions Count": len(d.permissions)
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)

                st.markdown("---")
                st.markdown("#### 📥 Download & Inspect Protected Documents")
                doc_select_map = {f"{d.name} (ID: {d.id[:8]}... | {d.classification})": d for d in docs}
                selected_doc_label = st.selectbox("Select Document to Download / Inspect", list(doc_select_map.keys()))
                target_doc = doc_select_map[selected_doc_label]

                col_d1, col_d2 = st.columns(2)

                with col_d1:
                    st.markdown("**1. Download Server Protected Copy**")
                    st.caption(f"File on disk: `{target_doc.protected_file_path}`")
                    if os.path.exists(target_doc.protected_file_path):
                        with open(target_doc.protected_file_path, "rb") as f:
                            file_bytes_to_download = f.read()
                        st.download_button(
                            label=f"⬇️ Download Protected File ({os.path.basename(target_doc.protected_file_path)})",
                            data=file_bytes_to_download,
                            file_name=f"PROTECTED_{target_doc.name}",
                            use_container_width=True
                        )
                    else:
                        st.error("Protected file missing on disk.")

                with col_d2:
                    st.markdown("**2. Generate Leaked Copy for Testing Attribution**")
                    st.caption("Personalizes document with a specific employee's watermark to test the Forensic Tool.")
                    if employee_options:
                        test_emp_label = st.selectbox("Select Target Employee", list(employee_options.keys()), key="test_emp_sel")
                        target_emp_id = employee_options[test_emp_label]

                        if st.button("Generate & Prepare Leaked Copy", key="gen_leak_btn", use_container_width=True):
                            try:
                                leaked_bytes, leaked_fname, leaked_mime = generate_watermarked_copy_for_user(
                                    db=db,
                                    doc_id=target_doc.id,
                                    user_id=target_emp_id
                                )
                                st.session_state["leaked_download"] = {
                                    "bytes": leaked_bytes,
                                    "name": leaked_fname,
                                    "mime": leaked_mime
                                }
                                st.success(f"Generated copy watermarked for {test_emp_label}!")
                            except Exception as e:
                                st.error(f"Error generating copy: {str(e)}")

                        if "leaked_download" in st.session_state:
                            ld = st.session_state["leaked_download"]
                            st.download_button(
                                label=f"⬇️ Download Leaked Sample ({ld['name']})",
                                data=ld["bytes"],
                                file_name=ld["name"],
                                mime=ld["mime"],
                                use_container_width=True
                            )
            else:
                st.info("No documents uploaded yet.")
    finally:
        db.close()
