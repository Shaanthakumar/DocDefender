import datetime
import cv2
import numpy as np
import streamlit as st
from PIL import Image
from database.database import SessionLocal
from database.repositories import (
    list_documents_for_user,
    get_document_by_id,
    create_or_update_session,
    get_session_by_id
)
from services.document_service import get_protected_document_pages, generate_watermarked_copy_for_user
from ui.components import render_header, render_badge, render_session_locked_banner
from ui.styles import get_visible_watermark_html

def render_employee_viewer():
    render_header("Secure Document Viewer", "Protected employee document portal with dynamic screen watermarks and active behavioral security guard")

    user_info = st.session_state.get("user", {})
    user_id = user_info.get("id", 1)
    user_name = user_info.get("name", "Employee")

    db = SessionLocal()
    try:
        assigned_docs = list_documents_for_user(db, user_id)

        if not assigned_docs:
            st.info("No documents currently assigned to your account.")
            return

        # Sidebar Document Selector
        doc_map = {f"{d.name} [{d.classification}]": d for d in assigned_docs}
        selected_label = st.selectbox("Select Assigned Document to View", list(doc_map.keys()))
        selected_doc = doc_map[selected_label]

        # Session Registration & Lock Check
        active_session_id = st.session_state.get(f"active_session_{selected_doc.id}")
        if not active_session_id:
            sess = create_or_update_session(db, user_id=user_id, document_id=selected_doc.id)
            active_session_id = sess.id
            st.session_state[f"active_session_{selected_doc.id}"] = active_session_id

        # Query session lock state
        sess_rec = get_session_by_id(db, active_session_id)
        is_locked = sess_rec and sess_rec.session_status == "locked"

        # Document Information Bar
        st.markdown(
            f"**Document Name**: `{selected_doc.name}` &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"**Classification**: {render_badge(selected_doc.classification)} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"**Doc ID**: `{selected_doc.id[:8]}...` &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"**Session Status**: `{'🔴 LOCKED' if is_locked else '🟢 ACTIVE'}`",
            unsafe_allow_html=True
        )

        st.markdown("---")

        if is_locked:
            render_session_locked_banner(sess_rec.lock_reason or "Mobile Phone Detection Security Alert")
            st.warning("Document content obfuscated due to active security event.")
            return

        # Render Protected Document Pages with Dynamic Screen Watermark
        pages = get_protected_document_pages(db, selected_doc.id, user_id)

        if not pages:
            st.error("Unable to load document page images.")
            return

        page_num = 1
        if len(pages) > 1:
            page_num = st.slider("Page Navigation", 1, len(pages), 1)

        target_page_bgr = pages[page_num - 1]
        target_page_rgb = cv2.cvtColor(target_page_bgr, cv2.COLOR_BGR2RGB)

        # Generate Dynamic Watermark Overlay HTML
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        watermark_overlay_html = get_visible_watermark_html(
            employee_id=str(user_id),
            employee_name=user_name,
            doc_id=selected_doc.id,
            ip_address="127.0.0.1",
            timestamp=current_time_str
        )

        st.caption(f"Viewing Page {page_num} of {len(pages)} | Dynamic Watermark Applied")

        # Container with relative CSS positioning & watermark overlay
        st.markdown('<div class="watermarked-viewer-container">', unsafe_allow_html=True)
        st.markdown(watermark_overlay_html, unsafe_allow_html=True)
        st.image(target_page_rgb, use_container_width=True, caption=f"DocsDefender Protected Viewer - {selected_doc.name}")
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("#### 📥 Document Download (Watermarked & Cryptographically Traced)")
        st.caption("Downloaded copies are stamped with your identity and embedded with invisible cryptographic watermarks for leak detection.")
        
        try:
            dl_bytes, dl_name, dl_mime = generate_watermarked_copy_for_user(
                db=db,
                doc_id=selected_doc.id,
                user_id=user_id
            )
            st.download_button(
                label=f"⬇️ Download Watermarked Copy ({dl_name})",
                data=dl_bytes,
                file_name=dl_name,
                mime=dl_mime,
                use_container_width=True
            )
        except Exception as e:
            st.error(f"Unable to prepare download: {str(e)}")

    finally:
        db.close()
