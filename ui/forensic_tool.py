import os
import json
import streamlit as st
import pandas as pd
from database.database import SessionLocal
from database.repositories import list_leak_reports
from core.forensic_engine import analyze_leaked_evidence
from ui.components import render_header, render_metric_card
from config.settings import TEMP_DIR

def render_forensic_tool():
    render_header("Forensic Tracing & Leak Attribution Engine", "Analyze suspected leaked document images, extract hidden watermarks, and attribute leaks to responsible employees")

    current_user = st.session_state.get("user", {})
    investigator_id = current_user.get("id", 1)

    db = SessionLocal()
    try:
        tab1, tab2 = st.tabs(["🔍 Analyze Leaked Evidence", "📄 Historical Forensic Reports"])

        with tab1:
            st.markdown("#### Upload Suspected Leaked Document Photo / Image")
            uploaded_file = st.file_uploader("Upload Evidence File (PDF, JPEG, PNG, TXT)", type=["pdf", "png", "jpg", "jpeg", "txt"])

            if uploaded_file:
                # Save temporarily for analysis
                temp_path = str(TEMP_DIR / f"upload_analysis_{uploaded_file.name}")
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.getvalue())

                if uploaded_file.name.lower().endswith(".pdf"):
                    st.info(f"📄 Leaked Evidence File: **{uploaded_file.name}** ({len(uploaded_file.getvalue()) / 1024:.1f} KB)")
                else:
                    st.image(uploaded_file, caption="Uploaded Evidence Preview", width=350)

                if st.button("Execute Forensic Extraction Pipeline", type="primary", use_container_width=True):
                    with st.spinner("Extracting frequency & spatial watermarks, decrypting AES-256 payload & verifying cryptographic tag..."):
                        success, report = analyze_leaked_evidence(db, temp_path, investigator_id)

                    st.markdown("---")
                    st.markdown("### 📊 Forensic Analysis Results")

                    col1, col2, col3 = st.columns(3)
                    with col1:
                        status_cls = "success" if report["extraction_status"] == "VERIFIED" else "critical"
                        render_metric_card("Cryptographic Status", report["extraction_status"], status_cls)
                    with col2:
                        render_metric_card("Confidence Score", report["confidence_score"], "success" if report["extraction_status"] == "VERIFIED" else "critical")
                    with col3:
                        render_metric_card("Extraction Method", report["extraction_method"], "normal")

                    if success and report["extraction_status"] == "VERIFIED":
                        st.success("🎯 LEAK SUCCESSFULLY ATTRIBUTED!")
                        st.markdown(
                            f"""
                            <div style="background-color: #161b22; border: 2px solid #3fb950; border-radius: 8px; padding: 20px; margin-top: 15px;">
                                <h3 style="color: #3fb950; margin-top: 0;">Attributed Employee Details</h3>
                                <p><b>Employee Name</b>: <span style="color: #58a6ff;">{report['attributed_employee_name']}</span></p>
                                <p><b>Employee Email</b>: {report['attributed_employee_email']}</p>
                                <p><b>Employee ID</b>: {report['attributed_employee_id']}</p>
                                <h4 style="color: #58a6ff; margin-top: 15px;">Leaked Document Details</h4>
                                <p><b>Document Name</b>: {report['document_name']}</p>
                                <p><b>Document ID</b>: <code>{report['document_id']}</code></p>
                                <p><b>Evidence Hash (SHA-256)</b>: <code>{report['evidence_hash']}</code></p>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                        # Download Report Button
                        report_json_str = json.dumps(report, indent=2)
                        st.download_button(
                            label="📥 Download Forensic JSON Report",
                            data=report_json_str,
                            file_name=f"forensic_report_{report['report_id']}.json",
                            mime="application/json"
                        )
                    else:
                        st.error("❌ Watermark Extraction Failed or Unverified.")
                        st.caption(f"Details: {report.get('error_detail', 'No cryptographic payload recovered.')}")

        with tab2:
            st.markdown("#### Historical Forensic Investigation Reports")
            reports = list_leak_reports(db)
            if reports:
                data = []
                for r in reports:
                    data.append({
                        "Report ID": r.id,
                        "Status": r.extraction_status,
                        "Confidence": f"{(r.confidence_score or 1.0)*100:.1f}%",
                        "Document ID": (r.document_id[:8] + "...") if r.document_id else "N/A",
                        "Attributed User ID": r.extracted_user_id or "N/A",
                        "Created At": r.created_at.strftime("%Y-%m-%d %H:%M"),
                        "Evidence Hash": r.evidence_hash[:16] + "..."
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)
            else:
                st.info("No historical forensic reports logged.")
    finally:
        db.close()
