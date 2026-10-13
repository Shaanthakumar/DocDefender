import os
import cv2
import numpy as np
import streamlit as st
import pandas as pd
from database.database import SessionLocal
from database.repositories import list_security_events, list_users
from core.vision_monitor import VisionGuardTracker, create_simulated_phone_frame
from core.network_monitor import (
    get_network_monitor,
    perform_real_network_egress,
    simulate_network_exfiltration
)
from core.filesystem_monitor import (
    get_filesystem_monitor,
    perform_real_confidential_file_op,
    simulate_filesystem_event
)
from config.settings import CONFIDENTIAL_DIR, MAX_EXFILTRATION_SIZE_BYTES
from services.session_manager import (
    lock_active_user_sessions,
    unlock_session,
    unlock_user_all_sessions,
    get_active_locked_sessions,
)
from ui.components import render_header, render_metric_card

def render_monitoring_dashboard():
    render_header("Security Operations Center (SOC) & Threat Guard", "Real-time AI camera vision guard, kernel filesystem observer, network exfiltration detection, and security response")

    user_info = st.session_state.get("user", {})
    current_user_id = user_info.get("id", 1)

    db = SessionLocal()
    try:
        sec_events = list_security_events(db, limit=100)
        active_alerts = [e for e in sec_events if e.status == "ACTIVE"]
        locked_sessions = get_active_locked_sessions(db)
        users = list_users(db)

        # Ensure background observers are initialized and active
        fs_monitor = get_filesystem_monitor()
        net_monitor = get_network_monitor()

        # Overview SOC Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            render_metric_card("Total Security Events", str(len(sec_events)), "normal")
        with col2:
            render_metric_card("Active Unresolved Alerts", str(len(active_alerts)), "critical" if len(active_alerts) > 0 else "success")
        with col3:
            render_metric_card("Locked User Sessions", str(len(locked_sessions)), "critical" if len(locked_sessions) > 0 else "success")
        with col4:
            render_metric_card("Camera Guard Status", "ACTIVE & ENFORCING", "success")

        st.markdown("---")
        tab1, tab2, tab3, tab4 = st.tabs([
            "🎥 Vision AI Camera Guard",
            "📁 Confidential Folder Observer",
            "🌐 Network Traffic & Exfiltration DLP",
            "🚨 Incident Log & Access Restoration"
        ])

        # TAB 1: VISION CAMERA GUARD
        with tab1:
            st.markdown("#### Real-time YOLOv8 Mobile Phone Guard")
            st.caption("Active camera monitor detects smartphones and mobile devices. Detection persistence >2.0s triggers immediate document session obfuscation and forced logout.")

            col_cam1, col_cam2 = st.columns([2, 1])

            with col_cam1:
                st.markdown("**Diagnostic Frame Inspection**")
                run_test_frame = st.button("Run YOLOv8 Phone Detection on Test Frame", use_container_width=True)
                if run_test_frame:
                    tracker = VisionGuardTracker()
                    sim_frame = create_simulated_phone_frame()
                    detected, conf, locked, annotated_frame = tracker.process_frame(current_user_id, sim_frame, db)

                    st.image(cv2.cvtColor(annotated_frame, cv2.COLOR_BGR2RGB), use_container_width=True, caption=f"YOLOv8 Output — Detected: {detected} | Confidence: {conf*100:.1f}%")

                    if locked:
                        st.error("🚨 SECURITY BREACH: Continuous phone detection triggered an active document session lock!")
                    elif detected:
                        st.warning(f"⚠️ Phone identified ({conf*100:.1f}% confidence). Persistent observation locks employee session.")
                    else:
                        st.success("✅ Clean frame. No optical capture device detected.")

            with col_cam2:
                st.markdown("**Guard Policies & Telemetry**")
                st.info(
                    "- **Neural Architecture**: `YOLOv8n` (Optimized INT8/FP32)\n"
                    "- **Target Class**: COCO Class 67 (`cell phone`)\n"
                    "- **Decision Threshold**: `70.0%`\n"
                    "- **Persistence Window**: `2.0 Seconds`\n"
                    "- **Mitigation**: Instant document blackout, token revocation, forced logout"
                )

        # TAB 2: REAL CONFIDENTIAL FOLDER OBSERVER
        with tab2:
            st.markdown("#### Kernel-Level Confidential Directory Observer")
            st.caption(f"Watchdog kernel observer actively monitoring physical directory: `{CONFIDENTIAL_DIR}`")

            # Status pill
            is_fs_alive = fs_monitor.observer.is_alive() if fs_monitor.observer else False
            status_color = "#10b981" if is_fs_alive else "#ff3366"
            st.markdown(f"**Observer Status**: <span style='color: {status_color}; font-weight: 700;'>● {'ACTIVE & POLLING KERNEL EVENTS' if is_fs_alive else 'OFFLINE'}</span>", unsafe_allow_html=True)

            col_fs1, col_fs2 = st.columns([1, 1])

            with col_fs1:
                st.markdown("**Active Directory File Browser**")
                os.makedirs(str(CONFIDENTIAL_DIR), exist_ok=True)
                current_files = os.listdir(str(CONFIDENTIAL_DIR))
                if current_files:
                    file_data = []
                    for fname in current_files:
                        fpath = os.path.join(str(CONFIDENTIAL_DIR), fname)
                        size_kb = os.path.getsize(fpath) / 1024 if os.path.exists(fpath) else 0
                        file_data.append({"Filename": fname, "Size": f"{size_kb:.2f} KB"})
                    st.dataframe(pd.DataFrame(file_data), use_container_width=True)
                else:
                    st.info(f"Directory `{CONFIDENTIAL_DIR}` is currently empty.")

            with col_fs2:
                st.markdown("**Live Kernel File Action Trigger**")
                st.caption("Perform real OS filesystem operations on the confidential directory. Watchdog detects creation, modification, or deletion in real time and writes to the audit log.")
                
                target_fname = st.text_input("Target Filename", value="Q4_Financial_Strategy.pdf")
                action_choice = st.selectbox("Filesystem Action", ["CREATE", "MODIFY", "DELETE"])

                if st.button("Execute Physical Filesystem Operation", use_container_width=True):
                    res = perform_real_confidential_file_op(action_choice, target_fname)
                    st.success(f"Executed real OS operation: {res['details']}")
                    st.info("Watchdog kernel observer captured this event and recorded an audit alert.")
                    st.rerun()

        # TAB 3: REAL NETWORK EGRESS & EXFILTRATION DLP
        with tab3:
            st.markdown("#### Real Outbound Egress & Data Exfiltration Monitor")
            st.caption(f"Continuous network monitoring inspecting outbound payloads. Exfiltration threshold: `{MAX_EXFILTRATION_SIZE_BYTES / (1024*1024):.1f} MB`.")

            is_net_alive = net_monitor.is_running
            net_status_color = "#10b981" if is_net_alive else "#ff3366"
            st.markdown(f"**Network Sniffer Status**: <span style='color: {net_status_color}; font-weight: 700;'>● {'ACTIVE (Scapy Packet Analyzer)' if is_net_alive else 'STOPPED'}</span>", unsafe_allow_html=True)

            col_net1, col_net2 = st.columns([1, 1])

            with col_net1:
                st.markdown("**Whitelisted Destination Domains**")
                st.code("\n".join(list(net_monitor.allowlist_ips)))
                st.caption("Transfers to external destinations outside this allowlist trigger immediate security events.")

            with col_net2:
                st.markdown("**Live Outbound Egress Probe**")
                st.caption("Transmit a real outbound network payload to an external endpoint to test data egress policies and verify DLP thresholds.")
                
                target_dest = st.text_input("Destination Endpoint URL", value="https://httpbin.org/post")
                transfer_size = st.slider("Payload Size (MB)", min_value=1.0, max_value=10.0, value=6.0, step=0.5)

                if st.button("Transmit Outbound Egress Payload", use_container_width=True):
                    with st.spinner("Transmitting real HTTP POST payload over network..."):
                        res = perform_real_network_egress(target_dest, transfer_size, db, user_id=current_user_id)
                    
                    if res["alert_triggered"]:
                        st.error(f"🚨 DLP EXFILTRATION ALERT TRIGGERED! Transmitted {res['size_mb']:.1f} MB (> 5.0 MB threshold) to {res['target_url']}. Status: {res['status_code'] or res['error']}.")
                    else:
                        st.warning(f"⚠️ Outbound transmission of {res['size_mb']:.1f} MB completed within threshold. Destination: {res['target_url']}.")
                    st.rerun()

        # TAB 4: INCIDENT LOG & RESTORATION
        with tab4:
            st.markdown("#### 🔒 Active Document Session Locks & Access Restoration")
            st.caption("Employees whose document viewing sessions are locked due to AI camera guard violations can be reviewed and unlocked here.")

            if locked_sessions:
                user_dict = {u.id: u for u in users}
                locked_by_user = {}
                for ls in locked_sessions:
                    locked_by_user.setdefault(ls.user_id, []).append(ls)

                for uid, s_list in locked_by_user.items():
                    u_obj = user_dict.get(uid)
                    uname = u_obj.name if u_obj else f"User {uid}"
                    uemail = u_obj.email if u_obj else "unknown"
                    latest_lock = s_list[0]
                    lock_time_str = latest_lock.locked_at.strftime("%Y-%m-%d %H:%M:%S") if latest_lock.locked_at else "Recent"

                    col_info, col_btn = st.columns([3, 1])
                    with col_info:
                        st.warning(
                            f"🔴 **Employee**: `{uname}` (`{uemail}`, ID: `{uid}`) &nbsp;|&nbsp; "
                            f"**Locked Sessions**: `{len(s_list)}` &nbsp;|&nbsp; "
                            f"**Locked At**: `{lock_time_str}`\n\n"
                            f"**Reason**: *{latest_lock.lock_reason or 'AI Camera Guard Threat Detected'}*"
                        )
                    with col_btn:
                        if st.button(f"🔓 Unlock & Restore Access", key=f"unlock_user_{uid}", use_container_width=True):
                            unlock_user_all_sessions(db, target_user_id=uid, admin_user_id=current_user_id)
                            st.success(f"Access successfully restored for {uname}!")
                            st.rerun()
                st.markdown("---")
            else:
                st.success("✅ No employee viewing sessions are currently locked.")
                st.markdown("---")

            st.markdown("#### 🚨 Security Incident Log")
            if sec_events:
                data = []
                for e in sec_events:
                    data.append({
                        "Event ID": e.id,
                        "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        "Event Type": e.event_type,
                        "Severity": e.severity,
                        "Description": e.description,
                        "Status": e.status,
                        "User ID": str(e.user_id) if e.user_id else "System"
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)
            else:
                st.info("No security events logged.")
    finally:
        db.close()

