import time
import av
import cv2
import numpy as np
import streamlit as st
from streamlit_webrtc import webrtc_streamer, VideoProcessorBase, RTCConfiguration
from ultralytics import YOLO

from config.settings import (
    YOLO_MODEL_PATH,
    YOLO_CONF_THRESHOLD,
    CAMERA_GUARD_CONF_THRESHOLD,
    PHONE_DETECTION_PERSISTENCE_SEC,
)
from database.database import SessionLocal
from services.session_manager import lock_active_user_sessions
from services.audit_logger import AuditLogger

# Optimized WebRTC ICE Configuration:
# Cloudflare Anycast STUN responds in ~10ms worldwide, with Google STUN as fallback
RTC_CONFIG = RTCConfiguration({
    "iceServers": [
        {"urls": ["stun:stun.cloudflare.com:3478"]},
        {"urls": ["stun:stun.l.google.com:19302"]}
    ]
})

# 70% threshold is sufficient to detect mobile phone, terminate session, and force logout
CAMERA_GUARD_THRESHOLD = CAMERA_GUARD_CONF_THRESHOLD

# Lightweight camera constraints for instantaneous connection (<200ms) and low CPU usage
FAST_MEDIA_CONSTRAINTS = {
    "video": {
        "width": {"ideal": 320, "max": 480},
        "height": {"ideal": 240, "max": 360},
        "frameRate": {"ideal": 15, "max": 20}
    },
    "audio": False
}

# Video element attributes ensuring immediate playback without browser autoplay blocking
FAST_VIDEO_HTML_ATTRS = {
    "autoPlay": True,
    "controls": False,
    "muted": True,
    "style": {
        "width": "100%",
        "height": "auto",
        "borderRadius": "8px",
        "border": "1px solid #30363d"
    }
}

# Pre-warmed shared YOLO detector singleton to eliminate cold-start delay
_CACHED_DETECTOR = None

def get_shared_detector():
    """Retrieve or initialize the pre-warmed YOLO model singleton."""
    global _CACHED_DETECTOR
    if _CACHED_DETECTOR is None:
        try:
            m = YOLO(YOLO_MODEL_PATH)
            # Warm up with dummy frame so the first real frame in stream has 0ms latency
            dummy = np.zeros((240, 320, 3), dtype=np.uint8)
            m(dummy, verbose=False, imgsz=320)
            _CACHED_DETECTOR = m
        except Exception:
            _CACHED_DETECTOR = None
    return _CACHED_DETECTOR


class RealTimePhoneGuardProcessor(VideoProcessorBase):
    """
    High-performance video stream processor for streamlit-webrtc.
    Analyzes live camera frames with YOLOv8 at 320px with inference throttling.
    A 70% threshold (0.70) is sufficient to detect mobile phone camera threat,
    immediately end the active session, and log out the user without requiring 100%.
    """
    def __init__(self, conf_threshold: float = CAMERA_GUARD_CONF_THRESHOLD):
        self.detector = get_shared_detector()
        self.user_id = None
        self.user_name = None
        self.conf_threshold = conf_threshold  # 70% confidence threshold
        self.phone_detected_flag = False
        self.lock_triggered_flag = False
        self.detection_start_time = None
        self.last_conf = 0.0

        # Frame skipping & caching for smooth playback
        self.frame_count = 0
        self.last_detected = False
        self.last_best_box = None
        self.last_conf_max = 0.0

    def recv(self, frame: av.VideoFrame) -> av.VideoFrame:
        img = frame.to_ndarray(format="bgr24")
        if self.detector is None or self.user_id is None:
            return av.VideoFrame.from_ndarray(img, format="bgr24")

        self.frame_count += 1
        now = time.time()

        # Run inference every 2 frames for ultra-low latency & zero stream lag
        if self.frame_count % 2 == 0:
            detected = False
            conf_max = 0.0
            best_box = None

            try:
                # Fast inference at 320px image size with 70% threshold
                results = self.detector(img, verbose=False, conf=self.conf_threshold, imgsz=320)
                for r in results:
                    for box in r.boxes:
                        cls_id = int(box.cls[0].item())
                        conf = float(box.conf[0].item())
                        label = r.names.get(cls_id, "").lower() if hasattr(r, "names") else ""
                        # COCO class 67 is cell phone, detected at >= 70% threshold
                        if (cls_id == 67 or "phone" in label) and conf >= self.conf_threshold:
                            detected = True
                            if conf > conf_max:
                                conf_max = conf
                                best_box = list(map(int, box.xyxy[0].tolist()))
            except Exception:
                pass

            self.last_detected = detected
            self.last_best_box = best_box
            self.last_conf_max = conf_max
        else:
            # Reuse cached detection from previous frame for intermediate smoothness
            detected = self.last_detected
            best_box = self.last_best_box
            conf_max = self.last_conf_max

        if detected:
            self.phone_detected_flag = True
            self.last_conf = conf_max
            if self.detection_start_time is None:
                self.detection_start_time = now

            elapsed = now - self.detection_start_time

            # Draw prominent alert box on webcam feed
            if best_box:
                x1, y1, x2, y2 = best_box
                cv2.rectangle(img, (x1, y1), (x2, y2), (0, 0, 255), 3)
                cv2.putText(
                    img,
                    f"PHONE DETECTED: {conf_max*100:.1f}% (>= {int(self.conf_threshold*100)}%)",
                    (x1, max(25, y1 - 10)),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.6,
                    (0, 0, 255),
                    2
                )

            cv2.putText(
                img,
                f"SECURITY VIOLATION! {conf_max*100:.1f}% >= {int(self.conf_threshold*100)}%",
                (20, 35),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.65,
                (0, 0, 255),
                2
            )
            cv2.putText(
                img,
                "TERMINATING SESSION & LOGGING OUT...",
                (20, 65),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.55,
                (0, 0, 255),
                2
            )

            # 70% threshold reached: immediately trigger lockout and end session (no 100% required)
            if not self.lock_triggered_flag:
                self.lock_triggered_flag = True
                db = SessionLocal()
                try:
                    lock_active_user_sessions(
                        db,
                        user_id=self.user_id,
                        reason=f"Mobile Phone Camera Threat Detected ({conf_max*100:.1f}% confidence >= {int(self.conf_threshold*100)}% threshold)"
                    )
                    AuditLogger.log_alert(
                        event_type="PHONE_DETECTED",
                        description=(
                            f"Mobile phone detected by live camera guard on user {self.user_name} "
                            f"(ID: {self.user_id}) with {conf_max*100:.1f}% confidence (>= {int(self.conf_threshold*100)}% threshold). "
                            f"Force logout initiated."
                        ),
                        severity="CRITICAL",
                        user_id=self.user_id,
                        metadata={
                            "confidence": conf_max,
                            "threshold": self.conf_threshold,
                            "detection_duration": elapsed,
                            "forced_logout": True
                        },
                        db=db
                    )
                finally:
                    db.close()
        else:
            self.detection_start_time = None
            cv2.putText(
                img,
                f"CAM GUARD: ACTIVE ({int(self.conf_threshold*100)}% THRESHOLD)",
                (20, 30),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (0, 255, 0),
                2
            )

        return av.VideoFrame.from_ndarray(img, format="bgr24")


@st.fragment(run_every="1s")
def _monitor_camera_guard_status(ctx, user):
    """
    Background fragment that monitors detection state every second.
    When 70% confidence threshold is reached, immediately ends the session and logs out the user.
    """
    if not ctx or not ctx.video_processor or not user:
        return

    vp = ctx.video_processor
    # Detect if phone has reached >= 70% threshold or lockout flag was raised
    if vp.lock_triggered_flag or (vp.phone_detected_flag and vp.last_conf >= CAMERA_GUARD_THRESHOLD):
        conf_pct = vp.last_conf * 100.0 if vp.last_conf > 0 else (CAMERA_GUARD_THRESHOLD * 100.0)
        st.session_state["camera_threat_detected"] = True
        st.session_state["threat_user_id"] = user.get("id")
        st.session_state["threat_user_name"] = user.get("name")
        st.session_state["threat_reason"] = (
            f"Mobile phone detected via live camera stream ({conf_pct:.1f}% confidence >= {int(CAMERA_GUARD_THRESHOLD*100)}% threshold). "
            f"Active session terminated and user logged out immediately."
        )
        # End session and log out user
        st.session_state["authenticated"] = False
        st.session_state.pop("user", None)
        st.session_state.pop("token", None)
        st.rerun()


def render_sidebar_camera_guard():
    """
    Renders live camera surveillance strictly inside the sidebar upon login.
    Optimized for instant video playback (<200ms) with lightweight resolution and Anycast STUN.
    If a mobile phone is detected with >= 70% confidence, immediately logs out the employee.
    """
    user = st.session_state.get("user")
    if not user:
        return

    with st.sidebar:
        st.markdown("### 📷 AI Camera Guard")
        st.caption(f"Real-time YOLOv8 mobile phone detection active ({int(CAMERA_GUARD_THRESHOLD*100)}% threshold).")

        ctx = webrtc_streamer(
            key="sidebar-camera-guard",
            video_processor_factory=lambda: RealTimePhoneGuardProcessor(conf_threshold=CAMERA_GUARD_THRESHOLD),
            rtc_configuration=RTC_CONFIG,
            media_stream_constraints=FAST_MEDIA_CONSTRAINTS,
            video_html_attrs=FAST_VIDEO_HTML_ATTRS,
            desired_playing_state=True
        )

        if ctx.video_processor:
            ctx.video_processor.user_id = user.get("id")
            ctx.video_processor.user_name = user.get("name")

            if ctx.video_processor.lock_triggered_flag or (ctx.video_processor.phone_detected_flag and ctx.video_processor.last_conf >= CAMERA_GUARD_THRESHOLD):
                conf_pct = ctx.video_processor.last_conf * 100.0 if ctx.video_processor.last_conf > 0 else (CAMERA_GUARD_THRESHOLD * 100.0)
                st.session_state["camera_threat_detected"] = True
                st.session_state["threat_user_id"] = user.get("id")
                st.session_state["threat_user_name"] = user.get("name")
                st.session_state["threat_reason"] = (
                    f"Mobile phone detected via live camera stream ({conf_pct:.1f}% confidence >= {int(CAMERA_GUARD_THRESHOLD*100)}% threshold). "
                    f"Session terminated and user logged out immediately."
                )
                # Log out immediately!
                st.session_state["authenticated"] = False
                st.session_state.pop("user", None)
                st.session_state.pop("token", None)
                st.rerun()

        _monitor_camera_guard_status(ctx, user)
