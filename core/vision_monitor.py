import time
import cv2
import numpy as np
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from ultralytics import YOLO

from config.settings import YOLO_MODEL_PATH, YOLO_CONF_THRESHOLD, PHONE_DETECTION_PERSISTENCE_SEC
from services.session_manager import lock_active_user_sessions
from services.audit_logger import AuditLogger

# COCO Class ID for "cell phone" in YOLOv8
CELL_PHONE_CLASS_ID = 67

class PhoneDetector:
    """YOLOv8 Mobile Phone Detection Engine."""

    def __init__(self, model_path: str = YOLO_MODEL_PATH, conf_threshold: float = YOLO_CONF_THRESHOLD):
        self.conf_threshold = conf_threshold
        self.model = None
        self.model_loaded = False
        self.load_error = None
        try:
            self.model = YOLO(model_path)
            self.model_loaded = True
        except Exception as e:
            self.load_error = str(e)

    def detect_phone(self, frame: np.ndarray) -> Tuple[bool, float, Optional[Tuple[int, int, int, int]], np.ndarray]:
        """
        Run YOLOv8 inference on a frame to detect mobile phones.
        Returns: (detected: bool, max_confidence: float, bbox: (x1, y1, x2, y2), annotated_frame: np.ndarray)
        """
        if not self.model_loaded or self.model is None:
            return False, 0.0, None, frame

        annotated_frame = frame.copy()
        detected = False
        max_conf = 0.0
        best_bbox = None

        try:
            results = self.model(frame, verbose=False, conf=self.conf_threshold)
            for r in results:
                for box in r.boxes:
                    cls_id = int(box.cls[0].item())
                    conf = float(box.conf[0].item())
                    # Check if class is cell phone (67) or matches label name
                    label_name = r.names.get(cls_id, "").lower() if hasattr(r, "names") else ""
                    if cls_id == CELL_PHONE_CLASS_ID or "phone" in label_name:
                        detected = True
                        if conf > max_conf:
                            max_conf = conf
                            x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())
                            best_bbox = (x1, y1, x2, y2)
                            # Draw prominent red warning box
                            cv2.rectangle(annotated_frame, (x1, y1), (x2, y2), (0, 0, 255), 3)
                            cv2.putText(
                                annotated_frame,
                                f"PHONE DETECTED: {conf*100:.1f}%",
                                (x1, max(25, y1 - 10)),
                                cv2.FONT_HERSHEY_SIMPLEX,
                                0.7,
                                (0, 0, 255),
                                2
                            )
        except Exception as e:
            pass

        return detected, max_conf, best_bbox, annotated_frame

class VisionGuardTracker:
    """Tracks continuous phone detection duration to trigger session lock after >2 seconds."""

    def __init__(self, persistence_sec: float = PHONE_DETECTION_PERSISTENCE_SEC):
        self.persistence_sec = persistence_sec
        self.detection_start_time: Optional[float] = None
        self.detector = PhoneDetector()

    def process_frame(
        self,
        user_id: int,
        frame: np.ndarray,
        db: Session
    ) -> Tuple[bool, float, bool, np.ndarray]:
        """
        Process frame and evaluate persistence threshold.
        Returns: (detected: bool, conf: float, lock_triggered: bool, annotated_frame: np.ndarray)
        """
        detected, conf, bbox, annotated_frame = self.detector.detect_phone(frame)

        lock_triggered = False
        now = time.time()

        if detected:
            if self.detection_start_time is None:
                self.detection_start_time = now

            elapsed = now - self.detection_start_time

            # Overlay persistent warning timer on frame
            cv2.putText(
                annotated_frame,
                f"SECURITY GUARD: PHONE DETECTED ({elapsed:.1f}s / {self.persistence_sec:.1f}s)",
                (20, 40),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (0, 0, 255),
                2
            )

            if elapsed >= self.persistence_sec:
                # Persistence threshold exceeded -> Lock session!
                lock_active_user_sessions(db, user_id=user_id, reason=f"Mobile Phone Detected for >{self.persistence_sec}s")
                AuditLogger.log_alert(
                    event_type="PHONE_DETECTED",
                    description=f"Mobile phone detected continuously for {elapsed:.2f}s (conf: {conf*100:.1f}%)",
                    severity="CRITICAL",
                    user_id=user_id,
                    metadata={"confidence": conf, "duration_sec": elapsed},
                    db=db
                )
                lock_triggered = True
                self.detection_start_time = None  # Reset timer
        else:
            self.detection_start_time = None

        return detected, conf, lock_triggered, annotated_frame

def create_simulated_phone_frame() -> np.ndarray:
    """Generate synthetic test frame containing a cell phone for automated testing."""
    frame = np.full((480, 640, 3), 120, dtype=np.uint8)
    # Draw simulated smartphone body
    cv2.rectangle(frame, (250, 140), (390, 340), (30, 30, 30), -1)
    cv2.rectangle(frame, (260, 160), (380, 320), (220, 220, 220), -1)
    cv2.putText(frame, "SIMULATED PHONE", (265, 240), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 0, 0), 1)
    return frame
