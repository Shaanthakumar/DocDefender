import time
import threading
from typing import List, Set, Optional, Dict, Any
from sqlalchemy.orm import Session

from config.settings import MAX_EXFILTRATION_SIZE_BYTES, NETWORK_SIMULATION_MODE
from services.audit_logger import AuditLogger
from database.database import SessionLocal

# Default Whitelisted IP addresses (Localhost, internal corporate range)
DEFAULT_WHITELIST_IPS: Set[str] = {
    "127.0.0.1",
    "localhost",
    "10.0.0.1",
    "192.168.1.1"
}

class NetworkEgressMonitor:
    """Scapy & Telemetry Outbound Egress Monitor."""

    def __init__(self, allowlist_ips: Optional[Set[str]] = None, max_size_bytes: int = MAX_EXFILTRATION_SIZE_BYTES):
        self.allowlist_ips = allowlist_ips or DEFAULT_WHITELIST_IPS
        self.max_size_bytes = max_size_bytes
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.accumulated_traffic: Dict[str, int] = {}  # dest_ip -> total_bytes

    def start_monitoring(self):
        """Start background network packet sniffer."""
        if self.is_running:
            return
        self.is_running = True
        self.sniffer_thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self.sniffer_thread.start()

    def stop_monitoring(self):
        """Stop network packet sniffer."""
        self.is_running = False

    def _run_sniffer(self):
        """Internal packet capture loop using Scapy if available."""
        try:
            from scapy.all import sniff, IP, TCP, UDP
            def packet_callback(pkt):
                if not self.is_running:
                    return
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    pkt_len = len(pkt)

                    if dst_ip not in self.allowlist_ips and not dst_ip.startswith("127."):
                        self.accumulated_traffic[dst_ip] = self.accumulated_traffic.get(dst_ip, 0) + pkt_len

                        if self.accumulated_traffic[dst_ip] > self.max_size_bytes:
                            total_mb = self.accumulated_traffic[dst_ip] / (1024 * 1024)
                            db = SessionLocal()
                            try:
                                AuditLogger.log_alert(
                                    event_type="EXFILTRATION_ATTEMPT",
                                    description=f"Large outbound transfer detected ({total_mb:.2f} MB) to non-whitelisted destination ({dst_ip})",
                                    severity="CRITICAL",
                                    metadata={"destination_ip": dst_ip, "bytes_transferred": self.accumulated_traffic[dst_ip]},
                                    db=db
                                )
                            finally:
                                db.close()
                            # Reset count to prevent spamming duplicate alerts
                            self.accumulated_traffic[dst_ip] = 0

            # Run sniff loop safely
            while self.is_running:
                sniff(count=10, prn=packet_callback, timeout=2.0, store=False)
        except Exception as e:
            # Scapy capture without Admin privileges will fail gracefully
            pass

_global_network_monitor: Optional[NetworkEgressMonitor] = None

def get_network_monitor() -> NetworkEgressMonitor:
    """Get or initialize global Scapy network monitor singleton."""
    global _global_network_monitor
    if _global_network_monitor is None:
        _global_network_monitor = NetworkEgressMonitor()
        _global_network_monitor.start_monitoring()
    return _global_network_monitor

def perform_real_network_egress(target_url: str, payload_size_mb: float, db: Session, user_id: Optional[int] = None) -> Dict[str, Any]:
    """Perform a real outbound network HTTP POST transmission with synthetic binary payload.
    Logs telemetry and validates egress threshold rules."""
    import urllib.request
    import urllib.error

    size_bytes = int(payload_size_mb * 1024 * 1024)
    # Generate random payload bytes
    payload = b"X" * min(size_bytes, 1024 * 1024 * 15)  # Cap at 15MB for network responsiveness
    
    start_t = time.time()
    status_code = 0
    error_msg = None

    try:
        req = urllib.request.Request(
            target_url,
            data=payload,
            headers={"User-Agent": "DocsDefender-DLP-Probe/1.0", "Content-Type": "application/octet-stream"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            status_code = resp.status
    except urllib.error.HTTPError as e:
        status_code = e.code
    except Exception as e:
        error_msg = str(e)

    duration = time.time() - start_t
    exceeded_threshold = payload_size_mb >= (MAX_EXFILTRATION_SIZE_BYTES / (1024 * 1024))

    desc = f"OUTBOUND EGRESS ATTEMPT: Transmitted {payload_size_mb:.2f} MB to destination [{target_url}]. Response: {status_code or error_msg} (Duration: {duration:.2f}s)"
    severity = "CRITICAL" if exceeded_threshold else "MEDIUM"
    
    AuditLogger.log_alert(
        event_type="EXFILTRATION_ATTEMPT",
        description=desc,
        severity=severity,
        user_id=user_id,
        metadata={
            "target_url": target_url,
            "size_mb": payload_size_mb,
            "status_code": status_code,
            "error": error_msg,
            "duration_sec": duration,
            "exceeded_threshold": exceeded_threshold
        },
        db=db
    )

    return {
        "status": "COMPLETED",
        "target_url": target_url,
        "size_mb": payload_size_mb,
        "status_code": status_code,
        "error": error_msg,
        "duration_sec": round(duration, 2),
        "alert_triggered": exceeded_threshold
    }

def simulate_network_exfiltration(
    db: Session,
    user_id: int,
    destination_domain: str = "mail.gmail.com",
    size_mb: float = 8.5
) -> Dict[str, Any]:
    """Simulate a network exfiltration security event for demonstration and testing."""
    size_bytes = int(size_mb * 1024 * 1024)
    event_desc = f"SIMULATED EXFILTRATION: Large outbound transfer of {size_mb:.2f} MB to non-whitelisted service ({destination_domain})."

    AuditLogger.log_alert(
        event_type="EXFILTRATION_ATTEMPT",
        description=event_desc,
        severity="CRITICAL",
        user_id=user_id,
        metadata={
            "destination_domain": destination_domain,
            "size_mb": size_mb,
            "bytes_transferred": size_bytes,
            "simulated": True
        },
        db=db
    )

    return {
        "status": "ALERT_TRIGGERED",
        "event_type": "EXFILTRATION_ATTEMPT",
        "destination": destination_domain,
        "size_mb": size_mb,
        "severity": "CRITICAL"
    }
