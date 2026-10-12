def get_custom_css() -> str:
    """Return dark enterprise security theme CSS with dynamic screen overlay styles."""
    return """
    <style>
    /* Dark Charcoal & Cyan Security Theme Foundation */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #161b22;
        border-right: 1px solid #30363d;
    }
    section[data-testid="stSidebar"] .stMarkdown h1, 
    section[data-testid="stSidebar"] .stMarkdown h2, 
    section[data-testid="stSidebar"] .stMarkdown h3 {
        color: #58a6ff;
    }

    /* Modern Glass-like Metric Cards */
    .metric-card {
        background: rgba(22, 27, 34, 0.85);
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 18px 20px;
        margin-bottom: 15px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    .metric-title {
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #8b949e;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #58a6ff;
    }
    .metric-value.critical {
        color: #f85149;
    }
    .metric-value.warning {
        color: #d29922;
    }
    .metric-value.success {
        color: #3fb950;
    }

    /* High-contrast Badges */
    .badge {
        display: inline-block;
        padding: 3px 10px;
        font-size: 0.75rem;
        font-weight: 600;
        border-radius: 12px;
        text-transform: uppercase;
    }
    .badge-confidential { background-color: #388bfd26; color: #58a6ff; border: 1px solid #388bfd66; }
    .badge-topsecret { background-color: #f8514926; color: #f85149; border: 1px solid #f8514966; }
    .badge-secret { background-color: #d2992226; color: #d29922; border: 1px solid #d2992266; }
    .badge-public { background-color: #3fb95026; color: #3fb950; border: 1px solid #3fb95066; }

    /* Security Header */
    .sec-header {
        background: linear-gradient(90deg, #161b22 0%, #0d1117 100%);
        border-bottom: 2px solid #1f6feb;
        padding: 15px 25px;
        margin-bottom: 25px;
        border-radius: 6px;
    }
    .sec-title {
        font-size: 1.6rem;
        font-weight: 700;
        color: #58a6ff;
        margin: 0;
    }
    .sec-subtitle {
        font-size: 0.9rem;
        color: #8b949e;
        margin: 0;
    }

    /* Dynamic Diagonal Visible Watermark Container Overlay */
    .watermarked-viewer-container {
        position: relative;
        overflow: hidden;
        border: 1px solid #30363d;
        border-radius: 8px;
        background-color: #161b22;
        padding: 20px;
    }

    .watermark-overlay {
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        pointer-events: none;
        z-index: 999;
        display: flex;
        flex-wrap: wrap;
        align-content: space-around;
        justify-content: space-around;
        transform: rotate(-45deg);
        opacity: 0.15;
        user-select: none;
    }

    .watermark-text-tile {
        font-family: monospace;
        font-size: 1.1rem;
        font-weight: 700;
        color: #58a6ff;
        padding: 40px 60px;
        text-shadow: 1px 1px 2px rgba(0,0,0,0.8);
        white-space: nowrap;
    }

    /* Locked Session Red Warning Shield Overlay */
    .session-locked-banner {
        background-color: #f851491a;
        border: 2px solid #f85149;
        border-radius: 8px;
        padding: 30px;
        text-align: center;
        margin: 20px 0;
    }
    .session-locked-title {
        color: #f85149;
        font-size: 1.6rem;
        font-weight: 800;
        margin-bottom: 10px;
    }
    </style>
    """

def get_visible_watermark_html(employee_id: str, employee_name: str, doc_id: str, ip_address: str, timestamp: str) -> str:
    """Generate dynamic diagonal semi-transparent CSS overlay HTML."""
    tile_text = f"CONFIDENTIAL | EMP:{employee_id} ({employee_name}) | DOC:{doc_id[:8]} | {timestamp} | IP:{ip_address}"
    tiles_html = "".join([f'<div class="watermark-text-tile">{tile_text}</div>' for _ in range(24)])
    return f'<div class="watermark-overlay">{tiles_html}</div>'
