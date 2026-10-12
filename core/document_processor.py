import os
import io
import fitz  # PyMuPDF
import numpy as np
import cv2
from PIL import Image
from typing import List, Tuple, Optional
from core.crypto_steg import (
    embed_lsb_watermark,
    embed_dct_watermark,
    extract_lsb_watermark,
    extract_dct_watermark,
    decrypt_payload
)

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB max document upload limit

def validate_uploaded_file(file_name: str, file_size: int, content_bytes: bytes) -> Tuple[bool, str]:
    """Validate file extension, file size, and basic header contents."""
    ext = os.path.splitext(file_name)[1].lower()

    # Fallback: Infer extension from magic bytes / content if missing from file_name
    if not ext and content_bytes:
        if content_bytes.startswith(b"%PDF"):
            ext = ".pdf"
        elif content_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            ext = ".png"
        elif content_bytes.startswith(b"\xff\xd8\xff"):
            ext = ".jpg"
        else:
            try:
                content_bytes.decode("utf-8")
                ext = ".txt"
            except UnicodeDecodeError:
                pass

    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file extension '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"

    if file_size > MAX_FILE_SIZE_BYTES:
        return False, f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum allowed limit (25 MB)."

    if len(content_bytes) == 0:
        return False, "Uploaded file is empty (0 bytes)."

    # Basic magic byte check for images and PDFs
    if ext == ".pdf" and not content_bytes.startswith(b"%PDF"):
        return False, "File content does not match a valid PDF header."

    return True, "File validation passed."

def render_pdf_to_images(pdf_bytes: bytes, dpi: int = 150) -> List[np.ndarray]:
    """Render each page of a PDF into an OpenCV BGR image array using PyMuPDF."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    page_images = []
    zoom = dpi / 72.0
    mat = fitz.Matrix(zoom, zoom)

    for page in doc:
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img_np = np.frombuffer(pix.samples, dtype=np.uint8).reshape((pix.height, pix.width, 3))
        # PyMuPDF outputs RGB; convert to BGR for OpenCV
        img_bgr = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        page_images.append(img_bgr)

    doc.close()
    return page_images

def apply_visible_watermark_stamp(
    img_bgr: np.ndarray,
    stamp_text: str = "CONFIDENTIAL",
    opacity: float = 0.22
) -> np.ndarray:
    """Stamp a semi-transparent diagonal visible watermark across image pixels."""
    h, w = img_bgr.shape[:2]
    overlay = img_bgr.copy()
    font = cv2.FONT_HERSHEY_SIMPLEX
    scale = max(0.55, min(w, h) / 1000.0)
    color = (0, 0, 200)  # Red/maroon watermark text

    step_y = max(100, int(150 * scale))
    step_x = max(200, int(350 * scale))

    for y in range(60, h + 200, step_y):
        for x in range(-120, w + 300, step_x):
            cv2.putText(overlay, stamp_text, (x, y), font, scale, color, 2, cv2.LINE_AA)

    output = img_bgr.copy()
    cv2.addWeighted(overlay, opacity, img_bgr, 1.0 - opacity, 0, output)
    return output

def save_images_as_pdf(image_list_bgr: List[np.ndarray], output_pdf_path: str):
    """Combine a list of OpenCV BGR images into a single PDF file using PyMuPDF lossless PNG."""
    doc = fitz.open()
    for img_bgr in image_list_bgr:
        img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)
        pil_img = Image.fromarray(img_rgb)
        img_bytes_io = io.BytesIO()
        pil_img.save(img_bytes_io, format="PNG")
        img_bytes = img_bytes_io.getvalue()

        img_doc = fitz.open(stream=img_bytes, filetype="png")
        pdf_bytes = img_doc.convert_to_pdf()
        img_doc.close()

        page_doc = fitz.open("pdf", pdf_bytes)
        doc.insert_pdf(page_doc)
        page_doc.close()

    doc.save(output_pdf_path)
    doc.close()

def watermark_image_pages(
    pages_bgr: List[np.ndarray],
    encrypted_payload: bytes,
    strategy: str = "lsb",
    visible_stamp_text: Optional[str] = None
) -> List[np.ndarray]:
    """Apply optional visible stamp and invisible LSB/DCT watermarking to page images."""
    watermarked_pages = []
    for page in pages_bgr:
        # Resize small images if needed for DCT capacity
        h, w = page.shape[:2]
        if strategy.lower() == "dct" and (h < 512 or w < 512):
            page = cv2.resize(page, (max(512, w), max(512, h)), interpolation=cv2.INTER_CUBIC)

        # Apply visible watermark stamp if requested
        if visible_stamp_text:
            page = apply_visible_watermark_stamp(page, visible_stamp_text)

        if strategy.lower() == "lsb":
            w_page = embed_lsb_watermark(page, encrypted_payload)
        elif strategy.lower() == "dct":
            w_page = embed_dct_watermark(page, encrypted_payload)
        else:
            w_page = embed_lsb_watermark(page, encrypted_payload)
        watermarked_pages.append(w_page)

    return watermarked_pages

# Zero-Width Character Encoding for Text Documents
ZERO_WIDTH_SPACE = "\u200B"        # 0 bit
ZERO_WIDTH_NON_JOINER = "\u200C"   # 1 bit
ZERO_WIDTH_JOINER = "\u200D"       # Header separator

def embed_text_watermark(text_content: str, encrypted_payload: bytes) -> str:
    """Embed encrypted payload into text using zero-width Unicode whitespace characters."""
    bits = np.unpackbits(np.frombuffer(encrypted_payload, dtype=np.uint8))
    zw_sequence = "".join(ZERO_WIDTH_NON_JOINER if b == 1 else ZERO_WIDTH_SPACE for b in bits)
    # Append framed sequence at the end of the text or after first paragraph
    return text_content + ZERO_WIDTH_JOINER + zw_sequence + ZERO_WIDTH_JOINER

def extract_text_watermark(text_content: str) -> Optional[bytes]:
    """Extract zero-width watermark payload from text."""
    if ZERO_WIDTH_JOINER not in text_content:
        return None
    parts = text_content.split(ZERO_WIDTH_JOINER)
    if len(parts) < 3:
        return None
    zw_seq = parts[1]
    bits = []
    for char in zw_seq:
        if char == ZERO_WIDTH_NON_JOINER:
            bits.append(1)
        elif char == ZERO_WIDTH_SPACE:
            bits.append(0)
    if not bits:
        return None
    return np.packbits(np.array(bits, dtype=np.uint8)).tobytes()
