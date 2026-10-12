import os
import json
import struct
import hashlib
import uuid
import numpy as np
import cv2
from typing import Tuple, Dict, Any, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from config.settings import AES_MASTER_KEY

# Constants
MAGIC_HEADER = b"DOCDEF1"       # 7 bytes magic identifier for AES payload
LSB_MAGIC_HEADER = b"LSBDEF01" # 8 bytes magic header for LSB framing
DCT_MAGIC_HEADER = b"DCTDEF01" # 8 bytes magic header for DCT payload bits
PAYLOAD_VERSION = 1

# --- 1. Cryptographic Hashing ---

def generate_sha256(data: bytes) -> str:
    """Generate SHA-256 hash string for raw byte data."""
    return hashlib.sha256(data).hexdigest()

def generate_file_sha256(file_path: str) -> str:
    """Generate SHA-256 hash string for a file path."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_document_hash(data_or_path: str | bytes, expected_hash: str) -> bool:
    """Verify raw bytes or file against expected SHA-256 hash."""
    if isinstance(data_or_path, str) and os.path.isfile(data_or_path):
        current_hash = generate_file_sha256(data_or_path)
    elif isinstance(data_or_path, bytes):
        current_hash = generate_sha256(data_or_path)
    else:
        return False
    return current_hash.lower() == expected_hash.lower()

# --- 2. AES-256-GCM Payload Encryption & Decryption ---

def construct_payload(
    doc_id: str,
    employee_id: int,
    doc_hash: str = "",
    watermark_id: Optional[str] = None
) -> dict:
    """Construct structured metadata payload dictionary."""
    return {
        "version": PAYLOAD_VERSION,
        "watermark_id": watermark_id or str(uuid.uuid4()),
        "doc_id": doc_id,
        "employee_id": employee_id,
        "issued_at": int(os.getenv("CURRENT_TIME", 0)) or int(os.environ.get("TIMESTAMP", 0)) or 1700000000,
        "doc_hash_ref": doc_hash[:16] if doc_hash else ""
    }

def encrypt_payload(payload: dict, key: bytes = AES_MASTER_KEY) -> bytes:
    """
    Encrypt dictionary payload using AES-256-GCM.
    Output binary format:
    [ MAGIC_HEADER (7B) ][ NONCE (12B) ][ TAG (16B) ][ CIPHERTEXT (NB) ]
    """
    json_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    nonce = get_random_bytes(12)  # 96-bit nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(json_bytes)
    return MAGIC_HEADER + nonce + tag + ciphertext

def decrypt_payload(encrypted_data: bytes, key: bytes = AES_MASTER_KEY) -> Tuple[bool, Optional[dict], str]:
    """
    Decrypt AES-256-GCM encrypted payload and verify authentication tag.
    Returns (success: bool, payload_dict: Optional[dict], error_message: str).
    """
    if len(encrypted_data) < 7 + 12 + 16:
        return False, None, "Payload data too short to contain AES header, nonce, and tag."

    header = encrypted_data[:7]
    if header != MAGIC_HEADER:
        return False, None, f"Invalid AES magic header: {header.hex()} (expected {MAGIC_HEADER.hex()})."

    nonce = encrypted_data[7:19]
    tag = encrypted_data[19:35]
    ciphertext = encrypted_data[35:]

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        payload_dict = json.loads(decrypted_bytes.decode("utf-8"))
        return True, payload_dict, "Authentication tag verified successfully."
    except ValueError:
        return False, None, "Cryptographic authentication tag verification failed. Key incorrect or data corrupted."
    except Exception as e:
        return False, None, f"Decryption error: {str(e)}"

# --- 3. LSB Image Steganography ---

def embed_lsb_watermark(image_np: np.ndarray, encrypted_payload: bytes) -> np.ndarray:
    """
    Embed encrypted payload into image using Least Significant Bit (LSB) steganography.
    Framing format: [ LSB_MAGIC_HEADER (8B) ][ LENGTH_4B (uint32) ][ ENCRYPTED_PAYLOAD ]
    """
    framed_payload = LSB_MAGIC_HEADER + struct.pack(">I", len(encrypted_payload)) + encrypted_payload
    payload_bits = np.unpackbits(np.frombuffer(framed_payload, dtype=np.uint8))

    img_copy = image_np.copy()
    flat_img = img_copy.flatten()

    total_bits = len(payload_bits)
    if total_bits > len(flat_img):
        raise ValueError(f"Image capacity insufficient ({len(flat_img)} bits available, {total_bits} bits required).")

    # Clear LSB and write payload bit
    flat_img[:total_bits] = (flat_img[:total_bits] & 0xFE) | payload_bits

    return flat_img.reshape(img_copy.shape)

def extract_lsb_watermark(image_np: np.ndarray) -> bytes:
    """
    Extract encrypted payload from LSB image steganography.
    """
    flat_img = image_np.flatten()
    
    # Extract LSB bits
    lsb_bits = flat_img & 1
    # Convert bits to bytes
    extracted_bytes = np.packbits(lsb_bits).tobytes()

    # Locate LSB Magic Header
    header_idx = extracted_bytes.find(LSB_MAGIC_HEADER)
    if header_idx == -1:
        raise ValueError("No valid LSB watermark header found in image.")

    start_idx = header_idx + len(LSB_MAGIC_HEADER)
    if start_idx + 4 > len(extracted_bytes):
        raise ValueError("Truncated LSB header framing.")

    payload_len = struct.unpack(">I", extracted_bytes[start_idx:start_idx+4])[0]
    payload_start = start_idx + 4
    payload_end = payload_start + payload_len

    if payload_end > len(extracted_bytes):
        raise ValueError(f"Corrupted LSB payload length header ({payload_len} bytes exceeds extracted data).")

    return extracted_bytes[payload_start:payload_end]

# --- 4. DCT Frequency Domain Watermarking ---

def embed_dct_watermark(image_np: np.ndarray, encrypted_payload: bytes) -> np.ndarray:
    """
    Embed watermark into frequency domain using Discrete Cosine Transform (DCT) on 8x8 blocks.
    Framing: [ DCT_MAGIC_HEADER (8B) ][ LENGTH_4B ][ ENCRYPTED_PAYLOAD ]
    """
    framed_payload = DCT_MAGIC_HEADER + struct.pack(">I", len(encrypted_payload)) + encrypted_payload
    bits = np.unpackbits(np.frombuffer(framed_payload, dtype=np.uint8))
    
    # Process Y channel if color, or grayscale directly
    if len(image_np.shape) == 3 and image_np.shape[2] == 3:
        ycrcb = cv2.cvtColor(image_np, cv2.COLOR_BGR2YCrCb)
        channel = ycrcb[:, :, 0].astype(np.float32)
    else:
        channel = image_np.astype(np.float32)

    h, w = channel.shape
    blocks_h = h // 8
    blocks_w = w // 8
    max_bits = blocks_h * blocks_w

    if len(bits) > max_bits:
        raise ValueError(f"Image too small for DCT watermarking ({max_bits} bits capacity, {len(bits)} bits needed).")

    bit_idx = 0
    alpha = 25.0  # Modification step strength

    for i in range(blocks_h):
        for j in range(blocks_w):
            if bit_idx >= len(bits):
                break

            block = channel[i*8:(i+1)*8, j*8:(j+1)*8]
            dct_block = cv2.dct(block)

            # Mid-frequency coefficients: (4, 3) and (3, 4)
            bit = bits[bit_idx]
            v1, v2 = dct_block[4, 3], dct_block[3, 4]

            if bit == 1:
                if v1 <= v2 + alpha:
                    dct_block[4, 3] = (v1 + v2 + alpha) / 2.0 + 1.0
                    dct_block[3, 4] = (v1 + v2 - alpha) / 2.0 - 1.0
            else:
                if v2 <= v1 + alpha:
                    dct_block[3, 4] = (v1 + v2 + alpha) / 2.0 + 1.0
                    dct_block[4, 3] = (v1 + v2 - alpha) / 2.0 - 1.0

            idct_block = cv2.idct(dct_block)
            channel[i*8:(i+1)*8, j*8:(j+1)*8] = idct_block
            bit_idx += 1
        if bit_idx >= len(bits):
            break

    watermarked_channel = np.clip(channel, 0, 255).astype(np.uint8)

    if len(image_np.shape) == 3 and image_np.shape[2] == 3:
        ycrcb[:, :, 0] = watermarked_channel
        return cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2BGR)
    else:
        return watermarked_channel

def extract_dct_watermark(image_np: np.ndarray) -> bytes:
    """
    Extract watermark payload from DCT frequency domain blocks.
    """
    if len(image_np.shape) == 3 and image_np.shape[2] == 3:
        ycrcb = cv2.cvtColor(image_np, cv2.COLOR_BGR2YCrCb)
        channel = ycrcb[:, :, 0].astype(np.float32)
    else:
        channel = image_np.astype(np.float32)

    h, w = channel.shape
    blocks_h = h // 8
    blocks_w = w // 8

    bits = []
    for i in range(blocks_h):
        for j in range(blocks_w):
            block = channel[i*8:(i+1)*8, j*8:(j+1)*8]
            dct_block = cv2.dct(block)
            v1, v2 = dct_block[4, 3], dct_block[3, 4]
            bits.append(1 if v1 > v2 else 0)

    extracted_bytes = np.packbits(np.array(bits, dtype=np.uint8)).tobytes()

    header_idx = extracted_bytes.find(DCT_MAGIC_HEADER)
    if header_idx == -1:
        raise ValueError("No valid DCT watermark header found.")

    start_idx = header_idx + len(DCT_MAGIC_HEADER)
    if start_idx + 4 > len(extracted_bytes):
        raise ValueError("Truncated DCT payload length header.")

    payload_len = struct.unpack(">I", extracted_bytes[start_idx:start_idx+4])[0]
    payload_start = start_idx + 4
    payload_end = payload_start + payload_len

    if payload_end > len(extracted_bytes):
        raise ValueError("Corrupted DCT payload length.")

    return extracted_bytes[payload_start:payload_end]

# --- 5. Image Quality Metrics (PSNR / SSIM) ---

def calculate_psnr(img1: np.ndarray, img2: np.ndarray) -> float:
    """Calculate Peak Signal-to-Noise Ratio (PSNR) in dB between two images."""
    mse = np.mean((img1.astype(np.float64) - img2.astype(np.float64)) ** 2)
    if mse == 0:
        return 100.0  # Perfect match
    pixel_max = 255.0
    return float(20 * np.log10(pixel_max / np.sqrt(mse)))
