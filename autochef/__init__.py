"""
AutoCyberChef - Automatic encoding detection and decoding toolkit.

A lightweight CLI tool for detecting and decoding common encoding formats,
designed for CTF challenges, security analysis, and data processing workflows.

Supported encodings:
    - Base64 / Base32
    - Hexadecimal
    - Binary
    - URL encoding
    - ROT13
    - Morse code
    - HTML entities
    - Caesar cipher (brute-force)

Modules:
    detector     - Identify possible encodings in a string
    decoder      - Execute individual decode operations
    pipeline     - Auto multi-layer decode orchestration
    file_handler - Batch decode lines from files
    utils        - Shared helper functions
"""

__version__ = "1.0.0"
__author__ = "AutoCyberChef Contributors"
__license__ = "MIT"

from autochef.detector import detect_encoding, get_encoding_confidence
from autochef.decoder import (
    decode_base64,
    decode_base32,
    decode_hex,
    decode_binary,
    decode_url,
    decode_rot13,
    decode_morse,
    decode_html,
    decode_caesar,
)
from autochef.pipeline import auto_decode
from autochef.file_handler import decode_file

__all__ = [
    "detect_encoding",
    "get_encoding_confidence",
    "decode_base64",
    "decode_base32",
    "decode_hex",
    "decode_binary",
    "decode_url",
    "decode_rot13",
    "decode_morse",
    "decode_html",
    "decode_caesar",
    "auto_decode",
    "decode_file",
]
