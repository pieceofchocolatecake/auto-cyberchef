"""
detector.py - Encoding detection for AutoCyberChef.

Analyses an input string and returns a ranked list of encoding formats it
may represent.  Detection is done through a combination of:

    1. Regular expression pattern matching
    2. Character-set membership tests
    3. Decode-attempt validation
    4. Heuristic confidence scoring

Supported formats:
    Base64, Base32, Hex, Binary, URL, HTML entities,
    ROT13, Morse code, Caesar cipher
"""

import re
import base64
import binascii
from typing import List, Dict, Optional

from autochef.utils import (
    normalize_hex,
    normalize_binary,
    clean_base64,
    is_printable,
    printability_score,
)

# ---------------------------------------------------------------------------
# Character-set constants
# ---------------------------------------------------------------------------

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
BASE32_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
HEX_CHARS    = set("0123456789abcdefABCDEF")
BINARY_CHARS = set("01 ")
MORSE_CHARS  = set(".- /\t")

# Regex patterns
RE_URL_ENCODED   = re.compile(r'%[0-9a-fA-F]{2}')
RE_HTML_ENTITY   = re.compile(r'&(?:[a-zA-Z]{2,8}|#\d{1,5}|#x[0-9a-fA-F]{1,4});')
RE_BASE64_STRICT = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
RE_BASE32_STRICT = re.compile(r'^[A-Z2-7]+=*$')
RE_HEX_CLEAN     = re.compile(r'^[0-9a-fA-F]+$')
RE_BINARY_CLEAN  = re.compile(r'^[01 ]+$')
RE_MORSE         = re.compile(r'^[.\- \/]+$')

# Priority order used by pipeline.py when multiple encodings are detected
ENCODING_PRIORITY: List[str] = [
    "URL",
    "HTML",
    "Binary",
    "Hex",
    "Base32",
    "Base64",
    "Morse",
    "ROT13",
    "Caesar",
]


# ---------------------------------------------------------------------------
# Individual format detectors
# ---------------------------------------------------------------------------

def _check_base64(s: str) -> bool:
    """
    Return True if `s` is a valid Base64-encoded string.

    Validates character set, padding, and that the decoded bytes are
    non-empty.  Strings shorter than 4 characters are rejected.

    Args:
        s: Candidate string (leading/trailing whitespace already stripped).

    Returns:
        True if `s` appears to be Base64.
    """
    if len(s) < 4:
        return False
    padded = clean_base64(s)
    if not RE_BASE64_STRICT.match(padded):
        return False
    if len(padded) % 4 != 0:
        return False
    try:
        decoded = base64.b64decode(padded)
        return len(decoded) > 0
    except Exception:
        return False


def _check_base32(s: str) -> bool:
    """
    Return True if `s` is a valid Base32-encoded string.

    Args:
        s: Candidate string.

    Returns:
        True if `s` appears to be Base32.
    """
    upper = s.upper().strip()
    if len(upper) < 8:
        return False
    if not RE_BASE32_STRICT.match(upper):
        return False
    if len(upper) % 8 != 0:
        return False
    try:
        decoded = base64.b32decode(upper)
        return len(decoded) > 0
    except Exception:
        return False


def _check_hex(s: str) -> bool:
    """
    Return True if `s` represents a hexadecimal byte sequence.

    Accepts common variants:
        - Plain hex:        "48656c6c6f"
        - Space-separated:  "48 65 6c 6c 6f"
        - 0x prefix:        "0x48656c6c6f"
        - \\x escape style: "\\x48\\x65\\x6c\\x6c\\x6f"

    Args:
        s: Candidate string.

    Returns:
        True if `s` appears to be a hex-encoded byte sequence.
    """
    cleaned = normalize_hex(s)
    if not cleaned:
        return False
    if not RE_HEX_CLEAN.match(cleaned):
        return False
    if len(cleaned) % 2 != 0:
        return False
    if len(cleaned) < 2:
        return False
    try:
        bytes.fromhex(cleaned)
        return True
    except ValueError:
        return False


def _check_binary(s: str) -> bool:
    """
    Return True if `s` is a binary (base-2) encoded string.

    Accepts both continuous and space-separated 8-bit groups.

    Args:
        s: Candidate string.

    Returns:
        True if `s` appears to be binary-encoded text.
    """
    cleaned = normalize_binary(s)
    if not cleaned:
        return False
    if not all(c in '01' for c in cleaned):
        return False
    if len(cleaned) % 8 != 0:
        return False
    if len(cleaned) < 8:
        return False
    return True


def _check_url(s: str) -> bool:
    """
    Return True if `s` contains percent-encoded (URL-encoded) characters.

    Args:
        s: Candidate string.

    Returns:
        True if at least one %XX sequence is found.
    """
    return bool(RE_URL_ENCODED.search(s))


def _check_html(s: str) -> bool:
    """
    Return True if `s` contains HTML entity sequences.

    Matches named entities (&amp;), decimal (&#65;), and hex (&#x41;) forms.

    Args:
        s: Candidate string.

    Returns:
        True if at least one HTML entity is found.
    """
    return bool(RE_HTML_ENTITY.search(s))


def _check_rot13(s: str) -> bool:
    """
    Return True if ROT13 decoding of `s` produces more readable output.

    ROT13 is only considered when the string contains enough alphabetic
    characters to make the comparison meaningful.

    Args:
        s: Candidate string.

    Returns:
        True if `s` likely benefits from ROT13 decoding.
    """
    alpha_count = sum(1 for c in s if c.isalpha())
    if alpha_count < 4:
        return False
    decoded = s.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )
    return printability_score(decoded) >= printability_score(s)


def _check_morse(s: str) -> bool:
    """
    Return True if `s` looks like Morse code.

    Args:
        s: Candidate string.

    Returns:
        True if `s` contains only Morse-compatible characters and
        has at least one dot or dash.
    """
    stripped = s.strip()
    if not stripped:
        return False
    if not RE_MORSE.match(stripped):
        return False
    return '.' in stripped or '-' in stripped


def _check_caesar(s: str) -> bool:
    """
    Return True if `s` might be a Caesar-cipher–encoded string.

    Caesar cipher is always possible on alphabetic strings, but we set
    a minimum alpha character threshold to avoid false positives.

    Args:
        s: Candidate string.

    Returns:
        True if `s` is long enough to potentially be Caesar-encoded.
    """
    alpha_count = sum(1 for c in s if c.isalpha())
    return alpha_count >= 6


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_encoding(input_string: str) -> List[str]:
    """
    Detect possible encodings for the given input string.

    Runs all individual detectors and returns a list of encoding names
    sorted by their position in ENCODING_PRIORITY (highest priority first).

    Args:
        input_string: The string to analyse.

    Returns:
        List of detected encoding names.  May be empty if no encoding
        is recognised.

    Example:
        >>> detect_encoding("SGVsbG8=")
        ['Base64']
        >>> detect_encoding("48656c6c6f")
        ['Hex']
    """
    s = input_string.strip()
    if not s:
        return []

    detected: List[str] = []

    checks = {
        "URL":    _check_url,
        "HTML":   _check_html,
        "Binary": _check_binary,
        "Hex":    _check_hex,
        "Base32": _check_base32,
        "Base64": _check_base64,
        "Morse":  _check_morse,
        "ROT13":  _check_rot13,
        "Caesar": _check_caesar,
    }

    for name, checker in checks.items():
        try:
            if checker(s):
                detected.append(name)
        except Exception:
            continue

    # Sort by priority list order
    priority_map = {enc: i for i, enc in enumerate(ENCODING_PRIORITY)}
    detected.sort(key=lambda x: priority_map.get(x, len(ENCODING_PRIORITY)))

    return detected


def get_encoding_confidence(input_string: str) -> Dict[str, float]:
    """
    Return a confidence score (0.0 – 1.0) for each detected encoding.

    Scores are heuristic and reflect how well the input matches each
    format's typical characteristics.

    Args:
        input_string: The string to analyse.

    Returns:
        Dict mapping encoding name to confidence float.

    Example:
        >>> scores = get_encoding_confidence("SGVsbG8=")
        >>> scores["Base64"]
        0.9
    """
    s = input_string.strip()
    scores: Dict[str, float] = {}

    if not s:
        return scores

    detected = detect_encoding(s)

    for enc in detected:
        if enc == "Base64":
            score = 0.5
            if s.endswith('='):
                score += 0.2
            try:
                decoded_bytes = base64.b64decode(clean_base64(s))
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                score += 0.3 * printability_score(decoded_str)
            except Exception:
                pass
            scores["Base64"] = min(round(score, 2), 1.0)

        elif enc == "Base32":
            score = 0.55
            if s.upper().endswith('='):
                score += 0.2
            try:
                decoded_bytes = base64.b32decode(s.upper())
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                score += 0.25 * printability_score(decoded_str)
            except Exception:
                pass
            scores["Base32"] = min(round(score, 2), 1.0)

        elif enc == "Hex":
            score = 0.5
            cleaned = normalize_hex(s)
            try:
                decoded_bytes = bytes.fromhex(cleaned)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                score += 0.35 * printability_score(decoded_str)
            except Exception:
                pass
            if ' ' not in s and s.lower() == s:
                score += 0.05
            scores["Hex"] = min(round(score, 2), 1.0)

        elif enc == "Binary":
            score = 0.65
            if ' ' in s:
                score += 0.1  # Space-grouped binary is more deliberate
            scores["Binary"] = min(round(score, 2), 1.0)

        elif enc == "URL":
            matches = RE_URL_ENCODED.findall(s)
            score = min(0.4 + 0.06 * len(matches), 0.95)
            scores["URL"] = round(score, 2)

        elif enc == "HTML":
            matches = RE_HTML_ENTITY.findall(s)
            score = min(0.45 + 0.08 * len(matches), 0.95)
            scores["HTML"] = round(score, 2)

        elif enc == "Morse":
            scores["Morse"] = 0.75

        elif enc == "ROT13":
            scores["ROT13"] = 0.30  # Low: any alpha string is technically valid

        elif enc == "Caesar":
            scores["Caesar"] = 0.20  # Very low: purely heuristic

    return scores


def best_encoding(input_string: str) -> Optional[str]:
    """
    Return the single most likely encoding for `input_string`.

    Uses confidence scores to break ties when multiple encodings are detected.

    Args:
        input_string: The string to analyse.

    Returns:
        Name of the best-guess encoding, or None if nothing was detected.
    """
    scores = get_encoding_confidence(input_string)
    if not scores:
        return None
    return max(scores, key=lambda k: scores[k])
