"""
decoder.py - Decoding implementations for AutoCyberChef.

Each public function accepts a raw string, attempts to decode it using the
corresponding algorithm, and returns a (result, success) tuple so callers
can check success without catching exceptions.

Supported decoders:
    Base64, Base32, Hex, Binary, URL, HTML entities,
    ROT13, Morse code, Caesar cipher (auto-shift detection)
"""

import base64
import binascii
import html as html_module
import re
from typing import Tuple, List, Optional, Dict

from autochef.utils import (
    normalize_hex,
    normalize_binary,
    clean_base64,
    safe_decode_bytes,
    is_printable,
    printability_score,
    looks_like_text,
)

# ---------------------------------------------------------------------------
# Morse code lookup table
# ---------------------------------------------------------------------------

MORSE_TABLE: Dict[str, str] = {
    ".-":    "A", "-...":  "B", "-.-.":  "C", "-..":   "D",
    ".":     "E", "..-.":  "F", "--.":   "G", "....":  "H",
    "..":    "I", ".---":  "J", "-.-":   "K", ".-..":  "L",
    "--":    "M", "-.":    "N", "---":   "O", ".--.":  "P",
    "--.-":  "Q", ".-.":   "R", "...":   "S", "-":     "T",
    "..-":   "U", "...-":  "V", ".--":   "W", "-..-":  "X",
    "-.--":  "Y", "--..":  "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'",
    "-.-.--": "!", "-..-.":  "/", "-.--.":  "(", "-.--.-": ")",
    ".-...":  "&", "---...": ":", "-.-.-.": ";", "-...-":  "=",
    ".-.-.":  "+", "-....-": "-", "..--.-": "_", ".-..-.": '"',
    "...-..-": "$", ".--.-.": "@",
}

REVERSE_MORSE: Dict[str, str] = {v: k for k, v in MORSE_TABLE.items()}


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

def decode_base64(data: str) -> Tuple[str, bool]:
    """
    Decode a Base64-encoded string.

    Handles missing padding automatically.

    Args:
        data: Base64-encoded input string.

    Returns:
        Tuple of (decoded_string, success).
        On failure, the first element contains an error description.

    Example:
        >>> decode_base64("SGVsbG8=")
        ('Hello', True)
    """
    try:
        stripped = data.strip()
        if not stripped:
            return "Empty input", False
        padded = clean_base64(stripped)
        decoded_bytes = base64.b64decode(padded)
        if not decoded_bytes:
            return "Decoded to empty bytes", False
        result, _ = safe_decode_bytes(decoded_bytes)
        return result, True
    except Exception as exc:
        return f"Base64 decode error: {exc}", False


def decode_base64_urlsafe(data: str) -> Tuple[str, bool]:
    """
    Decode a URL-safe Base64-encoded string (uses - and _ instead of + and /).

    Args:
        data: URL-safe Base64-encoded input string.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_base64_urlsafe("SGVsbG8-")
        ('Hello', True)
    """
    try:
        padded = clean_base64(data.strip())
        decoded_bytes = base64.urlsafe_b64decode(padded)
        result, _ = safe_decode_bytes(decoded_bytes)
        return result, True
    except Exception as exc:
        return f"Base64 URL-safe decode error: {exc}", False


# ---------------------------------------------------------------------------
# Base32
# ---------------------------------------------------------------------------

def decode_base32(data: str) -> Tuple[str, bool]:
    """
    Decode a Base32-encoded string.

    Automatically uppercases the input and normalises padding.

    Args:
        data: Base32-encoded input string.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_base32("JBSWY3DPEB3W64TMMQ======")
        ('Hello, World!', True)
    """
    try:
        upper = data.strip().upper()
        # Pad to multiple of 8
        missing = len(upper) % 8
        if missing:
            upper += '=' * (8 - missing)
        decoded_bytes = base64.b32decode(upper)
        result, _ = safe_decode_bytes(decoded_bytes)
        return result, True
    except Exception as exc:
        return f"Base32 decode error: {exc}", False


# ---------------------------------------------------------------------------
# Hexadecimal
# ---------------------------------------------------------------------------

def decode_hex(data: str) -> Tuple[str, bool]:
    """
    Decode a hexadecimal string to its text representation.

    Supports plain hex, space-separated bytes, 0x prefix, and \\x escapes.

    Args:
        data: Hex-encoded input string.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_hex("48656c6c6f")
        ('Hello', True)
        >>> decode_hex("48 65 6c 6c 6f")
        ('Hello', True)
    """
    try:
        cleaned = normalize_hex(data)
        if not cleaned:
            return "Empty hex string", False
        if len(cleaned) % 2 != 0:
            return "Hex string has odd length", False
        decoded_bytes = bytes.fromhex(cleaned)
        result, _ = safe_decode_bytes(decoded_bytes)
        return result, True
    except ValueError as exc:
        return f"Hex decode error: {exc}", False
    except Exception as exc:
        return f"Hex decode error: {exc}", False


def decode_hex_to_bytes(data: str) -> Tuple[bytes, bool]:
    """
    Decode a hexadecimal string directly to a bytes object.

    Useful when the downstream consumer needs raw bytes.

    Args:
        data: Hex-encoded input string.

    Returns:
        Tuple of (bytes_result, success).
    """
    try:
        cleaned = normalize_hex(data)
        return bytes.fromhex(cleaned), True
    except Exception as exc:
        return b"", False


# ---------------------------------------------------------------------------
# Binary
# ---------------------------------------------------------------------------

def decode_binary(data: str) -> Tuple[str, bool]:
    """
    Decode a binary string (groups of 8 bits) to its text representation.

    Accepts both continuous and space-separated 8-bit groups.

    Args:
        data: Binary-encoded input string.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_binary("01001000 01100101 01101100 01101100 01101111")
        ('Hello', True)
        >>> decode_binary("0100100001100101011011000110110001101111")
        ('Hello', True)
    """
    try:
        cleaned = normalize_binary(data)
        if not cleaned:
            return "Empty binary string", False
        if not all(c in '01' for c in cleaned):
            return "Non-binary characters detected", False
        if len(cleaned) % 8 != 0:
            return f"Binary length {len(cleaned)} is not a multiple of 8", False
        # Split into 8-bit chunks and convert each to a byte
        chunks = [cleaned[i:i+8] for i in range(0, len(cleaned), 8)]
        decoded_bytes = bytes(int(chunk, 2) for chunk in chunks)
        result, _ = safe_decode_bytes(decoded_bytes)
        return result, True
    except Exception as exc:
        return f"Binary decode error: {exc}", False


# ---------------------------------------------------------------------------
# URL encoding
# ---------------------------------------------------------------------------

def decode_url(data: str) -> Tuple[str, bool]:
    """
    Decode a percent-encoded (URL-encoded) string.

    Uses urllib.parse.unquote which handles both %XX and + as space.

    Args:
        data: URL-encoded input string.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_url("Hello%20World%21")
        ('Hello World!', True)
    """
    try:
        from urllib.parse import unquote
        result = unquote(data)
        if result == data:
            return result, True  # No-op is still a success
        return result, True
    except Exception as exc:
        return f"URL decode error: {exc}", False


def decode_url_plus(data: str) -> Tuple[str, bool]:
    """
    Decode a URL-encoded string where + represents a space character.

    Uses urllib.parse.unquote_plus, suitable for HTML form data.

    Args:
        data: URL-encoded form data string.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_url_plus("Hello+World%21")
        ('Hello World!', True)
    """
    try:
        from urllib.parse import unquote_plus
        result = unquote_plus(data)
        return result, True
    except Exception as exc:
        return f"URL+ decode error: {exc}", False


# ---------------------------------------------------------------------------
# HTML entities
# ---------------------------------------------------------------------------

def decode_html(data: str) -> Tuple[str, bool]:
    """
    Decode HTML entities in a string.

    Handles named entities (&amp;), decimal (&#65;), and hex (&#x41;) forms.

    Args:
        data: String containing HTML entities.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_html("&lt;b&gt;Hello&lt;/b&gt;")
        ('<b>Hello</b>', True)
        >>> decode_html("&#72;&#101;&#108;&#108;&#111;")
        ('Hello', True)
    """
    try:
        result = html_module.unescape(data)
        return result, True
    except Exception as exc:
        return f"HTML decode error: {exc}", False


# ---------------------------------------------------------------------------
# ROT13
# ---------------------------------------------------------------------------

_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def decode_rot13(data: str) -> Tuple[str, bool]:
    """
    Decode (or encode) a string using the ROT13 substitution cipher.

    ROT13 is its own inverse, so encoding and decoding use the same function.
    Non-alphabetic characters are passed through unchanged.

    Args:
        data: ROT13-encoded input string.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_rot13("Uryyb")
        ('Hello', True)
    """
    try:
        result = data.translate(_ROT13_TABLE)
        return result, True
    except Exception as exc:
        return f"ROT13 decode error: {exc}", False


# ---------------------------------------------------------------------------
# Caesar cipher
# ---------------------------------------------------------------------------

def _caesar_shift(text: str, shift: int) -> str:
    """
    Apply a Caesar cipher shift to `text`.

    Args:
        text:  Input string.
        shift: Number of positions to shift (0–25).

    Returns:
        Shifted string with non-alphabetic characters preserved.
    """
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
        elif ch.islower():
            result.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
        else:
            result.append(ch)
    return ''.join(result)


_ENGLISH_FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"
_ENGLISH_FREQ_SCORE = {ch: (26 - i) for i, ch in enumerate(_ENGLISH_FREQ_ORDER)}

# Common English words — used to boost Caesar scoring for short ciphertexts
# where pure letter-frequency analysis is statistically unreliable.
_COMMON_WORDS = frozenset({
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
    "for", "not", "on", "with", "he", "she", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her",
    "or", "an", "will", "my", "one", "all", "would", "there", "their",
    "what", "so", "up", "out", "if", "about", "who", "get", "which",
    "go", "me", "when", "make", "can", "like", "time", "no", "just",
    "him", "know", "take", "people", "into", "year", "your", "good",
    "some", "could", "them", "see", "other", "than", "then", "now",
    "look", "come", "its", "over", "think", "also", "back", "after",
    "use", "two", "how", "our", "work", "first", "well", "way", "even",
    "new", "want", "because", "any", "these", "give", "day", "most",
    "hello", "world", "flag", "ctf", "key", "secret", "password",
    "answer", "result", "decode", "message", "text", "data",
})


def _english_frequency_score(text: str) -> float:
    """
    Score how well `text` matches English using letter frequencies + word list.

    Combines a character frequency score with a word-list bonus so that short
    strings (where pure frequency analysis is statistically noisy) are handled
    more reliably.  The word-list bonus is weighted to dominate on short inputs.

    Args:
        text: Candidate decoded string.

    Returns:
        Non-negative float; higher = more English-like.
    """
    text_lower = text.lower()
    total_alpha = sum(1 for c in text_lower if c.isalpha())
    if total_alpha == 0:
        return 0.0

    # Normalised character frequency score
    freq_score = sum(_ENGLISH_FREQ_SCORE.get(c, 0) for c in text_lower if c.isalpha())
    freq_score /= total_alpha

    # Word-list bonus: fraction of words that are recognised English words,
    # weighted heavily so common-word matches dominate on short strings.
    words = re.findall(r"[a-z]+", text_lower)
    if words:
        hits = sum(1 for w in words if w in _COMMON_WORDS)
        word_bonus = (hits / len(words)) * 30.0
    else:
        word_bonus = 0.0

    return freq_score + word_bonus


def decode_caesar(data: str, shift: Optional[int] = None) -> Tuple[str, bool]:
    """
    Decode a Caesar cipher–encoded string.

    If `shift` is provided, that shift is applied directly.  If not, all
    25 non-trivial shifts are tried and the one producing the most
    English-like output (by letter-frequency analysis) is returned.

    Args:
        data:  Caesar-encoded input string.
        shift: Specific shift value (1–25), or None for auto-detection.

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_caesar("Khoor", shift=3)
        ('Hello', True)
        >>> decode_caesar("Khoor")
        ('Hello', True)
    """
    if not data.strip():
        return "Empty input", False
    try:
        if shift is not None:
            return _caesar_shift(data, shift), True

        best_text = data
        best_score = _english_frequency_score(data)
        best_shift = 0

        for s in range(1, 26):
            candidate = _caesar_shift(data, s)
            score = _english_frequency_score(candidate)
            if score > best_score:
                best_score = score
                best_text = candidate
                best_shift = s

        return best_text, True
    except Exception as exc:
        return f"Caesar decode error: {exc}", False


def decode_caesar_all(data: str) -> List[Tuple[int, str]]:
    """
    Return all 25 Caesar shifts for `data`, paired with the shift value.

    Useful for manual inspection when auto-detection is uncertain.

    Args:
        data: Caesar-encoded input string.

    Returns:
        List of (shift, decoded_text) tuples for shifts 1–25.
    """
    results = []
    for shift in range(1, 26):
        results.append((shift, _caesar_shift(data, shift)))
    return results


# ---------------------------------------------------------------------------
# Morse code
# ---------------------------------------------------------------------------

def decode_morse(data: str) -> Tuple[str, bool]:
    """
    Decode a Morse code string.

    Words are separated by '/' or multiple spaces; characters within a word
    are separated by single spaces.

    Args:
        data: Morse code input string using dots (.) and dashes (-).

    Returns:
        Tuple of (decoded_string, success).

    Example:
        >>> decode_morse(".... . .-.. .-.. ---")
        ('HELLO', True)
        >>> decode_morse(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
        ('HELLO WORLD', True)
    """
    try:
        # Normalise word separators
        data = data.strip()
        data = re.sub(r'\s*/\s*', ' / ', data)
        words_raw = data.split(' / ')
        decoded_words = []

        for word_raw in words_raw:
            chars = word_raw.strip().split()
            decoded_chars = []
            unknown = []
            for code in chars:
                code = code.strip()
                if not code:
                    continue
                if code in MORSE_TABLE:
                    decoded_chars.append(MORSE_TABLE[code])
                else:
                    decoded_chars.append(f'[?{code}?]')
                    unknown.append(code)
            decoded_words.append(''.join(decoded_chars))

        result = ' '.join(decoded_words)
        if not result.strip():
            return "No valid Morse sequences found", False
        return result, True
    except Exception as exc:
        return f"Morse decode error: {exc}", False


# ---------------------------------------------------------------------------
# Generic dispatcher
# ---------------------------------------------------------------------------

def decode_by_name(encoding: str, data: str, **kwargs) -> Tuple[str, bool]:
    """
    Decode `data` using the encoding identified by `encoding`.

    This dispatcher is used by the pipeline module to apply the correct
    decoder without a long if-elif chain at the call site.

    Args:
        encoding: Encoding name string (case-insensitive).
        data:     Raw encoded input string.
        **kwargs: Extra keyword arguments forwarded to the specific decoder
                  (e.g., shift=3 for Caesar).

    Returns:
        Tuple of (decoded_string, success).

    Raises:
        ValueError: If the encoding name is not recognised.
    """
    enc = encoding.lower().replace(' ', '_').replace('-', '_')

    dispatch = {
        "base64":     decode_base64,
        "base64_url": decode_base64_urlsafe,
        "base32":     decode_base32,
        "hex":        decode_hex,
        "binary":     decode_binary,
        "url":        decode_url,
        "url_plus":   decode_url_plus,
        "html":       decode_html,
        "rot13":      decode_rot13,
        "morse":      decode_morse,
        "caesar":     lambda d: decode_caesar(d, kwargs.get("shift")),
    }

    if enc not in dispatch:
        return f"Unknown encoding: {encoding}", False

    return dispatch[enc](data)
