"""
utils.py - Shared helper functions for AutoCyberChef.

Provides character analysis, safe decode wrappers, string sanitization,
printability scoring, and result formatting utilities used across all modules.
"""

import re
import unicodedata
from typing import Optional, Tuple, Any


# ---------------------------------------------------------------------------
# Character / string analysis
# ---------------------------------------------------------------------------

def is_printable(s: str, threshold: float = 0.85) -> bool:
    """
    Return True if at least `threshold` fraction of characters are printable.

    Args:
        s:         String to evaluate.
        threshold: Minimum ratio of printable characters (default 0.85).

    Returns:
        True if the string is considered human-readable.
    """
    if not s:
        return False
    printable_count = sum(1 for c in s if c.isprintable() or c in ('\n', '\r', '\t'))
    return (printable_count / len(s)) >= threshold


def printability_score(s: str) -> float:
    """
    Return a 0.0–1.0 score reflecting how printable a string is.

    Args:
        s: String to score.

    Returns:
        Float between 0.0 (all non-printable) and 1.0 (fully printable).
    """
    if not s:
        return 0.0
    printable_count = sum(1 for c in s if c.isprintable() or c in ('\n', '\r', '\t'))
    return printable_count / len(s)


def looks_like_text(s: str) -> bool:
    """
    Heuristic check: does the string look like natural language or code?

    Checks for a mix of letters, spaces, and common punctuation rather than
    random byte sequences.

    Args:
        s: String to evaluate.

    Returns:
        True if the string resembles readable text.
    """
    if not s or len(s) < 2:
        return False
    alpha = sum(1 for c in s if c.isalpha())
    space = sum(1 for c in s if c.isspace())
    total = len(s)
    alpha_ratio = alpha / total
    space_ratio = space / total
    return alpha_ratio > 0.4 or (alpha_ratio > 0.25 and space_ratio > 0.05)



# Minimal word list for English detection
_ENGLISH_WORDS = frozenset({
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
    "for", "not", "on", "with", "he", "she", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her",
    "or", "an", "will", "my", "one", "all", "would", "there", "their",
    "what", "so", "up", "out", "if", "about", "who", "get", "go", "me",
    "when", "can", "like", "time", "no", "just", "him", "know", "see",
    "than", "then", "now", "look", "come", "two", "how", "our", "work",
    "new", "want", "any", "give", "day", "hello", "world", "yes", "okay",
    "here", "well", "very", "your", "more", "also", "back", "after",
    "first", "over", "think", "still", "never", "where", "right", "too",
    "same", "tell", "does", "set", "put", "end", "help", "good",
    "old", "few", "let", "try", "ask", "big", "turn", "hand", "high",
    "place", "hold", "man", "men", "own", "small", "found",
})


def looks_like_english(s: str) -> bool:
    """
    Return True if `s` contains at least one recognised common English word.

    Stronger than looks_like_text — requires actual vocabulary matches, not
    just a high alpha-character ratio.  Used by the pipeline to distinguish
    real plaintext from all-alphabetic ciphertext (ROT13, Caesar, etc.).

    For strings of 4 words or fewer, a single word hit is sufficient.
    For longer strings, at least 25% of words must be recognised.

    Args:
        s: String to evaluate.

    Returns:
        True if the string appears to be real English.
    """
    words = re.findall(r"[a-zA-Z]+", s.lower())
    if not words:
        return False
    hits = sum(1 for w in words if w in _ENGLISH_WORDS)
    if len(words) <= 4:
        return hits >= 1
    return (hits / len(words)) >= 0.25


def count_charset(s: str, charset: str) -> int:
    """
    Count how many characters of `s` appear in `charset`.

    Args:
        s:       Input string.
        charset: String of allowed characters.

    Returns:
        Number of characters from `s` that are in `charset`.
    """
    return sum(1 for c in s if c in charset)


def all_in_charset(s: str, charset: str) -> bool:
    """
    Return True if every character in `s` is present in `charset`.

    Args:
        s:       Input string.
        charset: Allowed characters.

    Returns:
        True if all characters of `s` belong to `charset`.
    """
    return all(c in charset for c in s)


# ---------------------------------------------------------------------------
# String sanitization
# ---------------------------------------------------------------------------

def strip_whitespace(s: str) -> str:
    """
    Strip leading/trailing whitespace including newlines and tabs.

    Args:
        s: Raw input string.

    Returns:
        Cleaned string.
    """
    return s.strip()


def normalize_hex(s: str) -> str:
    """
    Normalize a hex string by removing common prefixes and spacing.

    Handles formats like:
        - "0x1a2b3c"
        - "\\x1a\\x2b\\x3c"
        - "1a 2b 3c"
        - "1a2b3c"

    Args:
        s: Raw hex string.

    Returns:
        Clean lowercase hex string without separators.
    """
    s = s.strip()
    s = re.sub(r'\\x', '', s)
    s = re.sub(r'^0x', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s+', '', s)
    return s.lower()


def normalize_binary(s: str) -> str:
    """
    Normalize a binary string by removing spaces.

    Args:
        s: Raw binary string (may contain spaces between bytes).

    Returns:
        Continuous binary string without spaces.
    """
    return re.sub(r'\s+', '', s.strip())


def clean_base64(s: str) -> str:
    """
    Strip whitespace and ensure correct Base64 padding.

    Args:
        s: Potentially malformed Base64 string.

    Returns:
        Padded Base64 string ready for decoding.
    """
    s = s.strip()
    missing = len(s) % 4
    if missing:
        s += '=' * (4 - missing)
    return s


# ---------------------------------------------------------------------------
# Safe decode wrappers
# ---------------------------------------------------------------------------

def safe_decode_bytes(data: bytes, encodings: Optional[list] = None) -> Tuple[str, str]:
    """
    Try to decode bytes using a list of encodings, falling back gracefully.

    Args:
        data:      Raw bytes to decode.
        encodings: List of encoding names to try in order.
                   Defaults to ['utf-8', 'latin-1', 'ascii'].

    Returns:
        Tuple of (decoded_string, encoding_used).
    """
    if encodings is None:
        encodings = ['utf-8', 'latin-1', 'ascii']
    for enc in encodings:
        try:
            return data.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode('latin-1', errors='replace'), 'latin-1 (lossy)'


def safe_call(func, *args, **kwargs) -> Tuple[Any, bool]:
    """
    Call a function and catch any exception, returning a (result, success) tuple.

    Args:
        func:   Callable to invoke.
        *args:  Positional arguments forwarded to `func`.
        **kwargs: Keyword arguments forwarded to `func`.

    Returns:
        (result, True) on success, (error_message, False) on failure.
    """
    try:
        result = func(*args, **kwargs)
        return result, True
    except Exception as exc:
        return str(exc), False


# ---------------------------------------------------------------------------
# Result formatting
# ---------------------------------------------------------------------------

def format_layer(index: int, encoding: str, result: str) -> str:
    """
    Format a single pipeline layer for display.

    Args:
        index:    Layer number (1-based).
        encoding: Name of the encoding decoded in this layer.
        result:   Decoded string value.

    Returns:
        Human-readable layer description.
    """
    truncated = result if len(result) <= 60 else result[:57] + '...'
    return f"  Layer {index}: [{encoding}] -> {truncated}"


def format_detect_results(encodings: list) -> str:
    """
    Format a list of detected encodings for CLI output.

    Args:
        encodings: List of encoding name strings.

    Returns:
        Formatted multi-line string.
    """
    if not encodings:
        return "  No recognizable encoding detected."
    lines = ["Possible encodings:"]
    for enc in encodings:
        lines.append(f"  - {enc}")
    return '\n'.join(lines)


def format_confidence_results(scores: dict) -> str:
    """
    Format confidence scores as a sorted table.

    Args:
        scores: Dict mapping encoding name to float confidence.

    Returns:
        Formatted multi-line string with percentage confidence.
    """
    if not scores:
        return "  No encodings detected."
    lines = ["Encoding confidence scores:"]
    for enc, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
        bar_len = int(score * 20)
        bar = '█' * bar_len + '░' * (20 - bar_len)
        lines.append(f"  {enc:<12} {bar} {score * 100:.1f}%")
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Entropy analysis
# ---------------------------------------------------------------------------

def byte_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.

    Higher entropy suggests compressed, encrypted, or random data.
    Lower entropy suggests structured or human-readable text.

    Args:
        data: Byte sequence to analyze.

    Returns:
        Entropy value in bits per byte (0.0 – 8.0).
    """
    if not data:
        return 0.0
    import math
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        prob = count / total
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def string_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string (treated as UTF-8 bytes).

    Args:
        s: Input string.

    Returns:
        Entropy value in bits per byte.
    """
    return byte_entropy(s.encode('utf-8', errors='replace'))
