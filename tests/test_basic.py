"""
tests/test_basic.py - Basic test suite for AutoCyberChef.

Covers:
    - Encoding detection
    - Individual decoders (Base64, Base32, Hex, Binary, URL, ROT13, Morse, HTML, Caesar)
    - Auto multi-layer pipeline
    - Utility functions
    - File handler (line-by-line)
    - Edge cases and error handling
"""

import sys
import os
import tempfile
import unittest

# Make sure the package is importable when tests are run from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from autochef.detector import detect_encoding, get_encoding_confidence, best_encoding
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
    decode_caesar_all,
    decode_by_name,
)
from autochef.pipeline import auto_decode, format_pipeline_output, pipeline_summary
from autochef.file_handler import decode_file, file_stats
from autochef.utils import (
    is_printable,
    printability_score,
    looks_like_text,
    normalize_hex,
    normalize_binary,
    clean_base64,
    byte_entropy,
)


# ---------------------------------------------------------------------------
# Detector tests
# ---------------------------------------------------------------------------

class TestDetector(unittest.TestCase):

    def test_detect_base64_hello(self):
        result = detect_encoding("SGVsbG8=")
        self.assertIn("Base64", result)

    def test_detect_base64_no_padding(self):
        # "Hello" in Base64 without padding
        result = detect_encoding("SGVsbG8")
        self.assertIn("Base64", result)

    def test_detect_hex_lowercase(self):
        result = detect_encoding("48656c6c6f")
        self.assertIn("Hex", result)

    def test_detect_hex_uppercase(self):
        result = detect_encoding("48656C6C6F")
        self.assertIn("Hex", result)

    def test_detect_binary(self):
        result = detect_encoding("0100100001100101011011000110110001101111")
        self.assertIn("Binary", result)

    def test_detect_binary_spaced(self):
        result = detect_encoding("01001000 01100101 01101100 01101100 01101111")
        self.assertIn("Binary", result)

    def test_detect_url_encoding(self):
        result = detect_encoding("Hello%20World%21")
        self.assertIn("URL", result)

    def test_detect_rot13(self):
        result = detect_encoding("Uryyb Jbeyq")
        self.assertIn("ROT13", result)

    def test_detect_morse(self):
        result = detect_encoding(".... . .-.. .-.. ---")
        self.assertIn("Morse", result)

    def test_detect_html_named(self):
        result = detect_encoding("&lt;b&gt;Hello&lt;/b&gt;")
        self.assertIn("HTML", result)

    def test_detect_html_decimal(self):
        result = detect_encoding("&#72;&#101;&#108;&#108;&#111;")
        self.assertIn("HTML", result)

    def test_detect_base32(self):
        result = detect_encoding("JBSWY3DPEB3W64TMMQ======")
        self.assertIn("Base32", result)

    def test_detect_empty_string(self):
        result = detect_encoding("")
        self.assertEqual(result, [])

    def test_detect_plaintext(self):
        # Plain English should not be flagged as Base64/Hex/etc.
        result = detect_encoding("This is plain English text.")
        self.assertNotIn("Base64", result)
        self.assertNotIn("Hex", result)
        self.assertNotIn("Binary", result)

    def test_confidence_base64(self):
        scores = get_encoding_confidence("SGVsbG8=")
        self.assertIn("Base64", scores)
        self.assertGreater(scores["Base64"], 0.5)

    def test_best_encoding_base64(self):
        enc = best_encoding("SGVsbG8=")
        self.assertEqual(enc, "Base64")

    def test_best_encoding_hex(self):
        enc = best_encoding("48656c6c6f")
        self.assertEqual(enc, "Hex")


# ---------------------------------------------------------------------------
# Decoder tests
# ---------------------------------------------------------------------------

class TestBase64Decoder(unittest.TestCase):

    def test_hello(self):
        result, ok = decode_base64("SGVsbG8=")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_hello_world(self):
        result, ok = decode_base64("SGVsbG8gV29ybGQ=")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello World")

    def test_missing_padding(self):
        result, ok = decode_base64("SGVsbG8")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_invalid_input(self):
        result, ok = decode_base64("!!!not_base64!!!")
        self.assertFalse(ok)

    def test_empty_string(self):
        result, ok = decode_base64("")
        self.assertFalse(ok)


class TestBase32Decoder(unittest.TestCase):

    def test_hello(self):
        result, ok = decode_base32("JBSWY3DP")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_hello_world(self):
        result, ok = decode_base32("JBSWY3DPEB3W64TMMQ======")
        self.assertTrue(ok)
        self.assertIn("Hello", result)

    def test_invalid(self):
        result, ok = decode_base32("!!!!!")
        self.assertFalse(ok)


class TestHexDecoder(unittest.TestCase):

    def test_hello_plain(self):
        result, ok = decode_hex("48656c6c6f")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_hello_spaced(self):
        result, ok = decode_hex("48 65 6c 6c 6f")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_hello_uppercase(self):
        result, ok = decode_hex("48656C6C6F")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_odd_length(self):
        result, ok = decode_hex("123")
        self.assertFalse(ok)

    def test_invalid_chars(self):
        result, ok = decode_hex("ZZZZZZ")
        self.assertFalse(ok)


class TestBinaryDecoder(unittest.TestCase):

    def test_hello_continuous(self):
        result, ok = decode_binary("0100100001100101011011000110110001101111")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_hello_spaced(self):
        result, ok = decode_binary("01001000 01100101 01101100 01101100 01101111")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_not_multiple_of_8(self):
        result, ok = decode_binary("0101010")
        self.assertFalse(ok)

    def test_invalid_chars(self):
        result, ok = decode_binary("012345678")
        self.assertFalse(ok)


class TestURLDecoder(unittest.TestCase):

    def test_space(self):
        result, ok = decode_url("Hello%20World")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello World")

    def test_special_chars(self):
        result, ok = decode_url("Hello%21%40%23")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello!@#")

    def test_no_encoding(self):
        result, ok = decode_url("plain text")
        self.assertTrue(ok)
        self.assertEqual(result, "plain text")


class TestROT13Decoder(unittest.TestCase):

    def test_hello(self):
        result, ok = decode_rot13("Uryyb")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_hello_world(self):
        result, ok = decode_rot13("Uryyb Jbeyq")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello World")

    def test_inverse(self):
        # ROT13 applied twice returns original
        r1, _ = decode_rot13("Hello")
        r2, _ = decode_rot13(r1)
        self.assertEqual(r2, "Hello")

    def test_numbers_unchanged(self):
        result, ok = decode_rot13("Hello 123")
        self.assertTrue(ok)
        self.assertEqual(result, "Uryyb 123")


class TestMorseDecoder(unittest.TestCase):

    def test_hello(self):
        result, ok = decode_morse(".... . .-.. .-.. ---")
        self.assertTrue(ok)
        self.assertEqual(result, "HELLO")

    def test_hello_world(self):
        result, ok = decode_morse(".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
        self.assertTrue(ok)
        self.assertEqual(result, "HELLO WORLD")

    def test_sos(self):
        result, ok = decode_morse("... --- ...")
        self.assertTrue(ok)
        self.assertEqual(result, "SOS")

    def test_empty(self):
        result, ok = decode_morse("")
        self.assertFalse(ok)


class TestHTMLDecoder(unittest.TestCase):

    def test_angle_brackets(self):
        result, ok = decode_html("&lt;b&gt;Hello&lt;/b&gt;")
        self.assertTrue(ok)
        self.assertEqual(result, "<b>Hello</b>")

    def test_ampersand(self):
        result, ok = decode_html("Hello &amp; World")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello & World")

    def test_decimal_entities(self):
        result, ok = decode_html("&#72;&#101;&#108;&#108;&#111;")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_no_entities(self):
        result, ok = decode_html("plain text")
        self.assertTrue(ok)
        self.assertEqual(result, "plain text")


class TestCaesarDecoder(unittest.TestCase):

    def test_shift_3(self):
        result, ok = decode_caesar("Khoor", shift=3)
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_auto_detect(self):
        result, ok = decode_caesar("Khoor Zruog")
        self.assertTrue(ok)
        self.assertIn("Hello", result)

    def test_all_shifts(self):
        shifts = decode_caesar_all("Khoor")
        self.assertEqual(len(shifts), 25)
        decoded_texts = [text for _, text in shifts]
        self.assertIn("Hello", decoded_texts)

    def test_empty(self):
        result, ok = decode_caesar("")
        self.assertFalse(ok)


class TestDecodeByName(unittest.TestCase):

    def test_base64_by_name(self):
        result, ok = decode_by_name("Base64", "SGVsbG8=")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_hex_by_name(self):
        result, ok = decode_by_name("Hex", "48656c6c6f")
        self.assertTrue(ok)
        self.assertEqual(result, "Hello")

    def test_unknown_encoding(self):
        result, ok = decode_by_name("UnknownFormat", "data")
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# Pipeline tests
# ---------------------------------------------------------------------------

class TestPipeline(unittest.TestCase):

    def test_single_layer_base64(self):
        steps, final = auto_decode("SGVsbG8=")
        self.assertEqual(final, "Hello")
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0][0], "Base64")

    def test_double_layer_base64(self):
        # "SGVsbG8=" in Base64 -> "Hello" needs two layers
        # "U0dWc2JHOD0=" -> "SGVsbG8=" -> "Hello"
        steps, final = auto_decode("U0dWc2JIOD0=")
        self.assertGreaterEqual(len(steps), 1)

    def test_single_layer_hex(self):
        steps, final = auto_decode("48656c6c6f")
        self.assertEqual(final, "Hello")

    def test_plaintext_passthrough(self):
        steps, final = auto_decode("Hello World")
        # Plaintext should be returned unchanged with no decode steps
        self.assertEqual(steps, [])
        self.assertEqual(final, "Hello World")

    def test_empty_input(self):
        steps, final = auto_decode("")
        self.assertEqual(steps, [])

    def test_pipeline_summary(self):
        steps, _ = auto_decode("SGVsbG8=")
        summary = pipeline_summary(steps)
        self.assertIn("Base64", summary)

    def test_format_output(self):
        steps, final = auto_decode("SGVsbG8=")
        output = format_pipeline_output(steps, final)
        self.assertIn("Hello", output)
        self.assertIn("Base64", output)


# ---------------------------------------------------------------------------
# File handler tests
# ---------------------------------------------------------------------------

class TestFileHandler(unittest.TestCase):

    def _make_temp_file(self, content: str) -> str:
        """Write content to a temporary file and return its path."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            return f.name

    def test_decode_base64_lines(self):
        path = self._make_temp_file("SGVsbG8=\nV29ybGQ=\n")
        try:
            results = decode_file(path)
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["result"], "Hello")
            self.assertEqual(results[1]["result"], "World")
        finally:
            os.unlink(path)

    def test_decode_hex_lines(self):
        path = self._make_temp_file("48656c6c6f\n")
        try:
            results = decode_file(path)
            self.assertEqual(results[0]["result"], "Hello")
        finally:
            os.unlink(path)

    def test_mixed_encodings(self):
        path = self._make_temp_file("SGVsbG8=\n48656c6c6f\n")
        try:
            results = decode_file(path)
            self.assertEqual(len(results), 2)
            for r in results:
                self.assertEqual(r["result"], "Hello")
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            decode_file("/nonexistent/path/file.txt")

    def test_file_stats(self):
        path = self._make_temp_file("SGVsbG8=\n48656c6c6f\n")
        try:
            stats = file_stats(path)
            self.assertEqual(stats["total_lines"], 2)
            self.assertGreaterEqual(stats["decoded_lines"], 1)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestUtils(unittest.TestCase):

    def test_is_printable_hello(self):
        self.assertTrue(is_printable("Hello, World!"))

    def test_is_printable_binary_garbage(self):
        self.assertFalse(is_printable("\x00\x01\x02\x03\x04\x05"))

    def test_printability_score_full(self):
        self.assertAlmostEqual(printability_score("Hello"), 1.0)

    def test_printability_score_zero(self):
        score = printability_score("\x00\x01\x02")
        self.assertLess(score, 0.5)

    def test_looks_like_text_true(self):
        self.assertTrue(looks_like_text("Hello World this is text"))

    def test_looks_like_text_false(self):
        self.assertFalse(looks_like_text("0101010101010101"))

    def test_normalize_hex_0x_prefix(self):
        self.assertEqual(normalize_hex("0x48656c6c6f"), "48656c6c6f")

    def test_normalize_hex_space_separated(self):
        self.assertEqual(normalize_hex("48 65 6c 6c 6f"), "48656c6c6f")

    def test_normalize_hex_backslash_x(self):
        self.assertEqual(normalize_hex("\\x48\\x65\\x6c"), "48656c")

    def test_normalize_binary_spaces(self):
        self.assertEqual(normalize_binary("01001000 01100101"), "0100100001100101")

    def test_clean_base64_adds_padding(self):
        padded = clean_base64("SGVsbG8")
        self.assertEqual(len(padded) % 4, 0)

    def test_byte_entropy_uniform(self):
        # Uniform bytes should have high entropy
        data = bytes(range(256))
        entropy = byte_entropy(data)
        self.assertGreater(entropy, 7.0)

    def test_byte_entropy_constant(self):
        # All-same bytes should have zero entropy
        data = b'\x00' * 100
        entropy = byte_entropy(data)
        self.assertAlmostEqual(entropy, 0.0)


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

class TestIntegration(unittest.TestCase):

    def test_url_then_base64(self):
        # URL-encoded Base64: "%53%47%56%73%62%47%38%3D" -> "SGVsbG8=" -> "Hello"
        url_encoded = "%53%47%56%73%62%47%38%3D"
        steps, final = auto_decode(url_encoded)
        # Should eventually reach "Hello"
        self.assertGreaterEqual(len(steps), 1)

    def test_rot13_decode(self):
        steps, final = auto_decode("Uryyb")
        self.assertIn("Hello", final)

    def test_morse_decode(self):
        steps, final = auto_decode(".... . .-.. .-.. ---")
        self.assertEqual(final, "HELLO")


if __name__ == "__main__":
    unittest.main(verbosity=2)
