"""
file_handler.py - Batch file decoding for AutoCyberChef.

Reads encoded content from files and applies auto-detection + decoding to
each line (or to the whole file as a single blob), writing results to stdout
or an optional output file.

Supported input modes:
    - Line-by-line processing (default)
    - Whole-file blob mode (--blob flag)
    - CSV column processing

Output modes:
    - Stdout (default)
    - File output (--output flag)
    - JSON output (--json flag)
"""

import json
import csv
import sys
from pathlib import Path
from typing import List, Optional, Tuple, Iterator, Dict

from autochef.detector import detect_encoding
from autochef.pipeline import auto_decode, format_pipeline_output
from autochef.decoder import decode_by_name
from autochef.utils import strip_whitespace, is_printable


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_lines(file_path: Path, encoding: str = "utf-8") -> Iterator[str]:
    """
    Yield non-empty lines from a text file.

    Args:
        file_path: Path to the input file.
        encoding:  File encoding (default utf-8, falls back to latin-1).

    Yields:
        Each non-blank line, stripped of surrounding whitespace.
    """
    try:
        with file_path.open("r", encoding=encoding, errors="replace") as fh:
            for raw_line in fh:
                line = strip_whitespace(raw_line)
                if line:
                    yield line
    except (OSError, IOError) as exc:
        raise FileNotFoundError(f"Cannot read '{file_path}': {exc}") from exc


def _read_blob(file_path: Path, encoding: str = "utf-8") -> str:
    """
    Read the entire file as a single string.

    Args:
        file_path: Path to the input file.
        encoding:  File encoding.

    Returns:
        Complete file contents as a string.
    """
    try:
        return file_path.read_text(encoding=encoding, errors="replace").strip()
    except (OSError, IOError) as exc:
        raise FileNotFoundError(f"Cannot read '{file_path}': {exc}") from exc


def _write_output(lines: List[str], output_path: Optional[Path]) -> None:
    """
    Write output lines to a file or stdout.

    Args:
        lines:       Lines to write.
        output_path: Destination file path, or None for stdout.
    """
    text = '\n'.join(lines) + '\n'
    if output_path is None:
        sys.stdout.write(text)
    else:
        output_path.write_text(text, encoding="utf-8")
        print(f"Output written to: {output_path}")


# ---------------------------------------------------------------------------
# Line-by-line processing
# ---------------------------------------------------------------------------

def decode_file(
    file_path: str,
    output_path: Optional[str] = None,
    show_layers: bool = False,
    encoding_hint: Optional[str] = None,
    skip_errors: bool = True,
) -> List[Dict]:
    """
    Decode each line of a file and return structured results.

    For each non-empty line the function:
        1. Detects possible encodings
        2. Runs the auto-decode pipeline (or applies `encoding_hint` directly)
        3. Collects the result into a list of result dicts

    Args:
        file_path:     Path to the input file (string or Path-like).
        output_path:   Optional path to write decoded output.
        show_layers:   If True, include multi-layer info in printed output.
        encoding_hint: Force a specific encoding instead of auto-detecting.
        skip_errors:   If True, failed lines are included with error flag
                       instead of raising an exception.

    Returns:
        List of dicts, one per processed line, each containing:
            - line_number  (int)
            - original     (str)
            - detected     (list[str])
            - result       (str)
            - success      (bool)
            - layers       (list)

    Example:
        >>> results = decode_file("encoded.txt")
        >>> for r in results:
        ...     print(r["result"])
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {file_path}")

    out_path = Path(output_path) if output_path else None
    results: List[Dict] = []
    output_lines: List[str] = []

    for line_num, line in enumerate(_read_lines(path), start=1):
        record: Dict = {
            "line_number": line_num,
            "original":    line,
            "detected":    [],
            "result":      "",
            "success":     False,
            "layers":      [],
        }

        try:
            if encoding_hint:
                decoded, success = decode_by_name(encoding_hint, line)
                record["detected"] = [encoding_hint]
                record["result"]   = decoded
                record["success"]  = success
                record["layers"]   = [(encoding_hint, line, decoded)] if success else []
            else:
                detected = detect_encoding(line)
                record["detected"] = detected

                if not detected:
                    record["result"]  = line
                    record["success"] = False
                    output_lines.append(f"[Line {line_num}] (no encoding detected) {line}")
                    results.append(record)
                    continue

                steps, final = auto_decode(line)
                record["layers"]  = steps
                record["result"]  = final
                record["success"] = True

                if show_layers and steps:
                    output_lines.append(f"[Line {line_num}]")
                    output_lines.append(format_pipeline_output(steps, final))
                else:
                    output_lines.append(final)

        except Exception as exc:
            if skip_errors:
                record["result"]  = f"ERROR: {exc}"
                record["success"] = False
                output_lines.append(f"[Line {line_num}] ERROR: {exc}")
            else:
                raise

        results.append(record)

    if output_lines:
        _write_output(output_lines, out_path)

    return results


# ---------------------------------------------------------------------------
# Blob mode
# ---------------------------------------------------------------------------

def decode_file_blob(
    file_path: str,
    output_path: Optional[str] = None,
    show_layers: bool = True,
) -> Dict:
    """
    Treat the entire file as a single encoded string and auto-decode it.

    Args:
        file_path:   Path to the input file.
        output_path: Optional path to write decoded output.
        show_layers: If True, print layer-by-layer details.

    Returns:
        Dict with keys: original, detected, result, success, layers.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    blob = _read_blob(path)
    detected = detect_encoding(blob)
    steps, final = auto_decode(blob)

    result = {
        "original": blob,
        "detected": detected,
        "result":   final,
        "success":  bool(steps),
        "layers":   steps,
    }

    if show_layers:
        output = format_pipeline_output(steps, final)
    else:
        output = final

    out_path = Path(output_path) if output_path else None
    _write_output([output], out_path)

    return result


# ---------------------------------------------------------------------------
# JSON output helper
# ---------------------------------------------------------------------------

def decode_file_json(
    file_path: str,
    output_path: Optional[str] = None,
    encoding_hint: Optional[str] = None,
) -> str:
    """
    Decode a file line-by-line and return/write results as JSON.

    Args:
        file_path:     Input file path.
        output_path:   Optional JSON output file path.
        encoding_hint: Force a specific encoding.

    Returns:
        JSON string of the results list.
    """
    results = decode_file(
        file_path,
        output_path=None,
        show_layers=False,
        encoding_hint=encoding_hint,
        skip_errors=True,
    )

    # Convert layer tuples to serialisable dicts
    serialisable = []
    for r in results:
        row = dict(r)
        row["layers"] = [
            {"encoding": s[0], "input": s[1], "output": s[2]}
            for s in r.get("layers", [])
        ]
        serialisable.append(row)

    json_str = json.dumps(serialisable, ensure_ascii=False, indent=2)

    out_path = Path(output_path) if output_path else None
    if out_path:
        out_path.write_text(json_str, encoding="utf-8")
        print(f"JSON output written to: {out_path}")
    else:
        print(json_str)

    return json_str


# ---------------------------------------------------------------------------
# File statistics helper
# ---------------------------------------------------------------------------

def file_stats(file_path: str) -> Dict:
    """
    Return basic statistics about the encodings found in a file.

    Args:
        file_path: Input file path.

    Returns:
        Dict with:
            - total_lines   (int)
            - decoded_lines (int)
            - failed_lines  (int)
            - encoding_counts (dict: encoding_name -> count)
    """
    from collections import Counter
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    total = 0
    decoded = 0
    failed = 0
    encoding_counter: Counter = Counter()

    for line in _read_lines(path):
        total += 1
        detected = detect_encoding(line)
        if detected:
            decoded += 1
            for enc in detected:
                encoding_counter[enc] += 1
        else:
            failed += 1

    return {
        "total_lines":     total,
        "decoded_lines":   decoded,
        "failed_lines":    failed,
        "encoding_counts": dict(encoding_counter.most_common()),
    }
