"""
pipeline.py - Automatic multi-layer decoding for AutoCyberChef.

Orchestrates repeated detect → decode cycles, unwrapping nested encodings
layer by layer until the result is plaintext or a maximum depth is reached.

Key safeguards:
    - Duplicate result detection prevents infinite loops
    - Printability scoring guides early termination
    - Configurable max layers (default 10)
    - Low-confidence encodings (ROT13, Caesar) are tried last
"""

from typing import List, Tuple, Optional, Dict
from autochef.detector import detect_encoding, get_encoding_confidence, ENCODING_PRIORITY
from autochef.decoder import decode_by_name
from autochef.utils import (
    is_printable,
    printability_score,
    looks_like_text,
    looks_like_english,
    format_layer,
)

# Type alias for a single pipeline step
#   (encoding_name, input_before_decode, decoded_result)
PipelineStep = Tuple[str, str, str]

# Maximum decode layers to prevent runaway recursion
DEFAULT_MAX_LAYERS = 10

# Minimum printability score to consider decoding successful
MIN_PRINTABILITY = 0.70

# Low-confidence encodings tried only when nothing better is available
LOW_CONFIDENCE_ENCODINGS = {"ROT13", "Caesar"}


# ---------------------------------------------------------------------------
# Core pipeline logic
# ---------------------------------------------------------------------------

def _select_encoding(encodings: List[str], tried: set) -> Optional[str]:
    """
    Select the next encoding to try from a detected list.

    Prefers high-confidence encodings and skips anything already attempted
    in this pipeline run.  Low-confidence encodings (ROT13, Caesar) are
    deferred until no better options remain.

    Args:
        encodings: Detected encoding names in priority order.
        tried:     Set of encoding names already attempted.

    Returns:
        The chosen encoding name, or None if all have been tried.
    """
    # First pass: skip low-confidence and already-tried
    for enc in encodings:
        if enc not in tried and enc not in LOW_CONFIDENCE_ENCODINGS:
            return enc
    # Second pass: allow low-confidence if nothing else is available
    for enc in encodings:
        if enc not in tried:
            return enc
    return None


def _is_dead_end(result: str, history: List[PipelineStep]) -> bool:
    """
    Return True if continuing would likely be unproductive.

    Checks whether:
        - The decoded result has appeared before (cycle detection)
        - The result is identical to the input of this step

    Args:
        result:  Current decoded string.
        history: All previous pipeline steps.

    Returns:
        True if decoding should stop.
    """
    seen_results = {step[2] for step in history}
    return result in seen_results


def _result_improved(previous: str, current: str) -> bool:
    """
    Return True if `current` is more readable than `previous`.

    Uses printability score as the primary metric, with a bonus for
    strings that look like natural language.

    Args:
        previous: String before the latest decode step.
        current:  String after the latest decode step.

    Returns:
        True if readability improved.
    """
    prev_score = printability_score(previous)
    curr_score = printability_score(current)
    if looks_like_text(current) and not looks_like_text(previous):
        return True
    return curr_score > prev_score - 0.05  # Allow small regressions


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def auto_decode(
    input_string: str,
    max_layers: int = DEFAULT_MAX_LAYERS,
    verbose: bool = False,
) -> Tuple[List[PipelineStep], str]:
    """
    Automatically detect and decode nested encodings layer by layer.

    The function iterates up to `max_layers` times.  At each iteration it:
        1. Detects possible encodings in the current string
        2. Selects the best candidate (highest priority, not yet tried)
        3. Attempts to decode it
        4. Checks whether the result is more readable
        5. Stops if the result is plaintext or no progress can be made

    Args:
        input_string: The (possibly multiply-encoded) string to decode.
        max_layers:   Maximum number of decoding layers (default 10).
        verbose:      If True, emit progress messages to stdout.

    Returns:
        Tuple of:
            - List of PipelineStep tuples (encoding, input, output)
            - Final decoded string

    Example:
        >>> steps, final = auto_decode("U0dWc2JHOD0=")
        >>> final
        'Hello'
        >>> [(s[0], s[2]) for s in steps]
        [('Base64', 'SGVsbG8='), ('Base64', 'Hello')]
    """
    current = input_string.strip()
    history: List[PipelineStep] = []
    globally_tried: set = set()

    # Early exit only if the string is real English plaintext
    # (contains recognised vocabulary words, not just high alpha ratio).
    # This prevents "Hello World" from being ROT13-decoded while still
    # allowing "Uryyb" (ROT13 for "Hello") to be processed.
    if is_printable(current) and looks_like_english(current):
        initial_encodings = detect_encoding(current)
        low_conf_only = all(e in LOW_CONFIDENCE_ENCODINGS for e in initial_encodings)
        if not initial_encodings or low_conf_only:
            if verbose:
                print("  [pipeline] Input appears to already be plaintext.")
            return history, current

    for layer_num in range(1, max_layers + 1):
        # Check if we already look like plaintext
        if is_printable(current) and looks_like_english(current) and layer_num > 1:
            if verbose:
                print(f"  [pipeline] Layer {layer_num}: result looks like plaintext, stopping.")
            break

        # Detect encodings in current string
        encodings = detect_encoding(current)

        if not encodings:
            if verbose:
                print(f"  [pipeline] Layer {layer_num}: no encodings detected, stopping.")
            break

        # Choose which encoding to try
        chosen = _select_encoding(encodings, globally_tried)
        if chosen is None:
            if verbose:
                print(f"  [pipeline] Layer {layer_num}: all detected encodings exhausted.")
            break

        if verbose:
            print(f"  [pipeline] Layer {layer_num}: trying {chosen} ...")

        # Attempt to decode
        decoded, success = decode_by_name(chosen, current)

        if not success:
            globally_tried.add(chosen)
            if verbose:
                print(f"  [pipeline] {chosen} decode failed: {decoded}")
            continue

        # Sanity checks on the decoded result
        if not decoded or not decoded.strip():
            globally_tried.add(chosen)
            if verbose:
                print(f"  [pipeline] {chosen} produced empty result, skipping.")
            continue

        if _is_dead_end(decoded, history):
            globally_tried.add(chosen)
            if verbose:
                print(f"  [pipeline] {chosen} produced a previously seen result, skipping.")
            continue

        if not _result_improved(current, decoded):
            # Special case: still accept if printability is above threshold
            if printability_score(decoded) < MIN_PRINTABILITY:
                globally_tried.add(chosen)
                if verbose:
                    print(f"  [pipeline] {chosen} result has low printability ({printability_score(decoded):.2f}), skipping.")
                continue

        # Accept this step
        history.append((chosen, current, decoded))
        globally_tried = set()  # Reset tried set for next layer
        current = decoded

        if verbose:
            print(f"  [pipeline] Layer {layer_num}: {chosen} -> {decoded[:60]}")

    return history, current


def decode_single(input_string: str, encoding: str) -> Tuple[str, bool]:
    """
    Decode `input_string` using a specific named encoding.

    A thin convenience wrapper around :func:`decode_by_name` that also
    validates the encoding name against the known list.

    Args:
        input_string: Raw encoded string.
        encoding:     Encoding name (case-insensitive).

    Returns:
        Tuple of (decoded_string, success).
    """
    return decode_by_name(encoding, input_string)


def format_pipeline_output(
    steps: List[PipelineStep],
    final: str,
    show_intermediate: bool = True,
) -> str:
    """
    Format the result of :func:`auto_decode` for CLI display.

    Args:
        steps:             List of pipeline steps from auto_decode.
        final:             Final decoded string.
        show_intermediate: If True, print intermediate layer results.

    Returns:
        Formatted string ready for printing.
    """
    if not steps:
        return f"No encoding detected.\nInput returned as-is: {final}"

    lines = []
    for i, (encoding, before, after) in enumerate(steps, start=1):
        truncated_after = after if len(after) <= 60 else after[:57] + "..."
        if show_intermediate:
            lines.append(f"  Layer {i}: [{encoding}]  →  {truncated_after}")
        else:
            lines.append(f"  Layer {i}: [{encoding}]")

    lines.append(f"\nFinal result: {final}")
    return '\n'.join(lines)


def pipeline_summary(steps: List[PipelineStep]) -> str:
    """
    Return a one-line summary of the encoding chain.

    Example output: "Base64 → Base64 → ROT13"

    Args:
        steps: List of pipeline steps from auto_decode.

    Returns:
        Arrow-delimited chain of encoding names.
    """
    if not steps:
        return "(no encodings detected)"
    return " → ".join(step[0] for step in steps)


def try_all_decoders(input_string: str) -> List[Tuple[str, str, bool]]:
    """
    Attempt decoding with every known decoder and return all results.

    Useful for debugging or when auto-detection is uncertain.  Results are
    returned regardless of success or readability.

    Args:
        input_string: Raw encoded string.

    Returns:
        List of (encoding_name, decoded_result, success) tuples for all
        supported encodings.
    """
    from autochef.detector import ENCODING_PRIORITY

    results = []
    for enc in ENCODING_PRIORITY:
        result, success = decode_by_name(enc, input_string)
        results.append((enc, result, success))
    return results


def decode_with_encoding(input_string: str, encoding: str) -> Dict:
    """
    Decode `input_string` with a specific encoding and return a rich result dict.

    Args:
        input_string: Raw encoded string.
        encoding:     Encoding name.

    Returns:
        Dict with keys:
            - encoding  (str)
            - input     (str)
            - result    (str)
            - success   (bool)
            - printability (float)
            - looks_like_text (bool)
    """
    result, success = decode_by_name(encoding, input_string)
    return {
        "encoding":       encoding,
        "input":          input_string,
        "result":         result,
        "success":        success,
        "printability":   printability_score(result) if success else 0.0,
        "looks_like_text": looks_like_text(result) if success else False,
    }
