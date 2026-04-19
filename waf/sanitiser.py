"""
Web Application Firewall (WAF) Sanitisation Module.

This module provides input sanitisation functions to detect and safely handle
encoded malicious payloads that may bypass simple pattern matching.

Key functions:
- sanitise(): Perform multi-layer decoding and HTML escaping
- is_encoded(): Detect if input contains encoding
"""

import html
import urllib.parse


def sanitise(value):
    """
    Sanitise user input by detecting and neutralising encoded payloads.

    This function performs the following steps:
    1. URL-decode the input (handles %3Cscript%3E -> <script>)
    2. HTML-unescape (handles &lt;script&gt; -> <script>)
    3. Repeat both steps again (catches double-encoded: %253C -> %3C -> <)
    4. HTML-escape the fully decoded result to make it safe

    Why double-decoding?
    Attackers often layer encodings to evade pattern detection:
    - %253C is %3C (URL-encoded) that was URL-encoded again
    - Decoding once gives %3C (still dangerous), decoding twice gives <
    - Double-decoding ensures we detect hidden malicious characters

    Args:
        value (str): Raw user input that may contain encoding

    Returns:
        tuple[str, str]: (safe_value, decoded_value)
            - safe_value: HTML-escaped string safe for storage/display
            - decoded_value: Fully decoded raw string for pattern checking by WAF
    """
    if not isinstance(value, str):
        value = str(value)

    # Step 1: First pass of URL decode + HTML unescape
    decoded = urllib.parse.unquote(value)
    decoded = html.unescape(decoded)

    # Step 2: Second pass to catch double-encoded payloads
    decoded = urllib.parse.unquote(decoded)
    decoded = html.unescape(decoded)

    # Step 3: HTML-escape the final decoded value for safe storage
    safe_value = html.escape(decoded, quote=True)

    return safe_value, decoded


def is_encoded(original, decoded):
    """
    Detect if input contains encoding by comparing original and decoded versions.

    Args:
        original (str): The original user input
        decoded (str): The fully decoded version (from sanitise() second return value)

    Returns:
        bool: True if encoding was detected (original != decoded), False otherwise
    """
    return original != decoded
