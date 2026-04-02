"""Pre-processing for obfuscated code.

Deobfuscates Base64, hex, unicode escape sequences before sending to LLM.
Calculates an obfuscation score to decide whether to skip local LLM.
"""

import base64
import math
import re
from collections import Counter

# Patterns for detecting encoded content
_BASE64_PATTERN = re.compile(r"""['"]([A-Za-z0-9+/]{12,}={0,2})['"]""")
_HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_UNICODE_ESCAPE_PATTERN = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_CHAR_CODE_PATTERN = re.compile(r"String\.fromCharCode\(([^)]+)\)")


def deobfuscate(content: str) -> tuple[str, float]:
    """Deobfuscate content and return (deobfuscated_content, obfuscation_score).

    The obfuscation score (0.0 - 1.0) indicates how heavily obfuscated the code is.
    Score >= 0.7 should skip local LLM and go directly to cloud.
    """
    result = content
    transformations = 0

    # Decode base64 strings
    result, b64_count = _decode_base64_strings(result)
    transformations += b64_count

    # Expand hex escape sequences
    result, hex_count = _expand_hex_escapes(result)
    transformations += hex_count

    # Expand unicode escape sequences
    result, uni_count = _expand_unicode_escapes(result)
    transformations += uni_count

    # Expand String.fromCharCode
    result, cc_count = _expand_char_codes(result)
    transformations += cc_count

    score = _calculate_obfuscation_score(content, transformations)
    return result, score


def _decode_base64_strings(content: str) -> tuple[str, int]:
    """Find and decode base64 strings inline."""
    count = 0

    def _replace(m: re.Match) -> str:
        nonlocal count
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            if decoded.isprintable() or "\n" in decoded:
                count += 1
                return f'/* b64_decoded: */ "{decoded}"'
        except Exception:
            pass
        return m.group(0)

    return _BASE64_PATTERN.sub(_replace, content), count


def _expand_hex_escapes(content: str) -> tuple[str, int]:
    """Expand hex escape sequences."""
    count = 0

    def _replace(m: re.Match) -> str:
        nonlocal count
        try:
            decoded = bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8", errors="replace")
            count += 1
            return f'/* hex_decoded: */ "{decoded}"'
        except Exception:
            return m.group(0)

    return _HEX_ESCAPE_PATTERN.sub(_replace, content), count


def _expand_unicode_escapes(content: str) -> tuple[str, int]:
    """Expand unicode escape sequences."""
    count = 0

    def _replace(m: re.Match) -> str:
        nonlocal count
        try:
            decoded = m.group(0).encode().decode("unicode_escape")
            count += 1
            return f'/* unicode_decoded: */ "{decoded}"'
        except Exception:
            return m.group(0)

    return _UNICODE_ESCAPE_PATTERN.sub(_replace, content), count


def _expand_char_codes(content: str) -> tuple[str, int]:
    """Expand String.fromCharCode calls."""
    count = 0

    def _replace(m: re.Match) -> str:
        nonlocal count
        try:
            codes = [int(c.strip()) for c in m.group(1).split(",")]
            decoded = "".join(chr(c) for c in codes)
            count += 1
            return f'/* charCode_decoded: */ "{decoded}"'
        except Exception:
            return m.group(0)

    return _CHAR_CODE_PATTERN.sub(_replace, content), count


def _calculate_obfuscation_score(content: str, transformation_count: int) -> float:
    """Calculate obfuscation score based on code characteristics."""
    if not content.strip():
        return 0.0

    signals: list[float] = []

    # Signal 1: Ratio of encoded content found
    encoded_ratio = min(1.0, transformation_count / max(1, len(content.split("\n")) / 5))
    signals.append(encoded_ratio * 0.4)

    # Signal 2: Variable name entropy (obfuscated code uses short random names)
    var_names = re.findall(r"\b([a-zA-Z_]\w{0,2})\b", content)
    if var_names:
        entropy = _shannon_entropy(var_names)
        # High entropy in short var names = likely obfuscated
        signals.append(min(1.0, entropy / 4.0) * 0.3)

    # Signal 3: Ratio of non-ASCII or escape sequences
    non_printable = sum(1 for c in content if not c.isprintable() and c not in "\n\r\t")
    escape_count = content.count("\\x") + content.count("\\u")
    noise_ratio = min(1.0, (non_printable + escape_count) / max(1, len(content)) * 10)
    signals.append(noise_ratio * 0.3)

    return min(1.0, sum(signals))


def _shannon_entropy(tokens: list[str]) -> float:
    """Calculate Shannon entropy of a token list."""
    counter = Counter(tokens)
    total = len(tokens)
    return -sum((c / total) * math.log2(c / total) for c in counter.values() if c > 0)
