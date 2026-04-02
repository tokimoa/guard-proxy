"""Hash utility functions."""

import base64
import hashlib


def compute_sha256(content: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(content).hexdigest()


def compute_integrity(content: bytes, algorithm: str = "sha512") -> str:
    """Compute subresource integrity hash (base64-encoded)."""
    h = hashlib.new(algorithm, content)
    digest_b64 = base64.b64encode(h.digest()).decode("ascii")
    return f"{algorithm}-{digest_b64}"
