"""Tests for SHA-256 hash utility."""

from app.utils.hash import compute_sha256


def test_compute_sha256_known():
    assert compute_sha256(b"hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_compute_sha256_empty():
    assert compute_sha256(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_compute_sha256_bytes():
    result = compute_sha256(b"\x00\xff")
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)
