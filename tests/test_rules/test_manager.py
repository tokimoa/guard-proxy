"""Tests for YARA rule manager (marketplace)."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.rules.manager import RuleIndex, RuleManager

_SAMPLE_YARA = """\
rule test_rule_1 {
  meta:
    description = "Test rule 1"
    severity = "high"
    author = "test-author"
  strings:
    $s1 = "malicious_payload" ascii
    $s2 = "evil_function" ascii
  condition:
    any of them
}

rule test_rule_2 {
  meta:
    description = "Test rule 2"
    severity = "critical"
  strings:
    $a = "dangerous_call" ascii
  condition:
    $a
}
"""


@pytest.fixture
def tmp_rules_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


# -- RuleIndex tests --


class TestRuleIndex:
    def test_empty_index(self, tmp_rules_dir):
        idx = RuleIndex(tmp_rules_dir)
        assert idx.sources == {}

    def test_add_source(self, tmp_rules_dir):
        idx = RuleIndex(tmp_rules_dir)
        idx.add_source("test", "https://example.com/rules.yar", "Test rules")
        assert "test" in idx.sources
        assert idx.sources["test"]["url"] == "https://example.com/rules.yar"

    def test_update_source(self, tmp_rules_dir):
        idx = RuleIndex(tmp_rules_dir)
        idx.add_source("test", "https://example.com/rules.yar")
        idx.update_source("test", rule_count=5, sha256="abc123")
        assert idx.sources["test"]["rule_count"] == 5
        assert idx.sources["test"]["sha256"] == "abc123"
        assert idx.sources["test"]["updated_at"] is not None

    def test_remove_source(self, tmp_rules_dir):
        idx = RuleIndex(tmp_rules_dir)
        idx.add_source("test", "https://example.com/rules.yar")
        assert idx.remove_source("test")
        assert "test" not in idx.sources

    def test_remove_nonexistent(self, tmp_rules_dir):
        idx = RuleIndex(tmp_rules_dir)
        assert not idx.remove_source("nonexistent")

    def test_persistence(self, tmp_rules_dir):
        idx1 = RuleIndex(tmp_rules_dir)
        idx1.add_source("test", "https://example.com/rules.yar")

        idx2 = RuleIndex(tmp_rules_dir)
        assert "test" in idx2.sources

    def test_get_source(self, tmp_rules_dir):
        idx = RuleIndex(tmp_rules_dir)
        idx.add_source("test", "https://example.com/rules.yar")
        assert idx.get_source("test") is not None
        assert idx.get_source("nonexistent") is None


# -- RuleManager tests --


class TestRuleManager:
    def test_list_sources_empty(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        sources = mgr.list_sources()
        assert sources == []

    def test_list_sources_with_local_yar(self, tmp_rules_dir):
        (tmp_rules_dir / "local.yar").write_text(_SAMPLE_YARA)
        mgr = RuleManager(tmp_rules_dir)
        sources = mgr.list_sources()
        assert len(sources) == 1
        assert sources[0]["name"] == "local"
        assert sources[0]["rule_count"] == 2

    def test_list_rules(self, tmp_rules_dir):
        (tmp_rules_dir / "test.yar").write_text(_SAMPLE_YARA)
        mgr = RuleManager(tmp_rules_dir)
        rules = mgr.list_rules()
        assert len(rules) == 2
        assert rules[0]["name"] == "test_rule_1"
        assert rules[0]["severity"] == "high"
        assert rules[0]["author"] == "test-author"
        assert rules[1]["name"] == "test_rule_2"
        assert rules[1]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_add_source(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)

        mock_response = AsyncMock()
        mock_response.text = _SAMPLE_YARA
        mock_response.raise_for_status = lambda: None

        with patch("app.rules.manager.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await mgr.add_source("community", "https://example.com/rules.yar", "Community rules")

        assert result["status"] == "updated"
        assert result["rule_count"] == 2
        assert (tmp_rules_dir / "community.yar").exists()

    @pytest.mark.asyncio
    async def test_add_duplicate_raises(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        mgr.index.add_source("existing", "https://example.com/rules.yar")

        with pytest.raises(ValueError, match="already exists"):
            await mgr.add_source("existing", "https://example.com/rules.yar")

    @pytest.mark.asyncio
    async def test_update_source(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        mgr.index.add_source("test", "https://example.com/rules.yar")

        mock_response = AsyncMock()
        mock_response.text = _SAMPLE_YARA
        mock_response.raise_for_status = lambda: None

        with patch("app.rules.manager.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await mgr.update_source("test")

        assert result["status"] == "updated"
        assert result["rule_count"] == 2

    @pytest.mark.asyncio
    async def test_update_nonexistent_raises(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        with pytest.raises(ValueError, match="not found"):
            await mgr.update_source("nonexistent")

    @pytest.mark.asyncio
    async def test_update_builtin_skipped(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        mgr.index.add_source("builtin", "", "Built-in rules")
        result = await mgr.update_source("builtin")
        assert result["status"] == "skipped"

    def test_remove_source_with_file(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        mgr.index.add_source("test", "https://example.com/rules.yar")
        (tmp_rules_dir / "test.yar").write_text(_SAMPLE_YARA)

        assert mgr.remove_source("test")
        assert not (tmp_rules_dir / "test.yar").exists()
        assert mgr.index.get_source("test") is None

    def test_remove_nonexistent(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        assert not mgr.remove_source("nonexistent")

    @pytest.mark.asyncio
    async def test_update_unchanged(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        mgr.index.add_source("test", "https://example.com/rules.yar")

        import hashlib

        content_hash = hashlib.sha256(_SAMPLE_YARA.encode()).hexdigest()
        mgr.index.update_source("test", 2, content_hash)

        mock_response = AsyncMock()
        mock_response.text = _SAMPLE_YARA
        mock_response.raise_for_status = lambda: None

        with patch("app.rules.manager.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await mgr.update_source("test")

        assert result["status"] == "unchanged"

    @pytest.mark.asyncio
    async def test_add_invalid_yara_raises(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)

        mock_response = AsyncMock()
        mock_response.text = "this is not valid YARA content"
        mock_response.raise_for_status = lambda: None

        with patch("app.rules.manager.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with pytest.raises(ValueError):
                await mgr.add_source("bad", "https://example.com/bad.yar")

    def test_validate_rules_valid(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        count = mgr._validate_rules(_SAMPLE_YARA)
        assert count == 2

    def test_validate_rules_invalid(self, tmp_rules_dir):
        mgr = RuleManager(tmp_rules_dir)
        with pytest.raises(ValueError):
            mgr._validate_rules("not valid yara { }")
