"""YARA rule marketplace — fetch, validate, and manage community rule packs.

Supports downloading .yar files from remote URLs (GitHub raw, etc.),
validating them with plyara, and maintaining a local index.
"""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
from loguru import logger

_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "yara_rules"
_INDEX_FILE = "rules_index.json"

# Built-in rule sources (shipped with guard-proxy)
BUILTIN_SOURCES: list[dict[str, str]] = [
    {
        "name": "guard-proxy-builtin",
        "url": "",
        "description": "Built-in supply chain detection rules",
    },
]


class RuleIndex:
    """Persistent index of installed YARA rule sources and their metadata."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._dir = rules_dir or _DEFAULT_RULES_DIR
        self._index_path = self._dir / _INDEX_FILE
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self._index_path.exists():
            try:
                return json.loads(self._index_path.read_text())
            except (json.JSONDecodeError, OSError):
                logger.warning("Corrupted rules index, resetting")
        return {"sources": {}, "version": 1}

    def save(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False))

    @property
    def sources(self) -> dict[str, dict]:
        return self._data.get("sources", {})

    def add_source(self, name: str, url: str, description: str = "") -> None:
        self._data.setdefault("sources", {})[name] = {
            "url": url,
            "description": description,
            "installed_at": datetime.now(UTC).isoformat(),
            "updated_at": None,
            "rule_count": 0,
            "sha256": "",
        }
        self.save()

    def update_source(self, name: str, rule_count: int, sha256: str) -> None:
        if name in self._data.get("sources", {}):
            self._data["sources"][name]["updated_at"] = datetime.now(UTC).isoformat()
            self._data["sources"][name]["rule_count"] = rule_count
            self._data["sources"][name]["sha256"] = sha256
            self.save()

    def remove_source(self, name: str) -> bool:
        if name in self._data.get("sources", {}):
            del self._data["sources"][name]
            self.save()
            return True
        return False

    def get_source(self, name: str) -> dict | None:
        return self._data.get("sources", {}).get(name)


class RuleManager:
    """Download, validate, and install YARA rule packs."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._dir = rules_dir or _DEFAULT_RULES_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index = RuleIndex(self._dir)

    @property
    def index(self) -> RuleIndex:
        return self._index

    @property
    def rules_dir(self) -> Path:
        return self._dir

    async def add_source(self, name: str, url: str, description: str = "") -> dict:
        """Add a new rule source and download its rules."""
        if self._index.get_source(name):
            raise ValueError(f"Source '{name}' already exists. Use update instead.")

        self._index.add_source(name, url, description)

        result = await self._download_and_install(name, url)
        return result

    async def update_source(self, name: str) -> dict:
        """Re-download rules from an existing source."""
        source = self._index.get_source(name)
        if not source:
            raise ValueError(f"Source '{name}' not found")
        if not source.get("url"):
            return {"name": name, "status": "skipped", "reason": "builtin source"}

        result = await self._download_and_install(name, source["url"])
        return result

    async def update_all(self) -> list[dict]:
        """Update all configured rule sources."""
        results = []
        for name in list(self._index.sources):
            try:
                result = await self.update_source(name)
                results.append(result)
            except Exception as e:
                results.append({"name": name, "status": "error", "error": str(e)})
        return results

    def remove_source(self, name: str) -> bool:
        """Remove a rule source and its downloaded files."""
        source = self._index.get_source(name)
        if not source:
            return False

        # Remove the .yar file
        rule_file = self._dir / f"{name}.yar"
        if rule_file.exists():
            rule_file.unlink()

        return self._index.remove_source(name)

    def list_sources(self) -> list[dict]:
        """List all installed rule sources with metadata."""
        result = []
        for name, source in self._index.sources.items():
            info = {
                "name": name,
                "url": source.get("url", ""),
                "description": source.get("description", ""),
                "rule_count": source.get("rule_count", 0),
                "updated_at": source.get("updated_at"),
                "sha256": source.get("sha256", "")[:12],
            }
            result.append(info)

        # Also list .yar files not tracked in index (e.g. supply_chain.yar)
        tracked_files = {f"{name}.yar" for name in self._index.sources}
        for yar_file in sorted(self._dir.glob("*.yar")):
            if yar_file.name not in tracked_files:
                rule_count = self._count_rules_in_file(yar_file)
                result.append(
                    {
                        "name": yar_file.stem,
                        "url": "",
                        "description": "Local rule file",
                        "rule_count": rule_count,
                        "updated_at": None,
                        "sha256": "",
                    }
                )

        return result

    def list_rules(self) -> list[dict]:
        """List all individual rules from all .yar files."""
        from plyara import Plyara

        rules = []
        parser = Plyara()

        for yar_file in sorted(self._dir.glob("*.yar")):
            try:
                raw_rules = parser.parse_string(yar_file.read_text())
                for raw in raw_rules:
                    meta = {}
                    for m in raw.get("metadata", []):
                        for k, v in m.items():
                            meta[k] = v
                    rules.append(
                        {
                            "name": raw.get("rule_name", "unknown"),
                            "source_file": yar_file.name,
                            "severity": meta.get("severity", "unknown"),
                            "description": meta.get("description", ""),
                            "author": meta.get("author", ""),
                            "string_count": len(raw.get("strings", [])),
                        }
                    )
                parser.clear()
            except Exception:
                logger.warning("Failed to parse {file}", file=yar_file.name)

        return rules

    async def _download_and_install(self, name: str, url: str) -> dict:
        """Download a .yar file from URL, validate, and install."""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()

        content = response.text
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Check if content has changed
        existing = self._index.get_source(name)
        if existing and existing.get("sha256") == content_hash:
            return {"name": name, "status": "unchanged", "sha256": content_hash[:12]}

        # Validate with plyara
        rule_count = self._validate_rules(content)
        if rule_count == 0:
            raise ValueError(f"No valid YARA rules found in {url}")

        # Install
        dest = self._dir / f"{name}.yar"
        dest.write_text(content)

        self._index.update_source(name, rule_count, content_hash)

        logger.info(
            "Installed {count} rules from {name}",
            count=rule_count,
            name=name,
        )

        return {
            "name": name,
            "status": "updated",
            "rule_count": rule_count,
            "sha256": content_hash[:12],
        }

    @staticmethod
    def _validate_rules(content: str) -> int:
        """Parse YARA content and return rule count. Raises on invalid content."""
        from plyara import Plyara

        parser = Plyara()
        try:
            rules = parser.parse_string(content)
            return len(rules)
        except Exception as e:
            raise ValueError(f"Invalid YARA content: {e}") from e

    @staticmethod
    def _count_rules_in_file(path: Path) -> int:
        """Count rules in a .yar file."""
        from plyara import Plyara

        parser = Plyara()
        try:
            rules = parser.parse_string(path.read_text())
            return len(rules)
        except Exception:
            return 0
