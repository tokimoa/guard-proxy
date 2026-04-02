"""YARA-compatible rule scanner (pure Python via plyara).

Loads .yar rule files and matches string patterns against package artifacts.
Compatible with GuardDog YARA rules without requiring native C dependencies.
"""

import re
from pathlib import Path

from loguru import logger

from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "yara_rules"


class YARARule:
    """Parsed YARA rule with compiled string patterns."""

    def __init__(self, name: str, strings: list[tuple[str, re.Pattern]], condition: str, meta: dict) -> None:
        self.name = name
        self.strings = strings  # [(var_name, compiled_regex)]
        self.condition = condition
        self.meta = meta
        self.severity = meta.get("severity", "high")
        self.description = meta.get("description", name)


class YARAScanner:
    """Scan artifacts using YARA-compatible rules (pure Python)."""

    def __init__(self, rules_dir: str | None = None) -> None:
        self._rules: list[YARARule] = []
        rules_path = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
        self._load_rules(rules_path)

    def _load_rules(self, rules_dir: Path) -> None:
        if not rules_dir.exists():
            logger.warning("YARA rules directory not found: {path}", path=rules_dir)
            return

        from plyara import Plyara

        parser = Plyara()

        for yar_file in sorted(rules_dir.glob("*.yar")):
            try:
                raw_rules = parser.parse_string(yar_file.read_text())
                for raw in raw_rules:
                    rule = self._compile_rule(raw)
                    if rule:
                        self._rules.append(rule)
                parser.clear()
            except Exception:
                logger.warning("Failed to parse YARA file: {file}", file=yar_file.name)

        logger.info("YARA rules loaded: {count} rules", count=len(self._rules))

    @staticmethod
    def _compile_rule(raw: dict) -> YARARule | None:
        """Convert plyara parsed rule to compiled patterns."""
        name = raw.get("rule_name", "unknown")
        meta = {}
        for m in raw.get("metadata", []):
            for k, v in m.items():
                meta[k] = v

        strings: list[tuple[str, re.Pattern]] = []
        for s in raw.get("strings", []):
            var_name = s.get("name", "")
            value = s.get("value", "")
            modifiers = s.get("modifiers", [])
            str_type = s.get("type", "text")

            if not value:
                continue

            # Build regex from YARA string
            flags = 0
            if "nocase" in modifiers:
                flags = re.IGNORECASE

            if str_type == "regex":
                # YARA regex: strip surrounding /.../ and use as-is
                pattern = value.strip("/")
            elif str_type == "byte":
                # YARA hex string: e.g. "6A 40 ?? 00" → byte regex with wildcards
                try:
                    hex_clean = value.replace("{", "").replace("}", "").strip()
                    hex_parts = hex_clean.split()
                    regex_parts = []
                    for hb in hex_parts:
                        if "?" in hb:
                            regex_parts.append(".")  # Wildcard byte
                        else:
                            regex_parts.append(re.escape(bytes.fromhex(hb).decode("latin-1")))
                    pattern = "".join(regex_parts)
                except (ValueError, UnicodeDecodeError):
                    continue
            else:
                # Text string: escape for literal matching
                pattern = re.escape(value)

            try:
                compiled = re.compile(pattern, flags)
                strings.append((var_name, compiled))
            except re.error:
                logger.debug("Failed to compile YARA string {var}: {val}", var=var_name, val=value[:50])
                continue

        if not strings:
            return None

        condition = raw.get("condition_terms", [])
        condition_str = " ".join(condition) if isinstance(condition, list) else str(condition)

        return YARARule(name=name, strings=strings, condition=condition_str, meta=meta)

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        if not self._rules:
            return ScanResult(
                scanner_name="yara_scan",
                verdict="pass",
                confidence=0.5,
                details="No YARA rules loaded",
            )

        matches: list[dict] = []

        for path in artifacts:
            if not path.exists() or not path.is_file():
                continue
            if path.stat().st_size > 512 * 1024:
                continue
            if path.name in ("metadata.yaml", "package.json"):
                continue

            try:
                content = path.read_text(errors="replace")
            except OSError:
                continue

            for rule in self._rules:
                matched_vars = self._evaluate_rule(rule, content)
                if matched_vars:
                    matches.append(
                        {
                            "rule": rule.name,
                            "severity": rule.severity,
                            "description": rule.description,
                            "file": path.name,
                            "matched_strings": matched_vars,
                        }
                    )

        if not matches:
            return ScanResult(
                scanner_name="yara_scan",
                verdict="pass",
                confidence=0.9,
                details="No YARA rule matches",
            )

        max_sev = max({"low": 0, "medium": 1, "high": 2, "critical": 3}.get(m["severity"], 0) for m in matches)

        if max_sev >= 3:
            verdict, confidence = "fail", min(1.0, 0.7 + len(matches) * 0.05)
        elif max_sev >= 2:
            verdict, confidence = "warn", min(0.8, 0.5 + len(matches) * 0.1)
        else:
            verdict, confidence = "warn", 0.4

        details = "; ".join(f"{m['rule']}: {m['description']}" for m in matches[:5])
        return ScanResult(
            scanner_name="yara_scan",
            verdict=verdict,
            confidence=round(confidence, 2),
            details=f"YARA matches: {details}",
            metadata={"matches": matches[:10]},
        )

    @staticmethod
    def _evaluate_rule(rule: YARARule, content: str) -> list[str]:
        """Evaluate a YARA rule against content. Returns list of matched variable names."""
        matched: dict[str, bool] = {}
        for var_name, pattern in rule.strings:
            matched[var_name] = bool(pattern.search(content))

        # Evaluate condition
        condition = rule.condition.lower().strip()

        # "all of them"
        if "all of them" in condition:
            if all(matched.values()):
                return [k for k, v in matched.items() if v]
            return []

        # "any of them"
        if "any of them" in condition:
            if any(matched.values()):
                return [k for k, v in matched.items() if v]
            return []

        # "N of them" (any number)
        import re as _re

        n_of_them = _re.match(r"(\d+)\s+of\s+them", condition)
        if n_of_them:
            n = int(n_of_them.group(1))
            matched_count = sum(1 for v in matched.values() if v)
            if matched_count >= n:
                return [k for k, v in matched.items() if v]
            return []

        # Complex condition with 'and' / 'or' — simplified evaluation
        or_groups = condition.split(" or ")
        for group in or_groups:
            and_parts = group.strip().split(" and ")
            all_match = True
            group_matches = []
            for part in and_parts:
                part = part.strip().strip("()")
                var_match = False

                # Check for "N of them" within group
                n_match = _re.match(r"(\d+)\s+of\s+them", part.strip())
                if n_match:
                    n = int(n_match.group(1))
                    if sum(1 for v in matched.values() if v) >= n:
                        var_match = True
                        group_matches.extend(k for k, v in matched.items() if v)
                elif "any of them" in part:
                    if any(matched.values()):
                        var_match = True
                        group_matches.extend(k for k, v in matched.items() if v)
                elif "all of them" in part:
                    if all(matched.values()):
                        var_match = True
                        group_matches.extend(k for k, v in matched.items() if v)
                else:
                    # Variable reference: exact match only
                    for var_name in matched:
                        if var_name == part.strip() or var_name.lstrip("$") == part.strip().lstrip("$"):
                            if matched[var_name]:
                                var_match = True
                                group_matches.append(var_name)
                            break

                if not var_match:
                    all_match = False
                    break
            if all_match and group_matches:
                return group_matches

        # Fallback: if condition contains unsupported keywords, conservatively skip
        unsupported = {"filesize", "entrypoint", "for", "of", "at", "in"}
        if any(tok in condition for tok in unsupported):
            logger.debug("YARA rule has unsupported condition: {cond}", cond=condition[:80])
            return []

        # Simple fallback for plain variable conditions
        if any(matched.values()):
            return [k for k, v in matched.items() if v]
        return []
