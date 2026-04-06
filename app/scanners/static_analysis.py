"""Static analysis scanner for npm install scripts."""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from app.core.config import Settings
from app.scanners.patterns.npm_patterns import ALL_NPM_PATTERNS, FALSE_POSITIVE_COMMANDS, MULTILINE_PATTERNS
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

_SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PatternMatch(BaseModel):
    """A single pattern match found during scanning."""

    pattern_name: str
    severity: Literal["low", "medium", "high", "critical"]
    line_number: int
    line_content: str
    file_path: str
    description: str


class StaticAnalysisScanner:
    """Pattern-matching scanner for install scripts."""

    def __init__(self, settings: Settings) -> None:
        self._threshold = settings.static_analysis_severity_threshold
        self._threshold_level = _SEVERITY_ORDER[self._threshold]

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        # If install scripts are known safe AND no artifacts to scan, fast pass
        if self._is_safe_install_scripts(package.install_scripts) and not artifacts:
            return ScanResult(
                scanner_name="static_analysis",
                verdict="pass",
                confidence=0.95,
                details="Install scripts match known safe patterns",
                metadata={"scripts": package.install_scripts},
            )

        # Check install script command strings directly
        all_matches: list[PatternMatch] = []
        for script_key, script_cmd in package.install_scripts.items():
            matches = self._scan_content(script_cmd, f"scripts.{script_key}")
            all_matches.extend(matches)

        # Scan extracted artifact files
        for artifact_path in artifacts:
            if artifact_path.exists() and artifact_path.is_file():
                try:
                    content = artifact_path.read_text(errors="replace")
                except OSError:
                    continue
                matches = self._scan_content(content, str(artifact_path.name))
                all_matches.extend(matches)
                # Multiline patterns (match across line boundaries)
                ml_matches = self._scan_content_multiline(content, str(artifact_path.name))
                all_matches.extend(ml_matches)

        # Filter by severity threshold
        filtered = [m for m in all_matches if _SEVERITY_ORDER[m.severity] >= self._threshold_level]

        if not filtered:
            return ScanResult(
                scanner_name="static_analysis",
                verdict="pass",
                confidence=0.9,
                details="No suspicious patterns detected",
            )

        verdict, confidence = self._calculate_verdict(filtered)
        details = self._build_details(filtered)

        return ScanResult(
            scanner_name="static_analysis",
            verdict=verdict,
            confidence=confidence,
            details=details,
            metadata={
                "match_count": len(filtered),
                "matches": [m.model_dump() for m in filtered[:10]],
            },
        )

    def _scan_content(self, content: str, source: str) -> list[PatternMatch]:
        """Scan content string against all patterns."""
        matches: list[PatternMatch] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            for pattern in ALL_NPM_PATTERNS:
                if pattern.pattern.search(line):
                    matches.append(
                        PatternMatch(
                            pattern_name=pattern.name,
                            severity=pattern.severity,
                            line_number=line_num,
                            line_content=line.strip()[:200],
                            file_path=source,
                            description=pattern.description,
                        )
                    )
        return matches

    def _scan_content_multiline(self, content: str, source: str) -> list[PatternMatch]:
        """Scan full file content against multiline patterns (DOTALL)."""
        matches: list[PatternMatch] = []
        for pattern in MULTILINE_PATTERNS:
            m = pattern.pattern.search(content)
            if m:
                # Calculate approximate line number from match position
                line_num = content[: m.start()].count("\n") + 1
                matches.append(
                    PatternMatch(
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        line_number=line_num,
                        line_content=m.group(0).replace("\n", " ")[:200],
                        file_path=source,
                        description=pattern.description,
                    )
                )
        return matches

    @staticmethod
    def _is_safe_install_scripts(install_scripts: dict[str, str]) -> bool:
        """Check if all install scripts are known safe commands."""
        if not install_scripts:
            return True

        for cmd in install_scripts.values():
            cmd_stripped = cmd.strip()
            if not any(cmd_stripped == safe or cmd_stripped.startswith(safe + " ") for safe in FALSE_POSITIVE_COMMANDS):
                return False
        return True

    @staticmethod
    def _calculate_verdict(matches: list[PatternMatch]) -> tuple[Literal["pass", "warn", "fail"], float]:
        """Determine verdict and confidence from matches."""
        max_severity = max(_SEVERITY_ORDER[m.severity] for m in matches)

        if max_severity >= _SEVERITY_ORDER["critical"]:
            return "fail", min(1.0, 0.7 + len(matches) * 0.05)

        if max_severity >= _SEVERITY_ORDER["high"]:
            return "fail", min(0.9, 0.6 + len(matches) * 0.05)

        if max_severity >= _SEVERITY_ORDER["medium"]:
            if len(matches) >= 3:
                return "warn", 0.7
            return "warn", 0.5

        return "pass", 0.6

    @staticmethod
    def _build_details(matches: list[PatternMatch]) -> str:
        """Build human-readable details string."""
        unique_patterns = {m.pattern_name: m.description for m in matches}
        lines = [f"Found {len(matches)} suspicious pattern(s):"]
        for name, desc in unique_patterns.items():
            count = sum(1 for m in matches if m.pattern_name == name)
            lines.append(f"  - {desc} ({name}): {count} occurrence(s)")
        return "\n".join(lines)
