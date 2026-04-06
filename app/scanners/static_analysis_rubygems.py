"""Static analysis scanner for RubyGems packages."""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from app.core.config import Settings
from app.scanners.patterns.rubygems_patterns import ALL_RUBYGEMS_PATTERNS, FALSE_POSITIVE_INDICATORS, MULTILINE_PATTERNS
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

_SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PatternMatch(BaseModel):
    pattern_name: str
    severity: Literal["low", "medium", "high", "critical"]
    line_number: int
    line_content: str
    file_path: str
    description: str


class RubyGemsStaticAnalysisScanner:
    """Pattern-matching scanner for RubyGems install scripts."""

    def __init__(self, settings: Settings) -> None:
        self._threshold = settings.static_analysis_severity_threshold
        self._threshold_level = _SEVERITY_ORDER[self._threshold]

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        all_matches: list[PatternMatch] = []

        for artifact_path in artifacts:
            if not artifact_path.exists() or not artifact_path.is_file():
                continue
            # Skip metadata.yaml (gemspec) — not executable
            if artifact_path.name == "metadata.yaml":
                continue

            try:
                content = artifact_path.read_text(errors="replace")
            except OSError:
                continue

            # Track if file has false-positive indicators (reduces severity, does NOT skip)
            has_safe_indicators = self._is_likely_safe(content)

            matches = self._scan_content(content, artifact_path.name)
            if has_safe_indicators:
                _NEVER_DOWNGRADE = {
                    "reverse_shell",
                    "crypto_miner",
                    "cloud_metadata",
                    "cloud_metadata_access",
                    "cloud_metadata_expanded",
                    "ssh_key_access",
                    "aws_credential_access",
                    "destructive_command",
                    "procfs_access",
                    "k8s_secret_access",
                    "system_binary_write",
                    "git_hook_write",
                    "dll_hijacking",
                    "known_c2_domain",
                    "known_c2_ip",
                    "crontab_write",
                    "systemd_write",
                    "launchd_write",
                    "sitecustomize_write",
                    "ld_preload_inject",
                    "base64_exec",
                    "base64_eval",
                    "getattr_exec",
                    "libc_system",
                    "crontab_persistence",
                    "webhook_exfiltration",
                    "etc_passwd",
                    "base64_decode_exec",
                    "build_rs_shell",
                }
                for m in matches:
                    if m.severity == "critical" and m.pattern_name not in _NEVER_DOWNGRADE:
                        m.severity = "high"
            all_matches.extend(matches)
            ml_matches = self._scan_content_multiline(content, artifact_path.name)
            all_matches.extend(ml_matches)

        filtered = [m for m in all_matches if _SEVERITY_ORDER[m.severity] >= self._threshold_level]

        if not filtered:
            return ScanResult(
                scanner_name="static_analysis",
                verdict="pass",
                confidence=0.9,
                details="No suspicious patterns detected in RubyGem",
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
        matches: list[PatternMatch] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, start=1):
            for pattern in ALL_RUBYGEMS_PATTERNS:
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
    def _is_likely_safe(content: str) -> bool:
        return any(indicator in content for indicator in FALSE_POSITIVE_INDICATORS)

    @staticmethod
    def _calculate_verdict(
        matches: list[PatternMatch],
    ) -> tuple[Literal["pass", "warn", "fail"], float]:
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
        unique_patterns = {m.pattern_name: m.description for m in matches}
        lines = [f"Found {len(matches)} suspicious pattern(s) in RubyGem:"]
        for name, desc in unique_patterns.items():
            count = sum(1 for m in matches if m.pattern_name == name)
            lines.append(f"  - {desc} ({name}): {count} occurrence(s)")
        return "\n".join(lines)
