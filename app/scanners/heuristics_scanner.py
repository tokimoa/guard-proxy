"""Behavioral heuristics scanner: entropy, binary detection, obfuscation signals.

Provides fast, pattern-independent detection of suspicious code characteristics.
"""

import math
import re
from collections import Counter
from pathlib import Path

from pydantic import BaseModel

from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

_MAX_FILE_SIZE = 512 * 1024  # 512KB

# Magic bytes for executable formats
_BINARY_MAGIC = {
    b"\x7fELF": "ELF executable",
    b"MZ": "PE/Windows executable",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (reversed)",
    b"\xce\xfa\xed\xfe": "Mach-O 32-bit (reversed)",
    b"\xca\xfe\xba\xbe": "Java class / Mach-O fat binary",
}

_BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".node", ".pyd", ".pyc", ".pyo"}

_SUSPICIOUS_KEYWORDS = re.compile(
    r"\b(?:exfiltrat|steal|credential|keylog|ransomware|cryptomin|reverse.?shell|backdoor|trojan|malware)\b",
    re.IGNORECASE,
)

_CI_ENV_NAMES = re.compile(r"\b(?:GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|TRAVIS|CIRCLECI|CODEBUILD|BUILDKITE|CI)\b")


class HeuristicFinding(BaseModel):
    check: str
    severity: str
    detail: str
    file: str = ""


class HeuristicsScanner:
    """Detect suspicious code characteristics via fast heuristics."""

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        findings: list[HeuristicFinding] = []

        for path in artifacts:
            if not path.exists() or not path.is_file():
                continue
            if path.stat().st_size > _MAX_FILE_SIZE:
                continue

            # Binary detection (first 4 bytes)
            finding = self._check_binary(path)
            if finding:
                findings.append(finding)
                continue  # skip text analysis for binaries

            try:
                content = path.read_text(errors="replace")
            except OSError:
                continue

            # Entropy analysis
            finding = self._check_entropy(content, path.name)
            if finding:
                findings.append(finding)

            # Minified/obfuscated code detection
            finding = self._check_minified(content, path.name)
            if finding:
                findings.append(finding)

            # Suspicious keywords
            kw_findings = self._check_keywords(content, path.name)
            findings.extend(kw_findings)

            # Unicode steganography (zero-width chars, RTL override)
            unicode_finding = self._check_unicode_steganography(content, path.name)
            if unicode_finding:
                findings.append(unicode_finding)

        if not findings:
            return ScanResult(
                scanner_name="heuristics_check",
                verdict="pass",
                confidence=0.9,
                details="No suspicious heuristic signals detected",
            )

        max_severity = max({"low": 0, "medium": 1, "high": 2, "critical": 3}.get(f.severity, 0) for f in findings)

        if max_severity >= 3:
            verdict, confidence = "fail", min(1.0, 0.6 + len(findings) * 0.1)
        elif max_severity >= 2:
            verdict, confidence = "warn", min(0.8, 0.5 + len(findings) * 0.1)
        else:
            verdict, confidence = "warn", 0.4

        details = "; ".join(f.detail for f in findings[:5])
        return ScanResult(
            scanner_name="heuristics_check",
            verdict=verdict,
            confidence=round(confidence, 2),
            details=f"Heuristic signals: {details}",
            metadata={"findings": [f.model_dump() for f in findings[:10]]},
        )

    @staticmethod
    def _check_binary(path: Path) -> HeuristicFinding | None:
        """Detect executable binaries via magic bytes or extension."""
        if path.suffix in _BINARY_EXTENSIONS:
            return HeuristicFinding(
                check="binary_extension",
                severity="high",
                detail=f"Binary file by extension: {path.name}",
                file=path.name,
            )

        try:
            with open(path, "rb") as f:
                header = f.read(4)
        except OSError:
            return None

        for magic, desc in _BINARY_MAGIC.items():
            if header[: len(magic)] == magic:
                return HeuristicFinding(
                    check="binary_magic",
                    severity="high",
                    detail=f"{desc} detected: {path.name}",
                    file=path.name,
                )
        return None

    @staticmethod
    def _check_entropy(content: str, filename: str) -> HeuristicFinding | None:
        """Shannon entropy analysis — high entropy indicates obfuscation."""
        if len(content) < 100:
            return None

        byte_counts = Counter(content.encode("utf-8", errors="replace"))
        total = sum(byte_counts.values())
        entropy = -sum((c / total) * math.log2(c / total) for c in byte_counts.values() if c > 0)

        if entropy > 7.0:
            return HeuristicFinding(
                check="high_entropy",
                severity="high",
                detail=f"Very high entropy ({entropy:.1f}/8.0) in {filename} — likely encrypted/compressed payload",
                file=filename,
            )
        if entropy > 6.5:
            return HeuristicFinding(
                check="elevated_entropy",
                severity="medium",
                detail=f"Elevated entropy ({entropy:.1f}/8.0) in {filename} — possible obfuscation",
                file=filename,
            )
        return None

    @staticmethod
    def _check_unicode_steganography(content: str, filename: str) -> HeuristicFinding | None:
        """Detect zero-width characters and RTL override used for steganography."""
        # Zero-width space, zero-width non-joiner, zero-width joiner, word joiner,
        # invisible times/separator, BOM, RTL/LTR override
        invisible_chars = re.findall(r"[\u200b\u200c\u200d\u2060\u2062\u2063\ufeff\u202e\u202d]", content)
        if len(invisible_chars) >= 3:
            return HeuristicFinding(
                check="unicode_steganography",
                severity="high",
                detail=f"{len(invisible_chars)} invisible Unicode characters in {filename} — possible steganography",
                file=filename,
            )
        return None

    @staticmethod
    def _check_minified(content: str, filename: str) -> HeuristicFinding | None:
        """Detect minified/obfuscated code (long lines + high entropy)."""
        if filename.endswith((".min.js", ".min.css", ".map")):
            return None  # known minified file, skip

        lines = content.split("\n")
        if not lines:
            return None

        avg_len = sum(len(line) for line in lines) / len(lines)
        if avg_len > 500 and len(lines) < 20:
            return HeuristicFinding(
                check="minified_code",
                severity="medium",
                detail=f"Likely minified/obfuscated code in {filename} (avg line length: {avg_len:.0f})",
                file=filename,
            )
        return None

    @staticmethod
    def _check_keywords(content: str, filename: str) -> list[HeuristicFinding]:
        """Scan for suspicious keywords indicating malicious intent."""
        findings: list[HeuristicFinding] = []

        kw_matches = _SUSPICIOUS_KEYWORDS.findall(content)
        if kw_matches:
            unique = set(kw.lower() for kw in kw_matches)
            findings.append(
                HeuristicFinding(
                    check="suspicious_keywords",
                    severity="medium",
                    detail=f"Suspicious keywords in {filename}: {', '.join(sorted(unique))}",
                    file=filename,
                )
            )

        # CI/CD environment variable references combined with conditional logic
        ci_matches = _CI_ENV_NAMES.findall(content)
        if ci_matches and re.search(r"\b(?:if|unless|when|case)\b", content):
            findings.append(
                HeuristicFinding(
                    check="ci_conditional",
                    severity="medium",
                    detail=f"CI/CD environment check with conditional logic in {filename}",
                    file=filename,
                )
            )

        return findings
