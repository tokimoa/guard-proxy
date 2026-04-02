"""Malicious pattern definitions for PyPI packages."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict


class MaliciousPattern(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    pattern: re.Pattern[str]
    severity: Literal["low", "medium", "high", "critical"]
    description: str


# -- Credential access patterns --

CREDENTIAL_ACCESS_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="env_bulk_access",
        pattern=re.compile(r"os\.environ(?!\[)|\bdict\(os\.environ\)", re.IGNORECASE),
        severity="high",
        description="Bulk environment variable access",
    ),
    MaliciousPattern(
        name="ssh_key_access",
        pattern=re.compile(r"""(?:open|read).{0,500}['"~/].{0,500}\.ssh""", re.IGNORECASE),
        severity="critical",
        description="SSH key file access",
    ),
    MaliciousPattern(
        name="aws_credential_access",
        pattern=re.compile(r"""(?:open|read).{0,500}['"~/].{0,500}\.aws""", re.IGNORECASE),
        severity="critical",
        description="AWS credential file access",
    ),
    MaliciousPattern(
        name="credential_file_access",
        pattern=re.compile(
            r"""(?:open|read).{0,500}['"].{0,500}(?:\.gnupg|\.npmrc|\.docker|\.kube|\.config/gcloud)""",
            re.IGNORECASE,
        ),
        severity="high",
        description="Credential/config file access",
    ),
    MaliciousPattern(
        name="cloud_metadata_access",
        pattern=re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.IGNORECASE),
        severity="critical",
        description="Cloud metadata API access",
    ),
]

# -- Network exfiltration patterns --

NETWORK_EXFIL_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="suspicious_tld_request",
        pattern=re.compile(
            r"""https?://[^/'"]+\.(?:xyz|tk|ml|ga|cf|top|pw|cc|buzz|surf|monster)(?:[/'"]|\b)""",
            re.IGNORECASE,
        ),
        severity="high",
        description="HTTP request to suspicious TLD",
    ),
    MaliciousPattern(
        name="data_exfil_urllib",
        pattern=re.compile(
            r"(?:urllib|requests|httpx).{0,500}(?:os\.environ|open\(|subprocess)",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="Data exfiltration via HTTP library",
    ),
    MaliciousPattern(
        name="dns_exfil",
        pattern=re.compile(r"socket\.getaddrinfo|dns\.resolver.{0,500}os\.environ", re.IGNORECASE),
        severity="high",
        description="Potential DNS exfiltration",
    ),
]

# -- Code execution / obfuscation patterns --

OBFUSCATION_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="base64_exec",
        pattern=re.compile(
            r"""(?:b64decode|base64\.b64decode).{0,500}(?:exec|eval|compile)|(?:exec|eval|compile).{0,500}(?:b64decode|base64\.b64decode)""",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="Base64 decode combined with exec/eval",
    ),
    MaliciousPattern(
        name="exec_dynamic",
        pattern=re.compile(r"""exec\s*\(\s*(?!['"])"""),
        severity="high",
        description="Dynamic exec with non-literal argument",
    ),
    MaliciousPattern(
        name="compile_exec",
        pattern=re.compile(r"""compile\s*\(.{0,500}exec""", re.DOTALL),
        severity="high",
        description="compile() followed by exec()",
    ),
    MaliciousPattern(
        name="pth_auto_exec",
        pattern=re.compile(r"""(?:exec|eval|compile|__import__)\s*\("""),
        severity="high",
        description=".pth file code execution (exec/eval/__import__)",
    ),
]

# -- Persistence patterns --

PERSISTENCE_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="crontab_write",
        pattern=re.compile(r"""(?:crontab|/etc/cron)""", re.IGNORECASE),
        severity="critical",
        description="Crontab modification",
    ),
    MaliciousPattern(
        name="systemd_write",
        pattern=re.compile(r"""(?:systemd|systemctl|/etc/init\.d)""", re.IGNORECASE),
        severity="critical",
        description="Systemd service manipulation",
    ),
    MaliciousPattern(
        name="launchd_write",
        pattern=re.compile(r"""(?:LaunchAgents|LaunchDaemons|launchctl)""", re.IGNORECASE),
        severity="critical",
        description="macOS LaunchAgent/Daemon manipulation",
    ),
    MaliciousPattern(
        name="subprocess_suspicious",
        pattern=re.compile(
            r"""subprocess\.(?:run|Popen|call)\s*\(.{0,500}(?:curl|wget|nc\b|bash|sh\b|powershell)""",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        description="Subprocess executing network/shell commands",
    ),
]

# -- Setup.py specific patterns --

SETUP_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="cmdclass_override",
        pattern=re.compile(r"""cmdclass\s*=.{0,500}(?:install|develop|egg_info)""", re.IGNORECASE),
        severity="medium",
        description="setup.py cmdclass override (install hook)",
    ),
    MaliciousPattern(
        name="os_system_in_setup",
        pattern=re.compile(r"""os\.system\s*\("""),
        severity="high",
        description="os.system() call in setup.py",
    ),
]

# -- Advanced threat patterns --

ADVANCED_THREAT_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="reverse_shell",
        pattern=re.compile(
            r"socket\.(?:socket|create_connection).{0,500}(?:connect|send).{0,500}(?:subprocess|os\.dup2)",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="Potential reverse shell",
    ),
    MaliciousPattern(
        name="crypto_miner",
        pattern=re.compile(r"(?:stratum\+tcp://|xmrig|coinhive|cryptonight|monero|ethash)", re.IGNORECASE),
        severity="critical",
        description="Cryptocurrency mining indicators",
    ),
    MaliciousPattern(
        name="ci_env_check",
        pattern=re.compile(
            r"os\.environ\.get\(['\"](?:GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|TRAVIS|CI)['\"]",
            re.IGNORECASE,
        ),
        severity="medium",
        description="CI/CD environment detection",
    ),
    MaliciousPattern(
        name="telegram_exfil",
        pattern=re.compile(r"api\.telegram\.org/bot", re.IGNORECASE),
        severity="high",
        description="Telegram bot API (potential exfiltration)",
    ),
    MaliciousPattern(
        name="tunnel_service",
        pattern=re.compile(r"(?:ngrok\.io|serveo\.net|localtunnel\.me|bore\.pub)", re.IGNORECASE),
        severity="high",
        description="Tunneling service (potential C2)",
    ),
    MaliciousPattern(
        name="cloud_metadata_expanded",
        pattern=re.compile(
            r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|100\.100\.100\.200|168\.63\.129\.16",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Cloud instance metadata API access",
    ),
    MaliciousPattern(
        name="pickle_load",
        pattern=re.compile(r"(?:pickle|_pickle|cPickle)\.loads?\(|shelve\.open", re.IGNORECASE),
        severity="high",
        description="Pickle deserialization (potential RCE)",
    ),
    MaliciousPattern(
        name="yaml_unsafe_load",
        pattern=re.compile(
            r"yaml\.(?:unsafe_load|full_load)\s*\(|yaml\.load\s*\([^)]*(?:Loader\s*=\s*None|$)",
            re.IGNORECASE,
        ),
        severity="high",
        description="Unsafe YAML load (potential RCE)",
    ),
    MaliciousPattern(
        name="marshal_load",
        pattern=re.compile(r"marshal\.loads?\(", re.IGNORECASE),
        severity="high",
        description="Marshal deserialization",
    ),
    MaliciousPattern(
        name="import_dunder",
        pattern=re.compile(
            r"__import__\s*\(\s*(?![\x27\x22](?:os|sys|json|re|math|io|pathlib)[\x27\x22])",
            re.IGNORECASE,
        ),
        severity="high",
        description="Dynamic __import__() with non-standard module",
    ),
    MaliciousPattern(
        name="destructive_command",
        pattern=re.compile(r"(?:shred|rm\s+-rf\s+/|os\.remove|shutil\.rmtree\s*\(\s*['\"/])", re.IGNORECASE),
        severity="critical",
        description="Destructive command (data destruction)",
    ),
    MaliciousPattern(
        name="procfs_access",
        pattern=re.compile(r"/proc/\w+/(?:mem|maps|environ|cmdline)", re.IGNORECASE),
        severity="critical",
        description="Process memory/environment access via /proc",
    ),
    MaliciousPattern(
        name="unicode_escape_exec",
        pattern=re.compile(r"exec\s*\(.{0,500}\\u[0-9a-fA-F]{4}", re.IGNORECASE),
        severity="high",
        description="Unicode escape sequence in exec/eval (obfuscation)",
    ),
    MaliciousPattern(
        name="image_code_extraction",
        pattern=re.compile(r"(?:Image\.open|getdata|getpixel).{0,500}(?:exec|eval|chr)", re.IGNORECASE | re.DOTALL),
        severity="critical",
        description="Code extraction from image data (steganography)",
    ),
    MaliciousPattern(
        name="system_binary_write",
        pattern=re.compile(r"(?:open|write).{0,500}(?:/usr/local/bin|/usr/bin|/bin/)", re.IGNORECASE),
        severity="critical",
        description="System binary path write (PATH hijack)",
    ),
    MaliciousPattern(
        name="ld_preload_inject",
        pattern=re.compile(r"LD_PRELOAD|DYLD_INSERT_LIBRARIES", re.IGNORECASE),
        severity="critical",
        description="Dynamic linker injection (LD_PRELOAD/DYLD_INSERT_LIBRARIES)",
    ),
    MaliciousPattern(
        name="git_hook_write",
        pattern=re.compile(r"(?:open|write).{0,500}\.git/hooks", re.IGNORECASE),
        severity="critical",
        description="Git hook injection (persistence)",
    ),
    MaliciousPattern(
        name="getattr_exec",
        pattern=re.compile(
            r"getattr\s*\(\s*__builtins__.{0,500}(?:exec|eval|compile|system)", re.IGNORECASE | re.DOTALL
        ),
        severity="critical",
        description="getattr(__builtins__) code execution bypass",
    ),
    MaliciousPattern(
        name="sitecustomize_write",
        pattern=re.compile(r"sitecustomize\.py|usercustomize\.py", re.IGNORECASE),
        severity="critical",
        description="Python startup hook persistence (sitecustomize/usercustomize)",
    ),
    MaliciousPattern(
        name="unicode_steganography",
        pattern=re.compile(r"[\u200b\u200c\u200d\u2060\u2062\u2063\ufeff\u202e\u202d]"),
        severity="high",
        description="Zero-width/invisible Unicode characters (steganography/obfuscation)",
    ),
    MaliciousPattern(
        name="cloud_storage_download",
        pattern=re.compile(
            r"(?:s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|r2\.cloudflarestorage\.com)",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Download from cloud storage (potential payload staging)",
    ),
    MaliciousPattern(
        name="k8s_secret_access",
        pattern=re.compile(r"/var/run/secrets/kubernetes\.io|KUBERNETES_SERVICE", re.IGNORECASE),
        severity="critical",
        description="Kubernetes secret/service account access",
    ),
    MaliciousPattern(
        name="private_key_access",
        pattern=re.compile(r"""(?:open|read).{0,500}\.(?:pem|key|p12|pfx)""", re.IGNORECASE),
        severity="high",
        description="Private key/certificate file access",
    ),
    MaliciousPattern(
        name="env_reflection",
        pattern=re.compile(r"os\.environ\[.{0,500}os\.environ|os\.environ\.get\(.{0,500}\+", re.IGNORECASE),
        severity="high",
        description="Environment variable reflection/computed access",
    ),
]

# -- Multiline patterns --

MULTILINE_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="split_eval_base64",
        pattern=re.compile(
            r"(?:b64decode|base64\.b64decode)\s*\([^)]+\)[\s\S]{0,200}(?:exec|eval|compile)\s*\(",
            re.DOTALL,
        ),
        severity="critical",
        description="Base64 decode and exec/eval split across lines",
    ),
    MaliciousPattern(
        name="fetch_then_eval",
        pattern=re.compile(
            r"(?:urllib|requests|httpx)\.(?:get|post|urlopen)\s*\([^)]+\)[\s\S]{0,300}(?:exec|eval)\s*\(",
            re.DOTALL,
        ),
        severity="critical",
        description="Network fetch followed by code execution",
    ),
]

# -- Known malicious patterns --

KNOWN_MALICIOUS_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="known_c2_domain",
        pattern=re.compile(r"""sfrclak\.com""", re.IGNORECASE),
        severity="critical",
        description="Known C2 domain",
    ),
    MaliciousPattern(
        name="known_c2_ip",
        pattern=re.compile(r"""142\.11\.206\.73"""),
        severity="critical",
        description="Known C2 IP address",
    ),
]

# -- Aggregate --

ALL_PYPI_PATTERNS: list[MaliciousPattern] = (
    CREDENTIAL_ACCESS_PATTERNS
    + NETWORK_EXFIL_PATTERNS
    + OBFUSCATION_PATTERNS
    + PERSISTENCE_PATTERNS
    + SETUP_PATTERNS
    + ADVANCED_THREAT_PATTERNS
    + KNOWN_MALICIOUS_PATTERNS
)

# -- False positive exclusions --
FALSE_POSITIVE_INDICATORS: list[str] = [
    "cythonize",
    "setuptools.Extension",
    "cmake",
    "meson",
    "numpy.distutils",
    "pybind11",
    "cffi.ffibuilder",
]
