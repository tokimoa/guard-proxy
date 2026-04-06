"""Malicious pattern definitions for RubyGems packages."""

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
        pattern=re.compile(r"ENV\.to_h|ENV\.to_a|ENV\.each|ENV\.map", re.IGNORECASE),
        severity="high",
        description="Bulk environment variable access",
    ),
    MaliciousPattern(
        name="ssh_key_access",
        pattern=re.compile(r"""(?:File\.read|Dir\.glob|IO\.read).{0,200}\.ssh""", re.IGNORECASE),
        severity="critical",
        description="SSH key file access",
    ),
    MaliciousPattern(
        name="aws_credential_access",
        pattern=re.compile(r"""(?:File\.read|Dir\.glob|IO\.read).{0,200}\.aws""", re.IGNORECASE),
        severity="critical",
        description="AWS credential file access",
    ),
    MaliciousPattern(
        name="credential_file_access",
        pattern=re.compile(
            r"""(?:File\.read|Dir\.glob|IO\.read).{0,200}(?:\.gnupg|\.docker|\.kube|\.config/gcloud)""",
            re.IGNORECASE,
        ),
        severity="high",
        description="Credential/config file access",
    ),
    MaliciousPattern(
        name="home_dir_traversal",
        pattern=re.compile(r"Dir\.home|ENV\[.HOME.\].{0,200}(?:Dir\.glob|File\.read|Dir\.entries)", re.IGNORECASE),
        severity="high",
        description="Home directory traversal",
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
        name="net_http_with_env",
        pattern=re.compile(
            r"(?:Net::HTTP|URI\.open|open-uri|HTTParty|Faraday|RestClient).{0,200}ENV",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="HTTP request combined with ENV access",
    ),
    MaliciousPattern(
        name="socket_connection",
        pattern=re.compile(r"TCPSocket\.(?:new|open)|UDPSocket\.(?:new|open)", re.IGNORECASE),
        severity="high",
        description="Raw socket connection",
    ),
]

# -- Obfuscation / code execution patterns --

OBFUSCATION_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="base64_eval",
        pattern=re.compile(
            r"(?:Base64\.decode64|Base64\.urlsafe_decode64).{0,200}eval|eval.{0,200}(?:Base64\.decode64|Base64\.urlsafe_decode64)",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="Base64 decode combined with eval",
    ),
    MaliciousPattern(
        name="eval_dynamic",
        pattern=re.compile(r"""(?:Kernel\.)?eval\s*\(?\s*(?!['\"])"""),
        severity="high",
        description="Dynamic eval with non-literal argument",
    ),
    MaliciousPattern(
        name="instance_eval_dynamic",
        pattern=re.compile(r"(?:instance_eval|class_eval|module_eval)\s*[\({]"),
        severity="high",
        description="Dynamic instance/class/module eval",
    ),
    MaliciousPattern(
        name="backtick_suspicious",
        pattern=re.compile(r"""`[^`]*(?:curl|wget|nc\b|bash|sh\b|powershell)""", re.IGNORECASE),
        severity="high",
        description="Backtick execution of network/shell command",
    ),
    MaliciousPattern(
        name="system_suspicious",
        pattern=re.compile(
            r"""(?:system|exec|%x)\s*[\(\{].{0,200}(?:curl|wget|nc\b|bash|sh\b|powershell)""",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        description="system/exec with network/shell command",
    ),
    MaliciousPattern(
        name="io_popen",
        pattern=re.compile(r"IO\.popen|Open3\.(?:capture|popen)", re.IGNORECASE),
        severity="medium",
        description="IO.popen / Open3 process execution",
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
        name="shell_profile_write",
        pattern=re.compile(
            r"""File\.(?:write|open|append).{0,200}(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)""",
            re.IGNORECASE,
        ),
        severity="high",
        description="Shell profile modification",
    ),
]

# -- Advanced threat patterns --

ADVANCED_THREAT_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="reverse_shell",
        pattern=re.compile(
            r"TCPSocket\.(?:new|open).{0,200}(?:exec|system|spawn|\$stdin\.reopen)",
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
            r"ENV\[['\"](?:GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|TRAVIS|CI|CIRCLECI)['\"]",
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
        name="marshal_load_unsafe",
        pattern=re.compile(r"Marshal\.(?:load|restore)\s*\(", re.IGNORECASE),
        severity="high",
        description="Marshal deserialization (potential RCE)",
    ),
    MaliciousPattern(
        name="yaml_unsafe_load",
        pattern=re.compile(r"YAML\.load\s*\((?!.{0,200}safe)", re.IGNORECASE),
        severity="high",
        description="Unsafe YAML load (potential RCE)",
    ),
    MaliciousPattern(
        name="erb_eval",
        pattern=re.compile(r"ERB\.new\s*\(.{0,200}\)\.result", re.IGNORECASE | re.DOTALL),
        severity="high",
        description="ERB template evaluation (potential code injection)",
    ),
    MaliciousPattern(
        name="destructive_command",
        pattern=re.compile(r"(?:shred|rm\s+-rf\s+/|FileUtils\.rm_rf)", re.IGNORECASE),
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
        name="system_binary_write",
        pattern=re.compile(
            r"(?:File\.write|File\.open|IO\.write).{0,200}(?:/usr/local/bin|/usr/bin|/bin/)", re.IGNORECASE
        ),
        severity="critical",
        description="System binary path write (PATH hijack)",
    ),
    MaliciousPattern(
        name="git_hook_write",
        pattern=re.compile(r"(?:File\.write|File\.open|IO\.write).{0,200}\.git/hooks", re.IGNORECASE),
        severity="critical",
        description="Git hook injection (persistence)",
    ),
    MaliciousPattern(
        name="send_system",
        pattern=re.compile(r"(?:Kernel\.)?send\s*\(\s*:(?:system|exec|eval|`)", re.IGNORECASE),
        severity="critical",
        description="Method dispatch bypass via send(:system)",
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
        pattern=re.compile(r"""(?:File\.read|IO\.read).{0,200}\.(?:pem|key|p12|pfx)""", re.IGNORECASE),
        severity="high",
        description="Private key/certificate file access",
    ),
    MaliciousPattern(
        name="env_reflection",
        pattern=re.compile(r"ENV\[.{0,200}ENV\[|ENV\.fetch\(.{0,200}\+", re.IGNORECASE),
        severity="high",
        description="Environment variable reflection/computed access",
    ),
]

# -- Multiline patterns --

MULTILINE_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="split_eval_base64",
        pattern=re.compile(
            r"Base64\.decode64\s*\([^)]+\)[\s\S]{0,200}(?:eval|instance_eval|class_eval)\s*[\(\{]",
            re.DOTALL,
        ),
        severity="critical",
        description="Base64 decode and eval split across lines",
    ),
    MaliciousPattern(
        name="fetch_then_eval",
        pattern=re.compile(
            r"(?:Net::HTTP|URI\.open|open-uri)[\s\S]{0,300}(?:eval|instance_eval|exec)\s*[\(\{]",
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

ALL_RUBYGEMS_PATTERNS: list[MaliciousPattern] = (
    CREDENTIAL_ACCESS_PATTERNS
    + NETWORK_EXFIL_PATTERNS
    + OBFUSCATION_PATTERNS
    + PERSISTENCE_PATTERNS
    + ADVANCED_THREAT_PATTERNS
    + KNOWN_MALICIOUS_PATTERNS
)

# -- False positive exclusions (legitimate native extension build) --
FALSE_POSITIVE_INDICATORS: list[str] = [
    "mkmf",
    "create_makefile",
    "have_library",
    "find_executable",
    "pkg_config",
    "RbConfig",
    "Gem::Ext::BuildError",
]
