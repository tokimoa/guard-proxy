"""Malicious pattern definitions for npm packages."""

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
        pattern=re.compile(r"process\.env(?!\.\w)|JSON\.stringify\(process\.env\)", re.IGNORECASE),
        severity="high",
        description="Bulk environment variable access",
    ),
    MaliciousPattern(
        name="ssh_key_access",
        pattern=re.compile(
            r"""(?:readFile(?:Sync)?|readdir(?:Sync)?|access(?:Sync)?|open(?:Sync)?).*['"~].*\.ssh""",
            re.IGNORECASE,
        ),
        severity="critical",
        description="SSH key file access",
    ),
    MaliciousPattern(
        name="aws_credential_access",
        pattern=re.compile(r"""(?:readFile(?:Sync)?|readdir(?:Sync)?|access(?:Sync)?).*['"~].*\.aws""", re.IGNORECASE),
        severity="critical",
        description="AWS credential file access",
    ),
    MaliciousPattern(
        name="credential_file_access",
        pattern=re.compile(
            r"""(?:readFile(?:Sync)?|readdir(?:Sync)?|access(?:Sync)?).*['"].*(?:\.gnupg|\.npmrc|\.docker|\.kube|\.config/gcloud)""",
            re.IGNORECASE,
        ),
        severity="high",
        description="Credential/config file access",
    ),
    MaliciousPattern(
        name="homedir_traversal",
        pattern=re.compile(r"os\.homedir\(\).*(?:readdir|readdirSync|readFile)", re.IGNORECASE),
        severity="high",
        description="Home directory traversal",
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
        name="dns_exfil",
        pattern=re.compile(r"dns\.resolve|dns\.lookup.*(?:process\.env|Buffer\.from)", re.IGNORECASE),
        severity="high",
        description="Potential DNS exfiltration",
    ),
    MaliciousPattern(
        name="data_exfil_http",
        pattern=re.compile(
            r"(?:https?\.(?:get|request|post)|fetch|axios|got)\s*\(.*(?:process\.env|readFile|Buffer\.from)",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="Data exfiltration via HTTP",
    ),
    MaliciousPattern(
        name="webhook_exfil",
        pattern=re.compile(
            r"""https?://(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|.*webhook)""",
            re.IGNORECASE,
        ),
        severity="medium",
        description="Data sent to webhook endpoint",
    ),
]

# -- Obfuscation / evasion patterns --

OBFUSCATION_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="base64_eval",
        pattern=re.compile(
            r"""(?:(?:Buffer\.from|atob)\s*\(.*(?:eval|Function|exec))|(?:(?:eval|Function|exec)\s*\(.*(?:Buffer\.from|atob))""",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="Base64 decode combined with eval/exec",
    ),
    MaliciousPattern(
        name="eval_dynamic",
        pattern=re.compile(r"""eval\s*\(\s*(?!['"])"""),
        severity="high",
        description="Dynamic eval with non-literal argument",
    ),
    MaliciousPattern(
        name="function_constructor",
        pattern=re.compile(r"""new\s+Function\s*\("""),
        severity="high",
        description="Function constructor (dynamic code execution)",
    ),
    MaliciousPattern(
        name="hex_encoded_strings",
        pattern=re.compile(r"""(?:\\x[0-9a-fA-F]{2}){8,}"""),
        severity="medium",
        description="Long hex-encoded string sequences",
    ),
    MaliciousPattern(
        name="char_code_obfuscation",
        pattern=re.compile(r"""String\.fromCharCode\s*\([^)]*(?:,\s*\d+){5,}"""),
        severity="high",
        description="Character code obfuscation",
    ),
]

# -- Persistence patterns --

PERSISTENCE_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="crontab_write",
        pattern=re.compile(r"""(?:crontab|\/etc\/cron)""", re.IGNORECASE),
        severity="critical",
        description="Crontab modification",
    ),
    MaliciousPattern(
        name="systemd_write",
        pattern=re.compile(r"""(?:systemd|systemctl|\/etc\/init\.d)""", re.IGNORECASE),
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
            r"""(?:writeFile|appendFile).*(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)""",
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
            r"(?:net\.Socket|child_process).*(?:connect|spawn).*(?:\d{1,3}\.){3}\d{1,3}",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="Potential reverse shell connection",
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
            r"(?:GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|TRAVIS|CIRCLECI|CODEBUILD|BUILDKITE)\s*(?:[!=]==?\s*['\"]|in\b)",
            re.IGNORECASE,
        ),
        severity="medium",
        description="CI/CD environment detection (conditional payload risk)",
    ),
    MaliciousPattern(
        name="telegram_exfil",
        pattern=re.compile(r"api\.telegram\.org/bot", re.IGNORECASE),
        severity="high",
        description="Telegram bot API (potential exfiltration channel)",
    ),
    MaliciousPattern(
        name="pastebin_exfil",
        pattern=re.compile(r"(?:pastebin\.com|hastebin\.com|paste\.ee|ghostbin\.co)/", re.IGNORECASE),
        severity="medium",
        description="Paste service access (potential data drop)",
    ),
    MaliciousPattern(
        name="tunnel_service",
        pattern=re.compile(r"(?:ngrok\.io|serveo\.net|localtunnel\.me|bore\.pub)", re.IGNORECASE),
        severity="high",
        description="Tunneling service (potential reverse shell/C2)",
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
        name="vm_sandbox_escape",
        pattern=re.compile(r"vm\.(?:runInNewContext|runInContext|createContext|Script)", re.IGNORECASE),
        severity="high",
        description="VM sandbox execution (potential escape)",
    ),
    MaliciousPattern(
        name="deserialize_unsafe",
        pattern=re.compile(r"(?:node-serialize|serialize-javascript).*(?:unserialize|deserialize)", re.IGNORECASE),
        severity="critical",
        description="Unsafe deserialization (RCE risk)",
    ),
    MaliciousPattern(
        name="wasm_exec",
        pattern=re.compile(r"WebAssembly\.(?:instantiate|compile).*(?:fetch|readFile)", re.IGNORECASE | re.DOTALL),
        severity="medium",
        description="WebAssembly loaded from external source",
    ),
    MaliciousPattern(
        name="delayed_exec",
        pattern=re.compile(
            r"(?:setTimeout|setInterval)\s*\([\s\S]{0,500}(?:exec|spawn|system|eval|Function|child_process)",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        description="Delayed code execution (time-bomb pattern)",
    ),
    MaliciousPattern(
        name="date_killswitch",
        pattern=re.compile(
            r"new\s+Date\s*\(\s*['\"]20\d{2}.*(?:process\.exit|exec|eval|child_process)",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        description="Date-based kill-switch / time-bomb activation",
    ),
    MaliciousPattern(
        name="git_hook_write",
        pattern=re.compile(r"(?:writeFile|appendFile|open).*\.git/hooks", re.IGNORECASE),
        severity="critical",
        description="Git hook injection (persistence)",
    ),
    MaliciousPattern(
        name="charcode_function",
        pattern=re.compile(
            r"String\.fromCharCode.*(?:Function|eval)|(?:Function|eval).*String\.fromCharCode",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="critical",
        description="CharCode construction with Function/eval (obfuscation)",
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
        name="anti_forensics",
        pattern=re.compile(r"(?:unlinkSync|rmSync|unlink)\s*\(.*(?:setup|install|hook)", re.IGNORECASE),
        severity="high",
        description="Anti-forensics: self-deleting install script",
    ),
    MaliciousPattern(
        name="dll_hijacking",
        pattern=re.compile(r"(?:writeFile|write).*(?:System32|SysWOW64|Windows).*\.dll", re.IGNORECASE),
        severity="critical",
        description="DLL hijacking (writing to Windows system directories)",
    ),
    MaliciousPattern(
        name="destructive_command",
        pattern=re.compile(r"(?:shred|rm\s+-rf\s+/|del\s+/s\s+/q|cipher\s+/w:)", re.IGNORECASE),
        severity="critical",
        description="Destructive command (data destruction / dead man's switch)",
    ),
    MaliciousPattern(
        name="terminal_spawn",
        pattern=re.compile(
            r"(?:open\s+-a\s+Terminal|gnome-terminal|xterm\s+-e|konsole|cmd\s+/c\s+start)",
            re.IGNORECASE,
        ),
        severity="high",
        description="New terminal/process window spawn (multi-stage payload)",
    ),
    MaliciousPattern(
        name="procfs_access",
        pattern=re.compile(r"/proc/.*(?:mem|maps|environ|cmdline)", re.IGNORECASE),
        severity="critical",
        description="Process memory/environment access via /proc (credential scanning)",
    ),
    MaliciousPattern(
        name="system_binary_write",
        pattern=re.compile(r"(?:writeFile|open|write).*(?:/usr/local/bin|/usr/bin|/bin/)", re.IGNORECASE),
        severity="critical",
        description="System binary path write (PATH hijack)",
    ),
    MaliciousPattern(
        name="shell_command_injection",
        pattern=re.compile(r"""\$\(.*(?:curl|wget|bash|sh\b|nc\b)""", re.IGNORECASE),
        severity="high",
        description="Shell command substitution with network/exec command",
    ),
    MaliciousPattern(
        name="k8s_secret_access",
        pattern=re.compile(r"/var/run/secrets/kubernetes\.io|KUBERNETES_SERVICE", re.IGNORECASE),
        severity="critical",
        description="Kubernetes secret/service account access",
    ),
    MaliciousPattern(
        name="private_key_access",
        pattern=re.compile(r"""(?:readFile|readdir|access).*\.(?:pem|key|p12|pfx|jks)""", re.IGNORECASE),
        severity="high",
        description="Private key/certificate file access",
    ),
    MaliciousPattern(
        name="env_reflection",
        pattern=re.compile(r"process\.env\[.*process\.env|process\.env\[.*\+", re.IGNORECASE),
        severity="high",
        description="Environment variable reflection/computed access",
    ),
]

# -- Multiline patterns (match across line boundaries) --

MULTILINE_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="split_eval_base64",
        pattern=re.compile(
            r"(?:atob|Buffer\.from|b64decode)\s*\([^)]+\)[\s\S]{0,200}(?:eval|exec|Function)\s*\(",
            re.DOTALL,
        ),
        severity="critical",
        description="Base64 decode and eval/exec split across lines",
    ),
    MaliciousPattern(
        name="fetch_then_eval",
        pattern=re.compile(
            r"(?:fetch|https?\.get|axios|got)\s*\([^)]+\)[\s\S]{0,300}(?:eval|Function|exec)\s*\(",
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
        description="Known C2 domain (axios compromise)",
    ),
    MaliciousPattern(
        name="known_c2_ip",
        pattern=re.compile(r"""142\.11\.206\.73"""),
        severity="critical",
        description="Known C2 IP address",
    ),
]

# -- Aggregate all patterns --

ALL_NPM_PATTERNS: list[MaliciousPattern] = (
    CREDENTIAL_ACCESS_PATTERNS
    + NETWORK_EXFIL_PATTERNS
    + OBFUSCATION_PATTERNS
    + PERSISTENCE_PATTERNS
    + ADVANCED_THREAT_PATTERNS
    + KNOWN_MALICIOUS_PATTERNS
)

# -- False positive exclusions --
# Install scripts that are known to be safe
FALSE_POSITIVE_COMMANDS: list[str] = [
    "node-gyp rebuild",
    "node-gyp configure build",
    "prebuild-install",
    "node-pre-gyp install",
    "tsc",
    "tsc --build",
    "npx tsc",
    "husky install",
    "husky",
    "patch-package",
    "ngcc",
    "opencollective-postinstall",
    "esbuild",
    "is-ci",
    "node install.js",  # esbuild's install script
]
