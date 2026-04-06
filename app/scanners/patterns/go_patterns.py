"""Malicious pattern definitions for Go module packages."""

import re

from app.scanners.patterns.npm_patterns import MaliciousPattern

# -- Command execution --

COMMAND_EXECUTION_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="exec_command",
        pattern=re.compile(r"exec\.Command(?:Context)?\s*\("),
        severity="high",
        description="os/exec command execution",
    ),
    MaliciousPattern(
        name="syscall_exec",
        pattern=re.compile(r"syscall\.(?:Exec|ForkExec|StartProcess)\s*\("),
        severity="critical",
        description="Low-level syscall process execution",
    ),
    MaliciousPattern(
        name="os_start_process",
        pattern=re.compile(r"os\.StartProcess\s*\("),
        severity="high",
        description="os.StartProcess call",
    ),
    MaliciousPattern(
        name="plugin_open",
        pattern=re.compile(r"plugin\.Open\s*\("),
        severity="high",
        description="Dynamic plugin loading",
    ),
    MaliciousPattern(
        name="shell_invocation",
        pattern=re.compile(r"""exec\.Command(?:Context)?\s*\(\s*["'](?:sh|bash|cmd|powershell|/bin/sh)["']"""),
        severity="critical",
        description="Shell invocation via exec.Command",
    ),
]

# -- Network exfiltration --

NETWORK_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="http_in_init",
        pattern=re.compile(r"func\s+init\s*\(\s*\).{0,500}http\.(?:Get|Post|NewRequest)", re.DOTALL),
        severity="high",
        description="HTTP request in init() function",
    ),
    MaliciousPattern(
        name="net_dial_in_init",
        pattern=re.compile(r"func\s+init\s*\(\s*\).{0,500}net\.Dial", re.DOTALL),
        severity="high",
        description="Network dial in init() function",
    ),
    MaliciousPattern(
        name="dns_exfiltration",
        pattern=re.compile(r"net\.Lookup(?:Host|Addr|IP|CNAME)\s*\("),
        severity="medium",
        description="DNS lookup (potential data exfiltration)",
    ),
    MaliciousPattern(
        name="suspicious_url",
        pattern=re.compile(
            r"""["']https?://(?:\d{1,3}\.){3}\d{1,3}[/:"']""",
        ),
        severity="high",
        description="HTTP request to raw IP address",
    ),
    MaliciousPattern(
        name="webhook_exfiltration",
        pattern=re.compile(
            r"""["']https?://(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|api\.telegram\.org)""",
            re.IGNORECASE,
        ),
        severity="critical",
        description="Data exfiltration via webhook/messaging service",
    ),
    MaliciousPattern(
        name="cloud_metadata",
        pattern=re.compile(r"169\.254\.169\.254"),
        severity="critical",
        description="Cloud metadata endpoint access (SSRF/credential theft)",
    ),
]

# -- CGo / unsafe --

UNSAFE_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="cgo_import",
        pattern=re.compile(r'import\s+"C"'),
        severity="medium",
        description="CGo import (enables arbitrary C code execution)",
    ),
    MaliciousPattern(
        name="unsafe_import",
        pattern=re.compile(r'import\s+"unsafe"'),
        severity="low",
        description="Unsafe pointer operations",
    ),
    MaliciousPattern(
        name="go_linkname",
        pattern=re.compile(r"//go:linkname\b"),
        severity="medium",
        description="go:linkname directive (type system bypass)",
    ),
]

# -- Build-time injection --

BUILD_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="go_generate_shell",
        pattern=re.compile(r"//go:generate\s+(?:sh|bash|cmd|powershell|/bin/sh)\b"),
        severity="critical",
        description="go:generate with shell execution",
    ),
    MaliciousPattern(
        name="go_generate",
        pattern=re.compile(r"//go:generate\b"),
        severity="medium",
        description="go:generate directive (runs commands at build time)",
    ),
]

# -- Obfuscation --

OBFUSCATION_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="hex_string",
        pattern=re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
        severity="medium",
        description="Long hex-encoded string (potential payload)",
    ),
    MaliciousPattern(
        name="base64_exec",
        pattern=re.compile(r"base64\.(?:Std|URL)Encoding\.DecodeString.{0,200}exec\.Command", re.DOTALL),
        severity="critical",
        description="Base64 decode followed by command execution",
    ),
]

# -- System access --

SYSTEM_ACCESS_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="ssh_key_access",
        pattern=re.compile(r"""(?:os\.(?:Open|ReadFile)|ioutil\.ReadFile).{0,200}\.ssh""", re.DOTALL),
        severity="critical",
        description="SSH key file access",
    ),
    MaliciousPattern(
        name="aws_credential_access",
        pattern=re.compile(r"""(?:os\.(?:Open|ReadFile)|ioutil\.ReadFile).{0,200}\.aws""", re.DOTALL),
        severity="critical",
        description="AWS credential file access",
    ),
    MaliciousPattern(
        name="etc_passwd",
        pattern=re.compile(r"""/etc/(?:passwd|shadow)"""),
        severity="critical",
        description="System password file access",
    ),
    MaliciousPattern(
        name="proc_access",
        pattern=re.compile(r"""/proc/(?:self|[0-9]+)/"""),
        severity="high",
        description="Proc filesystem access",
    ),
    MaliciousPattern(
        name="crontab_persistence",
        pattern=re.compile(r"""(?:crontab|/etc/cron|/var/spool/cron)"""),
        severity="critical",
        description="Crontab persistence mechanism",
    ),
]

# -- go.mod patterns --

GOMOD_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="replace_directive_url",
        pattern=re.compile(r"replace\s+\S+\s+=>\s+https?://"),
        severity="medium",
        description="go.mod replace directive pointing to URL",
    ),
    MaliciousPattern(
        name="replace_directive_local",
        pattern=re.compile(r"replace\s+\S+\s+=>\s+(?:\.\.|/)"),
        severity="medium",
        description="go.mod replace directive pointing to local path",
    ),
]

# -- Aggregate --

ALL_GO_PATTERNS: list[MaliciousPattern] = (
    COMMAND_EXECUTION_PATTERNS
    + NETWORK_PATTERNS
    + UNSAFE_PATTERNS
    + BUILD_PATTERNS
    + OBFUSCATION_PATTERNS
    + SYSTEM_ACCESS_PATTERNS
    + GOMOD_PATTERNS
)
