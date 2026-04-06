"""Malicious pattern definitions for Cargo (Rust) packages."""

import re

from app.scanners.patterns.npm_patterns import MaliciousPattern

# -- build.rs abuse (compile-time execution) --

BUILD_RS_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="build_rs_command",
        pattern=re.compile(r"Command::new\s*\("),
        severity="high",
        description="std::process::Command in build script",
    ),
    MaliciousPattern(
        name="build_rs_shell",
        pattern=re.compile(r"""Command::new\s*\(\s*["'](?:sh|bash|cmd|powershell)["']"""),
        severity="critical",
        description="Shell invocation in build script",
    ),
    MaliciousPattern(
        name="build_rs_env_access",
        pattern=re.compile(r"env::var(?:_os)?\s*\(\s*[\"'](?:HOME|USER|AWS_|SSH_|TOKEN|SECRET|PASSWORD|API_KEY)"),
        severity="high",
        description="Sensitive environment variable access in build script",
    ),
    MaliciousPattern(
        name="build_rs_network",
        pattern=re.compile(r"""(?:TcpStream|UdpSocket|reqwest|ureq|curl|hyper)"""),
        severity="high",
        description="Network access in build script",
    ),
]

# -- Command execution --

COMMAND_EXECUTION_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="process_command",
        pattern=re.compile(r"std::process::Command::new\s*\("),
        severity="high",
        description="Process command execution",
    ),
    MaliciousPattern(
        name="shell_exec",
        pattern=re.compile(r"""Command::new\s*\(\s*["'](?:sh|bash|cmd|powershell|/bin/sh)["']"""),
        severity="critical",
        description="Shell execution",
    ),
    MaliciousPattern(
        name="libc_system",
        pattern=re.compile(r"libc::system\s*\("),
        severity="critical",
        description="libc::system() call (arbitrary command execution)",
    ),
]

# -- Unsafe / FFI --

UNSAFE_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="extern_c_block",
        pattern=re.compile(r'extern\s+"C"\s*\{'),
        severity="medium",
        description="FFI extern C block",
    ),
    MaliciousPattern(
        name="include_bytes_remote",
        pattern=re.compile(r"include_bytes!\s*\("),
        severity="low",
        description="include_bytes! macro (potential embedded payload)",
    ),
    MaliciousPattern(
        name="include_str_macro",
        pattern=re.compile(r"include_str!\s*\("),
        severity="low",
        description="include_str! macro",
    ),
]

# -- Proc macros --

PROC_MACRO_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="proc_macro_command",
        pattern=re.compile(r"proc_macro.{0,500}Command::new", re.DOTALL),
        severity="high",
        description="Process execution inside proc macro",
    ),
]

# -- Network exfiltration --

NETWORK_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="suspicious_url",
        pattern=re.compile(r"""["']https?://(?:\d{1,3}\.){3}\d{1,3}[/:"']"""),
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
        description="Cloud metadata endpoint access",
    ),
]

# -- System access --

SYSTEM_ACCESS_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="ssh_key_access",
        pattern=re.compile(r"""(?:read_to_string|read|File::open).{0,200}\.ssh""", re.DOTALL),
        severity="critical",
        description="SSH key file access",
    ),
    MaliciousPattern(
        name="aws_credential_access",
        pattern=re.compile(r"""(?:read_to_string|read|File::open).{0,200}\.aws""", re.DOTALL),
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
        name="crontab_persistence",
        pattern=re.compile(r"""(?:crontab|/etc/cron|/var/spool/cron)"""),
        severity="critical",
        description="Crontab persistence mechanism",
    ),
]

# -- Obfuscation --

OBFUSCATION_PATTERNS: list[MaliciousPattern] = [
    MaliciousPattern(
        name="hex_bytes",
        pattern=re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
        severity="medium",
        description="Long hex-encoded byte sequence",
    ),
    MaliciousPattern(
        name="base64_decode_exec",
        pattern=re.compile(r"base64.{0,100}decode.{0,200}Command", re.DOTALL),
        severity="critical",
        description="Base64 decode followed by command execution",
    ),
]

# -- Aggregate --

ALL_CARGO_PATTERNS: list[MaliciousPattern] = (
    BUILD_RS_PATTERNS
    + COMMAND_EXECUTION_PATTERNS
    + UNSAFE_PATTERNS
    + PROC_MACRO_PATTERNS
    + NETWORK_PATTERNS
    + SYSTEM_ACCESS_PATTERNS
    + OBFUSCATION_PATTERNS
)

# Patterns only applicable to build.rs files
BUILD_RS_ONLY_NAMES = {p.name for p in BUILD_RS_PATTERNS}
