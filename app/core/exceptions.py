"""Custom exceptions for Guard Proxy."""


class GuardProxyError(Exception):
    """Base exception for Guard Proxy."""


class PackageBlockedError(GuardProxyError):
    """Raised when a package is denied by the decision engine."""

    def __init__(self, package_name: str, version: str, reason: str) -> None:
        self.package_name = package_name
        self.version = version
        self.reason = reason
        super().__init__(f"Package blocked: {package_name}@{version} — {reason}")


class PackageNotFoundError(GuardProxyError):
    """Raised when package is not found on upstream registry."""

    def __init__(self, package_name: str, version: str | None = None) -> None:
        self.package_name = package_name
        self.version = version
        msg = f"Package not found: {package_name}"
        if version:
            msg += f"@{version}"
        super().__init__(msg)


class ScanTimeoutError(GuardProxyError):
    """Raised when scanning exceeds the timeout."""

    def __init__(self, package_name: str, timeout_seconds: float) -> None:
        self.package_name = package_name
        self.timeout_seconds = timeout_seconds
        super().__init__(f"Scan timeout after {timeout_seconds}s for {package_name}")


class UpstreamRegistryError(GuardProxyError):
    """Raised when upstream registry is unreachable or returns an error."""

    def __init__(self, url: str, status_code: int | None = None, detail: str = "") -> None:
        self.url = url
        self.status_code = status_code
        self.detail = detail
        msg = f"Upstream registry error: {url}"
        if status_code:
            msg += f" (HTTP {status_code})"
        if detail:
            msg += f" — {detail}"
        super().__init__(msg)


class TarballExtractionError(GuardProxyError):
    """Raised when tarball extraction fails."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Tarball extraction failed: {detail}")
