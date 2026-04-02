"""AST-based semantic analysis scanner.

Detects attacks that bypass regex pattern matching via variable indirection,
data flow obfuscation, and dynamic code construction.

Uses Python stdlib `ast` for .py files and `pyjsparser` for .js files.
"""

import ast
from pathlib import Path

from pydantic import BaseModel

from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

# Dangerous functions/attributes that should be tracked through variable assignments
_PYTHON_DANGEROUS_CALLS = {"eval", "exec", "compile", "getattr", "__import__"}
_PYTHON_DANGEROUS_ATTRS = {"os.environ", "os.system", "subprocess.run", "subprocess.Popen", "subprocess.call"}
_PYTHON_SENSITIVE_PATHS = {".ssh", ".aws", ".gnupg", ".npmrc", ".docker", ".kube", ".config/gcloud"}
_PYTHON_NETWORK_MODULES = {"requests", "urllib", "httpx", "http.client", "socket"}

_JS_DANGEROUS_GLOBALS = {"eval", "Function", "setTimeout", "setInterval"}
_JS_DANGEROUS_REQUIRES = {"child_process", "fs", "net", "http", "https", "dns"}


class ASTFinding(BaseModel):
    check: str
    severity: str
    detail: str
    file: str
    line: int = 0


class ASTScanner:
    """Semantic code analysis using AST parsing."""

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        findings: list[ASTFinding] = []

        for path in artifacts:
            if not path.exists() or not path.is_file():
                continue
            if path.stat().st_size > 512 * 1024:  # Skip files > 512KB
                continue
            # Skip metadata files
            if path.name in ("metadata.yaml", "package.json", "checksums.yaml.gz"):
                continue

            try:
                content = path.read_text(errors="replace")
            except OSError:
                continue

            if path.suffix == ".py" or path.name in ("setup.py", "setup.cfg"):
                findings.extend(self._analyze_python(content, path.name))
            elif path.suffix in (".js", ".mjs", ".cjs"):
                findings.extend(self._analyze_javascript(content, path.name))

        if not findings:
            return ScanResult(
                scanner_name="ast_analysis",
                verdict="pass",
                confidence=0.9,
                details="No suspicious code patterns detected by AST analysis",
            )

        max_sev = max({"low": 0, "medium": 1, "high": 2, "critical": 3}.get(f.severity, 0) for f in findings)
        if max_sev >= 3:
            verdict, confidence = "fail", min(1.0, 0.7 + len(findings) * 0.05)
        elif max_sev >= 2:
            verdict, confidence = "warn", min(0.8, 0.5 + len(findings) * 0.1)
        else:
            verdict, confidence = "warn", 0.4

        details = "; ".join(f.detail for f in findings[:5])
        return ScanResult(
            scanner_name="ast_analysis",
            verdict=verdict,
            confidence=round(confidence, 2),
            details=f"AST analysis: {details}",
            metadata={"findings": [f.model_dump() for f in findings[:10]]},
        )

    # ========== Python AST Analysis ==========

    def _analyze_python(self, content: str, filename: str) -> list[ASTFinding]:
        try:
            tree = ast.parse(content, filename=filename)
        except SyntaxError:
            return []

        findings: list[ASTFinding] = []
        visitor = _PythonSecurityVisitor(filename)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings

    # ========== JavaScript AST Analysis ==========

    def _analyze_javascript(self, content: str, filename: str) -> list[ASTFinding]:
        try:
            from pyjsparser import parse

            tree = parse(content)
        except Exception:
            return []

        findings: list[ASTFinding] = []
        tainted_vars: set[str] = set()
        self._walk_js_ast(tree, filename, findings, tainted_vars)
        return findings

    def _walk_js_ast(self, node: dict, filename: str, findings: list[ASTFinding], tainted: set[str]) -> None:
        if not isinstance(node, dict):
            return

        node_type = node.get("type", "")

        # Track variable assignments of dangerous globals
        if node_type == "VariableDeclarator":
            var_name = node.get("id", {}).get("name", "")
            init = node.get("init", {})
            if isinstance(init, dict):
                init_name = init.get("name", "")
                if init_name in _JS_DANGEROUS_GLOBALS:
                    tainted.add(var_name)
                    findings.append(
                        ASTFinding(
                            check="js_dangerous_alias",
                            severity="critical",
                            detail=f"Dangerous function aliased: {var_name} = {init_name}",
                            file=filename,
                        )
                    )

        # Track require() calls for dangerous modules
        if node_type == "CallExpression":
            callee = node.get("callee", {})
            args = node.get("arguments", [])

            # require('child_process') etc
            if isinstance(callee, dict) and callee.get("name") == "require" and args:
                arg = args[0]
                if isinstance(arg, dict) and arg.get("type") == "Literal":
                    mod_name = str(arg.get("value", ""))
                    if mod_name in _JS_DANGEROUS_REQUIRES:
                        # Check if result is assigned to a variable
                        pass  # The require itself is OK, but tracked

            # Detect calls to tainted variables
            if isinstance(callee, dict) and callee.get("name", "") in tainted:
                findings.append(
                    ASTFinding(
                        check="js_tainted_call",
                        severity="critical",
                        detail=f"Tainted function called: {callee.get('name', '')}()",
                        file=filename,
                    )
                )

        # Track string concatenation that builds dangerous module names
        if node_type == "BinaryExpression" and node.get("operator") == "+":
            combined = self._try_resolve_concat(node)
            if combined and any(m in combined for m in _JS_DANGEROUS_REQUIRES):
                findings.append(
                    ASTFinding(
                        check="js_dynamic_require",
                        severity="high",
                        detail=f"Dynamic module name construction: '{combined}'",
                        file=filename,
                    )
                )

        # Recurse into all child nodes
        for _key, value in node.items():
            if isinstance(value, dict):
                self._walk_js_ast(value, filename, findings, tainted)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._walk_js_ast(item, filename, findings, tainted)

    @staticmethod
    def _try_resolve_concat(node: dict) -> str | None:
        """Try to resolve string concatenation at AST level."""
        if node.get("type") == "Literal":
            return str(node.get("value", ""))
        if node.get("type") == "BinaryExpression" and node.get("operator") == "+":
            left = ASTScanner._try_resolve_concat(node.get("left", {}))
            right = ASTScanner._try_resolve_concat(node.get("right", {}))
            if left is not None and right is not None:
                return left + right
        return None


class _PythonSecurityVisitor(ast.NodeVisitor):
    """AST visitor that tracks dangerous variable assignments and data flow."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: list[ASTFinding] = []
        self._tainted_vars: set[str] = set()  # vars that hold dangerous values
        self._dangerous_aliases: dict[str, str] = {}  # var_name → original function
        self._import_aliases: dict[str, str] = {}  # alias → real module (e.g. sp → subprocess)

    def visit_Import(self, node: ast.Import) -> None:
        """Track import aliases: import subprocess as sp."""
        for alias in node.names:
            real_name = alias.name
            local_name = alias.asname or alias.name
            self._import_aliases[local_name] = real_name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from-imports: from os import system; from subprocess import run as r."""
        module = node.module or ""
        for alias in node.names:
            real_name = f"{module}.{alias.name}" if module else alias.name
            local_name = alias.asname or alias.name
            self._import_aliases[local_name] = real_name
            # Direct import of dangerous function: from os import system
            if real_name in _PYTHON_DANGEROUS_ATTRS or alias.name in _PYTHON_DANGEROUS_CALLS:
                self._tainted_vars.add(local_name)
                self._dangerous_aliases[local_name] = real_name
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments of dangerous functions to variables."""
        value = node.value

        # x = eval / x = exec / x = __import__
        if isinstance(value, ast.Name) and value.id in _PYTHON_DANGEROUS_CALLS:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted_vars.add(target.id)
                    self._dangerous_aliases[target.id] = value.id
                    self.findings.append(
                        ASTFinding(
                            check="py_dangerous_alias",
                            severity="critical",
                            detail=f"Dangerous function aliased: {target.id} = {value.id}",
                            file=self.filename,
                            line=node.lineno,
                        )
                    )

        # x = os.environ
        if isinstance(value, ast.Attribute):
            full_name = self._get_attr_str(value)
            if full_name in _PYTHON_DANGEROUS_ATTRS or full_name == "os.environ":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._tainted_vars.add(target.id)

        # x = getattr(__builtins__, 'exec')
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "getattr":
            if len(value.args) >= 2 and isinstance(value.args[1], ast.Constant):
                attr_name = str(value.args[1].value)
                if attr_name in _PYTHON_DANGEROUS_CALLS:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self._tainted_vars.add(target.id)
                            self.findings.append(
                                ASTFinding(
                                    check="py_getattr_dangerous",
                                    severity="critical",
                                    detail=f"getattr used to access '{attr_name}' — assigned to {target.id}",
                                    file=self.filename,
                                    line=node.lineno,
                                )
                            )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect calls to tainted/aliased dangerous functions."""
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = self._get_attr_str(node.func)

        # Call to tainted variable (aliased eval/exec)
        if func_name and func_name in self._tainted_vars:
            original = self._dangerous_aliases.get(func_name, "unknown")
            self.findings.append(
                ASTFinding(
                    check="py_tainted_call",
                    severity="critical",
                    detail=f"Call to aliased dangerous function: {func_name}() (was {original})",
                    file=self.filename,
                    line=node.lineno,
                )
            )

        # open() with credential file paths in arguments
        if func_name in ("open", "builtins.open"):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if any(p in arg.value for p in _PYTHON_SENSITIVE_PATHS):
                        self.findings.append(
                            ASTFinding(
                                check="py_credential_file",
                                severity="high",
                                detail=f"Credential file access: open('{arg.value}')",
                                file=self.filename,
                                line=node.lineno,
                            )
                        )

        self.generic_visit(node)

    def _get_attr_str(self, node: ast.Attribute) -> str:
        """Resolve dotted attribute access to string, resolving import aliases.

        e.g. if `import subprocess as sp`, then `sp.run` → 'subprocess.run'
        """
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            # Resolve alias: sp → subprocess
            real_name = self._import_aliases.get(current.id, current.id)
            parts.append(real_name)
        return ".".join(reversed(parts))
