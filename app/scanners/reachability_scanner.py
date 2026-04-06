"""Reachability analysis scanner.

Builds a simplified call graph from package entry points and determines
whether suspicious code patterns are reachable. Unreachable threats get
reduced severity; directly reachable threats get boosted confidence.

Supports Python (.py) and JavaScript (.js) via AST parsing.
"""

import ast
from pathlib import Path

from pydantic import BaseModel

from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

# Dangerous function calls to track reachability for
_PY_DANGEROUS = {"eval", "exec", "compile", "__import__", "os.system", "subprocess.run", "subprocess.Popen"}
_JS_DANGEROUS = {"eval", "Function", "child_process.exec", "child_process.spawn"}


class FunctionNode(BaseModel):
    """A function definition in the call graph."""

    name: str
    file: str
    line: int
    calls: list[str] = []
    is_entry_point: bool = False
    has_dangerous_calls: list[str] = []


class ReachabilityResult(BaseModel):
    """Result of reachability analysis for a single file."""

    file: str
    total_functions: int
    entry_points: list[str]
    reachable_dangerous: list[dict] = []
    unreachable_dangerous: list[dict] = []


class ReachabilityScanner:
    """Analyze whether suspicious code is reachable from package entry points."""

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        all_results: list[ReachabilityResult] = []

        for path in artifacts:
            if not path.exists() or not path.is_file():
                continue
            if path.stat().st_size > 512 * 1024:
                continue
            if path.name in ("metadata.yaml", "package.json", "checksums.yaml.gz"):
                continue

            try:
                content = path.read_text(errors="replace")
            except OSError:
                continue

            result = None
            if path.suffix == ".py" or path.name in ("setup.py", "setup.cfg"):
                result = self._analyze_python(content, path.name)
            elif path.suffix in (".js", ".mjs", ".cjs"):
                result = self._analyze_javascript(content, path.name)

            if result and (result.reachable_dangerous or result.unreachable_dangerous):
                all_results.append(result)

        if not all_results:
            return ScanResult(
                scanner_name="reachability",
                verdict="pass",
                confidence=0.7,
                details="No dangerous code patterns found in reachability analysis",
            )

        total_reachable = sum(len(r.reachable_dangerous) for r in all_results)
        total_unreachable = sum(len(r.unreachable_dangerous) for r in all_results)

        if total_reachable > 0:
            confidence = min(0.95, 0.6 + total_reachable * 0.1)
            details_parts = []
            for r in all_results:
                for d in r.reachable_dangerous:
                    details_parts.append(f"{d['call']} in {d['function']} ({r.file})")
            details = f"Reachable dangerous code: {'; '.join(details_parts[:5])}"
            if total_unreachable > 0:
                details += f" (+{total_unreachable} unreachable)"
            return ScanResult(
                scanner_name="reachability",
                verdict="warn",
                confidence=round(confidence, 2),
                details=details,
                metadata={
                    "reachable_count": total_reachable,
                    "unreachable_count": total_unreachable,
                    "results": [r.model_dump() for r in all_results[:5]],
                },
            )

        # Only unreachable dangerous code
        return ScanResult(
            scanner_name="reachability",
            verdict="pass",
            confidence=0.8,
            details=f"Dangerous code found but unreachable from entry points ({total_unreachable} pattern(s))",
            metadata={
                "reachable_count": 0,
                "unreachable_count": total_unreachable,
                "results": [r.model_dump() for r in all_results[:5]],
            },
        )

    def _analyze_python(self, content: str, filename: str) -> ReachabilityResult | None:
        """Build call graph and check reachability for Python code."""
        try:
            tree = ast.parse(content, filename=filename)
        except SyntaxError:
            return None

        functions: dict[str, FunctionNode] = {}
        module_level_calls: list[str] = []
        module_level_dangerous: list[str] = []

        # First pass: collect function definitions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func = FunctionNode(name=node.name, file=filename, line=node.lineno)

                # Determine if it's an entry point
                is_entry = self._is_python_entry_point(node, filename)
                func.is_entry_point = is_entry

                # Collect calls within this function
                calls, dangerous = self._extract_python_calls(node)
                func.calls = calls
                func.has_dangerous_calls = dangerous

                functions[node.name] = func

        # Module-level code analysis (always reachable)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            # This is module-level code
            for child in ast.walk(node):
                call_name = self._get_python_call_name(child)
                if call_name:
                    module_level_calls.append(call_name)
                    if call_name in _PY_DANGEROUS or any(call_name.endswith(f".{d}") for d in _PY_DANGEROUS):
                        module_level_dangerous.append(call_name)

        # Build reachable set
        entry_points: list[str] = ["<module>"]
        reachable: set[str] = set()
        for name, func in functions.items():
            if func.is_entry_point or name in module_level_calls:
                entry_points.append(name)
                reachable.add(name)

        # Propagate reachability
        changed = True
        while changed:
            changed = False
            for name in list(reachable):
                func = functions.get(name)
                if not func:
                    continue
                for callee in func.calls:
                    if callee in functions and callee not in reachable:
                        reachable.add(callee)
                        changed = True

        # Classify dangerous calls
        reachable_dangerous: list[dict] = []
        unreachable_dangerous: list[dict] = []

        # Module-level dangerous calls are always reachable
        for call in module_level_dangerous:
            reachable_dangerous.append({"call": call, "function": "<module>", "line": 0})

        for name, func in functions.items():
            for dangerous_call in func.has_dangerous_calls:
                entry = {"call": dangerous_call, "function": name, "line": func.line}
                if name in reachable:
                    reachable_dangerous.append(entry)
                else:
                    unreachable_dangerous.append(entry)

        if not reachable_dangerous and not unreachable_dangerous:
            return None

        return ReachabilityResult(
            file=filename,
            total_functions=len(functions),
            entry_points=entry_points,
            reachable_dangerous=reachable_dangerous,
            unreachable_dangerous=unreachable_dangerous,
        )

    def _analyze_javascript(self, content: str, filename: str) -> ReachabilityResult | None:
        """Build call graph and check reachability for JavaScript code."""
        try:
            from pyjsparser import parse

            tree = parse(content)
        except Exception:
            return None

        functions: dict[str, FunctionNode] = {}
        module_level_dangerous: list[str] = []
        exported_names: set[str] = set()

        # Walk top-level statements
        body = tree.get("body", [])
        for stmt in body:
            self._collect_js_functions(stmt, filename, functions, module_level_dangerous, exported_names)

        # Mark entry points (exported functions + top-level)
        entry_points: list[str] = ["<module>"]
        reachable: set[str] = set()
        for name, func in functions.items():
            if name in exported_names:
                func.is_entry_point = True
                entry_points.append(name)
                reachable.add(name)

        # Propagate
        changed = True
        while changed:
            changed = False
            for name in list(reachable):
                func = functions.get(name)
                if not func:
                    continue
                for callee in func.calls:
                    if callee in functions and callee not in reachable:
                        reachable.add(callee)
                        changed = True

        reachable_dangerous: list[dict] = []
        unreachable_dangerous: list[dict] = []

        for call in module_level_dangerous:
            reachable_dangerous.append({"call": call, "function": "<module>", "line": 0})

        for name, func in functions.items():
            for dc in func.has_dangerous_calls:
                entry = {"call": dc, "function": name, "line": func.line}
                if name in reachable:
                    reachable_dangerous.append(entry)
                else:
                    unreachable_dangerous.append(entry)

        if not reachable_dangerous and not unreachable_dangerous:
            return None

        return ReachabilityResult(
            file=filename,
            total_functions=len(functions),
            entry_points=entry_points,
            reachable_dangerous=reachable_dangerous,
            unreachable_dangerous=unreachable_dangerous,
        )

    # -- Python helpers --

    @staticmethod
    def _is_python_entry_point(node: ast.FunctionDef | ast.AsyncFunctionDef, filename: str) -> bool:
        """Determine if a Python function is an entry point."""
        # setup.py functions are entry points
        if filename in ("setup.py", "__init__.py"):
            return True
        # Decorated with common entry point decorators
        for dec in node.decorator_list:
            dec_name = ""
            if isinstance(dec, ast.Name):
                dec_name = dec.id
            elif isinstance(dec, ast.Attribute):
                dec_name = dec.attr
            if dec_name in ("staticmethod", "classmethod", "property", "app", "cli", "command"):
                return True
        # __init__, __call__, main
        if node.name in ("__init__", "__call__", "main", "__enter__", "__exit__"):
            return True
        return False

    def _extract_python_calls(self, node: ast.AST) -> tuple[list[str], list[str]]:
        """Extract function calls and dangerous calls from a Python AST node."""
        calls: list[str] = []
        dangerous: list[str] = []
        for child in ast.walk(node):
            call_name = self._get_python_call_name(child)
            if call_name:
                calls.append(call_name)
                if call_name in _PY_DANGEROUS or any(d in call_name for d in _PY_DANGEROUS):
                    dangerous.append(call_name)
        return calls, dangerous

    @staticmethod
    def _get_python_call_name(node: ast.AST) -> str | None:
        """Get the function name from a Call node."""
        if not isinstance(node, ast.Call):
            return None
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    # -- JavaScript helpers --

    def _collect_js_functions(
        self,
        node: dict,
        filename: str,
        functions: dict[str, FunctionNode],
        module_dangerous: list[str],
        exported: set[str],
    ) -> None:
        """Collect function definitions and exports from JS AST."""
        if not isinstance(node, dict):
            return

        node_type = node.get("type", "")

        # Function declarations
        if node_type == "FunctionDeclaration":
            name = node.get("id", {}).get("name", "")
            if name:
                calls, dangerous = self._extract_js_calls(node)
                functions[name] = FunctionNode(
                    name=name, file=filename, line=0, calls=calls, has_dangerous_calls=dangerous
                )

        # module.exports = ... or exports.xxx = ...
        elif node_type == "ExpressionStatement":
            expr = node.get("expression", {})
            if expr.get("type") == "AssignmentExpression":
                left = expr.get("left", {})
                # module.exports.xxx = function
                if left.get("type") == "MemberExpression":
                    obj = left.get("object", {})
                    if isinstance(obj, dict):
                        obj_name = obj.get("name", "")
                        if obj_name == "exports":
                            prop = left.get("property", {}).get("name", "")
                            if prop:
                                exported.add(prop)
                        elif obj.get("type") == "MemberExpression":
                            inner_obj = obj.get("object", {}).get("name", "")
                            inner_prop = obj.get("property", {}).get("name", "")
                            if inner_obj == "module" and inner_prop == "exports":
                                prop = left.get("property", {}).get("name", "")
                                if prop:
                                    exported.add(prop)

        # Variable declarations with function expressions
        elif node_type == "VariableDeclaration":
            for decl in node.get("declarations", []):
                name = decl.get("id", {}).get("name", "")
                init = decl.get("init", {})
                if isinstance(init, dict) and init.get("type") in (
                    "FunctionExpression",
                    "ArrowFunctionExpression",
                ):
                    if name:
                        calls, dangerous = self._extract_js_calls(init)
                        functions[name] = FunctionNode(
                            name=name, file=filename, line=0, calls=calls, has_dangerous_calls=dangerous
                        )

        # Module-level calls (top-level expressions that aren't function defs)
        if node_type == "ExpressionStatement":
            calls, dangerous = self._extract_js_calls(node)
            module_dangerous.extend(dangerous)

    def _extract_js_calls(self, node: dict) -> tuple[list[str], list[str]]:
        """Extract function calls from a JS AST node."""
        calls: list[str] = []
        dangerous: list[str] = []
        self._walk_js_for_calls(node, calls, dangerous)
        return calls, dangerous

    def _walk_js_for_calls(self, node: dict, calls: list[str], dangerous: list[str]) -> None:
        if not isinstance(node, dict):
            return

        if node.get("type") == "CallExpression":
            callee = node.get("callee", {})
            name = self._get_js_callee_name(callee)
            if name:
                calls.append(name)
                if name in _JS_DANGEROUS or any(d in name for d in _JS_DANGEROUS):
                    dangerous.append(name)

        for value in node.values():
            if isinstance(value, dict):
                self._walk_js_for_calls(value, calls, dangerous)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._walk_js_for_calls(item, calls, dangerous)

    @staticmethod
    def _get_js_callee_name(callee: dict) -> str | None:
        if not isinstance(callee, dict):
            return None
        if callee.get("type") == "Identifier":
            return callee.get("name")
        if callee.get("type") == "MemberExpression":
            obj = callee.get("object", {})
            prop = callee.get("property", {})
            obj_name = obj.get("name", "")
            prop_name = prop.get("name", "")
            if obj_name and prop_name:
                return f"{obj_name}.{prop_name}"
        return None
