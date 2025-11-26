"""
Module: auth_bypass.py
Author: Code Archaeologist Team
Purpose: Detect authentication and authorization bypass vulnerabilities.

This detector finds auth issues that AI commonly generates:
- Missing @login_required decorator
- Missing permission checks
- IDOR (Insecure Direct Object Reference)
- @csrf_exempt without authentication
- Weak session management

CRITICAL: Max 400 lines per CLAUDE.md standards.
"""

import ast
from typing import List, Optional, Set
from dataclasses import dataclass


@dataclass
class AuthBypassFinding:
    """A detected authentication bypass vulnerability."""
    pattern_id: str
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    exploit_example: str
    fix_suggestion: str
    cwe_id: str = "CWE-862"
    owasp_category: str = "A01:2021 - Broken Access Control"

    def to_dict(self) -> dict:
        """Convert to dictionary format for scanner compatibility."""
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'exploit_example': self.exploit_example,
            'fix': self.fix_suggestion,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category
        }


class AuthBypassDetector:
    """
    Detects authentication and authorization bypass vulnerabilities.

    Specialized for Django/Flask patterns where AI forgets to add
    security decorators or permission checks.
    """

    # Decorators that indicate authentication
    AUTH_DECORATORS = {
        'login_required', 'require_authentication', 'authenticated',
        'permission_required', 'user_passes_test'
    }

    # Dangerous decorators
    DANGEROUS_DECORATORS = {
        'csrf_exempt'
    }

    # ORM methods that query objects
    QUERY_METHODS = {
        'get', 'filter', 'all', 'first'
    }

    # Sensitive operations that need permission checks
    SENSITIVE_OPERATIONS = {
        'delete', 'update', 'save', 'create'
    }

    def __init__(self):
        """Initialize the auth bypass detector."""
        self.findings: List[AuthBypassFinding] = []

    def detect(
        self,
        source_code: str,
        file_path: str
    ) -> List[AuthBypassFinding]:
        """
        Detect authentication bypass vulnerabilities in source code.

        Args:
            source_code: Python source code to analyze
            file_path: Path to the file being analyzed

        Returns:
            List of auth bypass findings
        """
        self.findings = []

        # Skip scripts, migrations, and non-production code
        skip_patterns = ['scripts/', 'migrations/', 'fixtures/', 'management/commands/',
                        'tests/', 'test_', 'conftest.py', 'check_', 'verify_', 'migrate_']
        if any(pattern in file_path for pattern in skip_patterns):
            return self.findings

        try:
            tree = ast.parse(source_code)
            self._analyze_ast(tree, source_code)
        except SyntaxError:
            return self.findings

        return self.findings

    def _analyze_ast(self, tree: ast.AST, source_code: str) -> None:
        """
        Analyze the AST for auth bypass patterns.

        Args:
            tree: AST of the source code
            source_code: Original source code for context
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self._analyze_function(node, source_code)

    def _analyze_function(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Analyze a function for authentication issues.

        Args:
            func_node: Function definition AST node
            source_code: Source code for context
        """
        # Pattern 1: Missing @login_required on views
        if self._is_view_function(func_node):
            if not self._has_auth_decorator(func_node):
                self._check_if_needs_auth(func_node, source_code)

        # Pattern 2: @csrf_exempt without authentication
        if self._has_csrf_exempt(func_node):
            if not self._has_auth_decorator(func_node):
                code_snippet = ast.get_source_segment(source_code, func_node)

                finding = AuthBypassFinding(
                    pattern_id="AUTH_BYPASS_002",
                    line=func_node.lineno,
                    column=func_node.col_offset,
                    code_snippet=self._truncate(code_snippet),
                    severity="CRITICAL",
                    confidence=95,
                    description="@csrf_exempt without authentication check",
                    exploit_example="POST request without authentication bypasses CSRF and auth",
                    fix_suggestion=(
                        "Add @login_required decorator:\n"
                        "@login_required\n"
                        f"@csrf_exempt\ndef {func_node.name}(request): ..."
                    )
                )

                self.findings.append(finding)

        # Pattern 3: IDOR - object access without ownership check
        self._check_idor(func_node, source_code)

    def _is_view_function(self, func_node: ast.FunctionDef) -> bool:
        """
        Check if function is a Django/Flask view.

        Args:
            func_node: Function definition node

        Returns:
            True if function appears to be a view
        """
        # Check if first parameter is 'request'
        if func_node.args.args:
            first_param = func_node.args.args[0]
            if isinstance(first_param, ast.arg):
                if first_param.arg == 'request':
                    return True

        # Check for HttpResponse return
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return):
                if node.value:
                    if isinstance(node.value, ast.Call):
                        func_name = self._get_function_name(node.value)
                        if func_name in ('HttpResponse', 'JsonResponse', 'render', 'redirect'):
                            return True

        return False

    def _has_auth_decorator(self, func_node: ast.FunctionDef) -> bool:
        """
        Check if function has authentication decorator.

        Args:
            func_node: Function definition node

        Returns:
            True if function has auth decorator
        """
        for decorator in func_node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            if decorator_name in self.AUTH_DECORATORS:
                return True

        return False

    def _has_csrf_exempt(self, func_node: ast.FunctionDef) -> bool:
        """Check if function has @csrf_exempt decorator."""
        for decorator in func_node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            if decorator_name == 'csrf_exempt':
                return True
        return False

    def _check_if_needs_auth(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Check if a view function needs authentication.

        Args:
            func_node: Function definition node
            source_code: Source code for context
        """
        # Check if function accesses user data or performs sensitive operations
        needs_auth = False

        for node in ast.walk(func_node):
            # Accessing request.user suggests auth is needed
            if isinstance(node, ast.Attribute):
                if self._get_full_attribute_name(node) == 'request.user':
                    needs_auth = True
                    break

            # Database queries suggest auth might be needed
            if isinstance(node, ast.Call):
                if self._is_database_operation(node):
                    needs_auth = True
                    break

        if needs_auth:
            code_snippet = ast.get_source_segment(source_code, func_node)

            finding = AuthBypassFinding(
                pattern_id="AUTH_BYPASS_001",
                line=func_node.lineno,
                column=func_node.col_offset,
                code_snippet=self._truncate(code_snippet),
                severity="CRITICAL",
                confidence=85,
                description=f"View function '{func_node.name}' missing @login_required decorator",
                exploit_example="Direct access to URL without authentication",
                fix_suggestion=(
                    "Add authentication decorator:\n"
                    "@login_required\n"
                    f"def {func_node.name}(request): ..."
                )
            )

            self.findings.append(finding)

    def _check_idor(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Check for IDOR (Insecure Direct Object Reference) vulnerabilities.

        Pattern:
            document = Document.objects.get(id=doc_id)
            # Missing: if document.owner != request.user: return Forbidden

        Args:
            func_node: Function definition node
            source_code: Source code for context
        """
        # ONLY check view functions (has 'request' parameter)
        if not self._is_view_function(func_node):
            return

        # Find .get() calls on Django ORM (objects.get)
        get_calls = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'get':
                        # Must be .objects.get() pattern
                        if isinstance(node.func.value, ast.Attribute):
                            if node.func.value.attr == 'objects':
                                get_calls.append(node)

        for get_call in get_calls:
            # Skip if it's a safe model or context
            code_snippet = ast.get_source_segment(source_code, get_call) or ""

            # Safe models that don't need ownership checks
            safe_models = ['Config', 'Setting', 'Country', 'Language', 'Category',
                          'Tag', 'Status', 'Type', 'Choice', 'Option']
            if any(model in code_snippet for model in safe_models):
                continue

            # Check if there's an ownership check after the .get()
            has_ownership_check = self._has_ownership_check_after(
                func_node,
                get_call
            )

            if not has_ownership_check:
                finding = AuthBypassFinding(
                    pattern_id="AUTH_BYPASS_004",
                    line=get_call.lineno,
                    column=get_call.col_offset,
                    code_snippet=code_snippet[:100] or "objects.get(...)",
                    severity="HIGH",  # Lowered from CRITICAL
                    confidence=60,  # Lowered from 75 - many false positives
                    description="Potential IDOR - object access without ownership check",
                    exploit_example="Change ID parameter to access other users' data",
                    fix_suggestion=(
                        "Add ownership check:\n"
                        "obj = Model.objects.get(id=obj_id)\n"
                        "if obj.owner != request.user:\n"
                        "    return HttpResponseForbidden()"
                    )
                )

                self.findings.append(finding)

    def _has_ownership_check_after(
        self,
        func_node: ast.FunctionDef,
        get_call: ast.Call
    ) -> bool:
        """
        Check if there's an ownership check after a .get() call.

        This is a simplified heuristic check.

        Args:
            func_node: Function node
            get_call: The .get() call to check

        Returns:
            True if ownership check found
        """
        # Look for comparisons with request.user
        for node in ast.walk(func_node):
            if isinstance(node, ast.Compare):
                # Check if comparing something with request.user
                if self._compares_with_request_user(node):
                    return True

        return False

    def _compares_with_request_user(self, node: ast.Compare) -> bool:
        """Check if comparison involves request.user."""
        # Check left side
        if isinstance(node.left, ast.Attribute):
            if 'request.user' in self._get_full_attribute_name(node.left):
                return True

        # Check comparators
        for comparator in node.comparators:
            if isinstance(comparator, ast.Attribute):
                if 'request.user' in self._get_full_attribute_name(comparator):
                    return True

        return False

    def _is_database_operation(self, node: ast.Call) -> bool:
        """Check if call is a database operation."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in self.QUERY_METHODS or \
               node.func.attr in self.SENSITIVE_OPERATIONS:
                return True
        return False

    def _get_decorator_name(self, decorator: ast.AST) -> Optional[str]:
        """Get decorator name from AST node."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return decorator.attr
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name):
                return decorator.func.id
            elif isinstance(decorator.func, ast.Attribute):
                return decorator.func.attr
        return None

    def _get_function_name(self, node: ast.Call) -> Optional[str]:
        """Get function name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _get_full_attribute_name(self, node: ast.Attribute) -> str:
        """Get full dotted attribute name."""
        parts = []
        current = node

        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.insert(0, current.id)

        return '.'.join(parts)

    def _truncate(self, code: Optional[str], max_len: int = 200) -> str:
        """Truncate code snippet to max length."""
        if not code:
            return "Unable to extract snippet"

        if len(code) > max_len:
            return code[:max_len] + "..."

        return code
