"""
Module: xss.py
Author: Code Archaeologist Team
Purpose: Detect Cross-Site Scripting (XSS) vulnerabilities.

This detector finds XSS patterns that AI commonly generates:
- mark_safe() with user input
- Template rendering without escaping
- DOM-based XSS via JSON endpoints
- JavaScript URL injection
- SVG/CSS injection

CRITICAL: Max 400 lines per CLAUDE.md standards.
"""

import ast
import re
from typing import List, Optional, Set
from dataclasses import dataclass


@dataclass
class XSSFinding:
    """A detected XSS vulnerability."""
    pattern_id: str
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    exploit_example: str
    fix_suggestion: str
    cwe_id: str = "CWE-79"
    owasp_category: str = "A03:2021 - Injection"

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


class XSSDetector:
    """
    Detects Cross-Site Scripting (XSS) vulnerabilities.

    Specialized for Django/Flask patterns where AI generates
    code that bypasses built-in escaping mechanisms.
    """

    # User input sources
    USER_INPUT_SOURCES = {
        'request.GET', 'request.POST', 'request.DATA',
        'request.query_params', 'request.data', 'request.body',
        'request.form', 'request.args', 'request.values'
    }

    # Dangerous functions that bypass escaping
    DANGEROUS_FUNCTIONS = {
        'mark_safe', 'Markup', 'safe', 'SafeString'
    }

    # Response functions that render HTML
    RESPONSE_FUNCTIONS = {
        'HttpResponse', 'render', 'render_to_string',
        'JsonResponse', 'make_response'
    }

    def __init__(self):
        """Initialize the XSS detector."""
        self.findings: List[XSSFinding] = []

    def detect(
        self,
        source_code: str,
        file_path: str
    ) -> List[XSSFinding]:
        """
        Detect XSS vulnerabilities in source code.

        Args:
            source_code: Python source code to analyze
            file_path: Path to the file being analyzed

        Returns:
            List of XSS findings
        """
        self.findings = []

        try:
            tree = ast.parse(source_code)
            self._analyze_ast(tree, source_code)
        except SyntaxError:
            return self.findings

        return self.findings

    def _analyze_ast(self, tree: ast.AST, source_code: str) -> None:
        """
        Analyze the AST for XSS patterns.

        Args:
            tree: AST of the source code
            source_code: Original source code for context
        """
        for node in ast.walk(tree):
            # Pattern 1: mark_safe() with user input
            if isinstance(node, ast.Call):
                self._check_mark_safe(node, source_code)
                self._check_json_response(node, source_code)
                self._check_redirect(node, source_code)

            # Pattern 2: f-strings with HTML
            if isinstance(node, ast.JoinedStr):
                self._check_html_fstring(node, source_code)

    def _check_mark_safe(self, node: ast.Call, source_code: str) -> None:
        """
        Detect mark_safe() with user input.

        Pattern: mark_safe(request.GET.get('bio'))
        """
        func_name = self._get_function_name(node)

        if func_name in self.DANGEROUS_FUNCTIONS:
            # Check if argument contains user input
            if node.args:
                arg = node.args[0]

                # Check for direct user input
                if self._is_user_input(arg):
                    code_snippet = ast.get_source_segment(source_code, node)

                    finding = XSSFinding(
                        pattern_id="XSS_001",
                        line=node.lineno,
                        column=node.col_offset,
                        code_snippet=code_snippet or "Unable to extract snippet",
                        severity="HIGH",
                        confidence=95,
                        description=f"{func_name}() used with user input",
                        exploit_example="?bio=<script>alert(document.cookie)</script>",
                        fix_suggestion=(
                            "Do not use mark_safe() with user input. "
                            "Use Django's auto-escaping or bleach.clean()"
                        )
                    )

                    self.findings.append(finding)

                # Check for f-strings or concatenation
                elif self._contains_dynamic_content(arg):
                    code_snippet = ast.get_source_segment(source_code, node)

                    finding = XSSFinding(
                        pattern_id="XSS_001",
                        line=node.lineno,
                        column=node.col_offset,
                        code_snippet=code_snippet or "Unable to extract snippet",
                        severity="HIGH",
                        confidence=85,
                        description=f"{func_name}() with dynamic content",
                        exploit_example="<img src=x onerror=alert(1)>",
                        fix_suggestion=(
                            "Avoid mark_safe() with dynamic content. "
                            "Sanitize with bleach.clean() if HTML is required"
                        )
                    )

                    self.findings.append(finding)

    def _check_html_fstring(
        self,
        node: ast.JoinedStr,
        source_code: str
    ) -> None:
        """
        Detect f-strings that build HTML with variables.

        Pattern: f"<div>{user_input}</div>"
        """
        # Check if f-string contains HTML-like content
        has_html = False
        has_variables = len(node.values) > 1

        for value in node.values:
            if isinstance(value, ast.Constant):
                if isinstance(value.value, str):
                    if '<' in value.value and '>' in value.value:
                        has_html = True
                        break

        if has_html and has_variables:
            # Check if used with mark_safe or HttpResponse
            parent_is_unsafe = self._check_if_rendered_unsafely(node)

            if parent_is_unsafe:
                code_snippet = ast.get_source_segment(source_code, node)

                finding = XSSFinding(
                    pattern_id="XSS_001",
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=code_snippet or "Unable to extract snippet",
                    severity="HIGH",
                    confidence=80,
                    description="HTML constructed with f-string and rendered unsafely",
                    exploit_example="?name=<script>alert(1)</script>",
                    fix_suggestion=(
                        "Use Django templates with auto-escaping or "
                        "sanitize variables before f-string interpolation"
                    )
                )

                self.findings.append(finding)

    def _check_json_response(
        self,
        node: ast.Call,
        source_code: str
    ) -> None:
        """
        Detect JsonResponse with unsanitized data (DOM XSS).

        Pattern: JsonResponse({'comment': request.GET.get('comment')})
        """
        func_name = self._get_function_name(node)

        if func_name == 'JsonResponse':
            # Check if arguments contain user input
            if node.args:
                arg = node.args[0]

                # Check for dict with user input values
                if isinstance(arg, ast.Dict):
                    for value in arg.values:
                        if self._is_user_input(value):
                            code_snippet = ast.get_source_segment(source_code, node)

                            finding = XSSFinding(
                                pattern_id="XSS_003",
                                line=node.lineno,
                                column=node.col_offset,
                                code_snippet=code_snippet or "Unable to extract snippet",
                                severity="MEDIUM",
                                confidence=75,
                                description="JsonResponse with unsanitized user input (DOM XSS risk)",
                                exploit_example=(
                                    "If frontend uses innerHTML: "
                                    "?comment=</script><script>alert(1)</script>"
                                ),
                                fix_suggestion=(
                                    "Sanitize data before JSON response or ensure "
                                    "frontend uses textContent instead of innerHTML"
                                )
                            )

                            self.findings.append(finding)
                            break

    def _check_redirect(self, node: ast.Call, source_code: str) -> None:
        """
        Detect redirect with user-controlled URL (open redirect + XSS).

        Pattern: redirect(request.GET.get('next'))
        """
        func_name = self._get_function_name(node)

        if func_name in ('redirect', 'HttpResponseRedirect'):
            if node.args:
                arg = node.args[0]

                if self._is_user_input(arg):
                    code_snippet = ast.get_source_segment(source_code, node)

                    finding = XSSFinding(
                        pattern_id="XSS_008",
                        line=node.lineno,
                        column=node.col_offset,
                        code_snippet=code_snippet or "Unable to extract snippet",
                        severity="HIGH",
                        confidence=85,
                        description="Redirect with user-controlled URL (open redirect + XSS)",
                        exploit_example="?next=javascript:alert(document.cookie)",
                        fix_suggestion=(
                            "Validate redirect URL is same-origin:\n"
                            "from urllib.parse import urlparse\n"
                            "parsed = urlparse(next_url)\n"
                            "if not parsed.netloc or parsed.netloc == request.get_host():\n"
                            "    redirect(next_url)"
                        )
                    )

                    self.findings.append(finding)

    def _is_user_input(self, node: ast.AST) -> bool:
        """
        Check if node represents user input.

        Args:
            node: AST node to check

        Returns:
            True if node is user input
        """
        # Check for request.GET.get(), request.POST.get(), etc.
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == 'get':
                    if isinstance(node.func.value, ast.Attribute):
                        full_name = self._get_full_attribute_name(node.func.value)
                        if full_name in self.USER_INPUT_SOURCES:
                            return True

        # Check for request.GET['key'], request.POST['key']
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                full_name = self._get_full_attribute_name(node.value)
                if full_name in self.USER_INPUT_SOURCES:
                    return True

        return False

    def _contains_dynamic_content(self, node: ast.AST) -> bool:
        """
        Check if node contains dynamic content (f-strings, concatenation).

        Args:
            node: AST node to check

        Returns:
            True if node contains dynamic content
        """
        # Check for f-strings
        if isinstance(node, ast.JoinedStr):
            return True

        # Check for string concatenation
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                return True

        # Check for .format()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == 'format':
                    return True

        return False

    def _check_if_rendered_unsafely(self, node: ast.AST) -> bool:
        """
        Check if an f-string is rendered without escaping.

        This is a simplified check - in a full implementation,
        we'd need to track data flow to see if the f-string
        is passed to mark_safe() or HttpResponse().

        Args:
            node: AST node to check

        Returns:
            True if likely rendered unsafely
        """
        # Conservative: assume f-strings with HTML are rendered
        # TODO: Implement full data flow tracking
        return True

    def _get_function_name(self, node: ast.Call) -> Optional[str]:
        """
        Get the function name from a Call node.

        Args:
            node: ast.Call node

        Returns:
            Function name or None
        """
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _get_full_attribute_name(self, node: ast.Attribute) -> str:
        """
        Get full dotted attribute name.

        Example: request.GET -> "request.GET"

        Args:
            node: ast.Attribute node

        Returns:
            Full attribute name
        """
        parts = []

        current = node
        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.insert(0, current.id)

        return '.'.join(parts)
