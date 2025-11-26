"""
Cross-Site Request Forgery (CSRF) Detector (CWE-352)

Detects missing CSRF protection on state-changing operations, allowing
attackers to perform unauthorized actions on behalf of authenticated users.

OWASP: A01:2021 - Broken Access Control
Research: AI-generated code frequently omits CSRF protection
Training Era: 2010-2020 (StackOverflow examples rarely showed CSRF protection)

Attack Vector:
    Attacker site: <form action="https://victim.com/transfer" method="POST">
                   <input name="amount" value="10000">
                   <input name="to" value="attacker">
    User visits attacker site while logged into victim.com
    Result: Unauthorized money transfer

AI Training Paradox:
    StackOverflow (2010-2015) focused on "make it work" not security
    "How to create POST endpoint?" → No mention of CSRF protection
    AI learned: "Just handle POST requests, no token needed"
    Reality: ALL state-changing operations need CSRF protection
"""

import ast
import re
from typing import List, Dict, Set
from dataclasses import dataclass

try:
    from analysis_engine.research.academic_validation import (
        get_cwe_research,
        explain_why_ai_generates
    )
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False


@dataclass
class CSRFFinding:
    """A detected CSRF vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    endpoint: str
    http_method: str
    cwe_id: str = "CWE-352"
    owasp_category: str = "A01:2021 - Broken Access Control"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'endpoint': self.endpoint,
            'http_method': self.http_method,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2010-2020'
            result['why_ai_generates'] = explain_why_ai_generates('CWE-352')

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:
```python
# DJANGO VULNERABLE:
from django.views import View

class TransferMoneyView(View):
    def post(self, request):  # Missing CSRF protection!
        amount = request.POST.get('amount')
        to_account = request.POST.get('to')
        transfer_money(request.user, to_account, amount)
        return JsonResponse({'status': 'success'})

# DJANGO SAFE:
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator

@method_decorator(csrf_protect, name='dispatch')
class TransferMoneyView(View):
    def post(self, request):
        # CSRF token automatically validated by Django middleware
        amount = request.POST.get('amount')
        to_account = request.POST.get('to')
        transfer_money(request.user, to_account, amount)
        return JsonResponse({'status': 'success'})

# Or for function-based views:
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def transfer_money_view(request):
    if request.method == 'POST':
        amount = request.POST.get('amount')
        to_account = request.POST.get('to')
        transfer_money(request.user, to_account, amount)
        return JsonResponse({'status': 'success'})

# NEVER USE @csrf_exempt UNLESS:
# 1. It's a public API with other authentication (API keys, OAuth)
# 2. You're implementing custom CSRF protection
# 3. It's a webhook from trusted external service
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # DANGEROUS - only for APIs with auth tokens
def webhook_handler(request):
    # Verify signature from external service
    if not verify_webhook_signature(request):
        return HttpResponseForbidden()
    # Process webhook
    return HttpResponse('OK')

# FLASK VULNERABLE:
from flask import Flask, request
app = Flask(__name__)

@app.route('/transfer', methods=['POST'])
def transfer():  # No CSRF protection!
    amount = request.form.get('amount')
    to_account = request.form.get('to')
    transfer_money(current_user, to_account, amount)
    return {'status': 'success'}

# FLASK SAFE:
from flask import Flask, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
def transfer():
    # CSRF token automatically validated
    amount = request.form.get('amount')
    to_account = request.form.get('to')
    transfer_money(current_user, to_account, amount)
    return {'status': 'success'}

# For AJAX requests, include token in headers:
# JavaScript:
fetch('/transfer', {
    method: 'POST',
    headers: {
        'X-CSRFToken': getCookie('csrftoken'),
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({amount: 100, to: 'account123'})
});

# FASTAPI SAFE:
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer

app = FastAPI()
security = HTTPBearer()

@app.post("/transfer")
async def transfer(
    amount: int,
    to_account: str,
    token: str = Depends(security)  # Requires bearer token
):
    # Token-based auth provides CSRF protection
    transfer_money(current_user, to_account, amount)
    return {"status": "success"}
```

PROTECTION RULES:
1. ALL POST/PUT/DELETE/PATCH require CSRF protection
2. GET requests should NEVER modify state (be idempotent)
3. Use framework's built-in CSRF protection (Django, Flask-WTF)
4. For APIs: use token-based auth (JWT, OAuth) instead of cookies
5. Set SameSite=Lax or Strict on cookies
6. Only use @csrf_exempt for public APIs with proper authentication

Reference: OWASP CSRF Prevention Cheat Sheet
"""


class CSRFDetector:
    """
    Detects missing CSRF protection on state-changing endpoints.

    Checks for:
    - POST/PUT/DELETE/PATCH without @csrf_protect
    - @csrf_exempt abuse on sensitive endpoints
    - Missing CSRF middleware configuration
    """

    # HTTP methods that change state (need CSRF protection)
    STATE_CHANGING_METHODS = {'POST', 'PUT', 'DELETE', 'PATCH'}

    # Sensitive operations that MUST have CSRF protection
    SENSITIVE_OPERATIONS = {
        'transfer', 'payment', 'delete', 'update', 'create',
        'login', 'logout', 'password', 'email', 'profile',
        'purchase', 'order', 'checkout', 'submit'
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_csrf(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_csrf(self, content: str, file_path: str) -> List[CSRFFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                finding = self._check_view_function(node, content)
                if finding:
                    findings.append(finding)

            if isinstance(node, ast.ClassDef):
                class_findings = self._check_view_class(node, content)
                findings.extend(class_findings)

        return findings

    def _check_view_function(self, node: ast.FunctionDef, content: str) -> CSRFFinding:
        """Check if function is a view without CSRF protection."""
        # Check if it's a view function (has request parameter)
        if not self._is_view_function(node):
            return None

        # Check if it handles state-changing methods
        handles_post = self._handles_state_changing_method(node, content)
        if not handles_post:
            return None

        # Check if it has CSRF protection
        has_csrf_protect = self._has_csrf_decorator(node, 'csrf_protect')
        has_csrf_exempt = self._has_csrf_decorator(node, 'csrf_exempt')

        # @csrf_exempt on sensitive operations is CRITICAL
        if has_csrf_exempt:
            if self._is_sensitive_operation(node.name, content):
                return CSRFFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node)[:200] or node.name,
                    severity='CRITICAL',
                    confidence=90,
                    description=f'@csrf_exempt on sensitive operation: {node.name}()',
                    endpoint=node.name,
                    http_method='POST/PUT/DELETE'
                )

        # Missing CSRF protection on POST/PUT/DELETE
        if not has_csrf_protect and not has_csrf_exempt:
            severity = 'CRITICAL' if self._is_sensitive_operation(node.name, content) else 'HIGH'
            confidence = 85

            return CSRFFinding(
                line=node.lineno,
                column=node.col_offset,
                code_snippet=ast.get_source_segment(content, node)[:200] or node.name,
                severity=severity,
                confidence=confidence,
                description=f'Missing CSRF protection on {node.name}()',
                endpoint=node.name,
                http_method='POST/PUT/DELETE'
            )

        return None

    def _check_view_class(self, node: ast.ClassDef, content: str) -> List[CSRFFinding]:
        """Check class-based views for CSRF protection."""
        findings = []

        # Check if it's a view class
        if not self._is_view_class(node):
            return findings

        # Check if class has CSRF decorator
        has_class_csrf = self._has_csrf_decorator(node, 'csrf_protect')

        # Check each method
        for method in node.body:
            if not isinstance(method, ast.FunctionDef):
                continue

            method_name = method.name.lower()

            # Check if it's a state-changing method
            if method_name not in ['post', 'put', 'delete', 'patch']:
                continue

            # Check if method has CSRF protection
            has_method_csrf = self._has_csrf_decorator(method, 'csrf_protect')

            if not has_class_csrf and not has_method_csrf:
                severity = 'CRITICAL' if self._is_sensitive_operation(node.name, content) else 'HIGH'

                findings.append(CSRFFinding(
                    line=method.lineno,
                    column=method.col_offset,
                    code_snippet=f"{node.name}.{method.name}",
                    severity=severity,
                    confidence=85,
                    description=f'Missing CSRF protection on {node.name}.{method.name}()',
                    endpoint=f'{node.name}.{method.name}',
                    http_method=method_name.upper()
                ))

        return findings

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[CSRFFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: @csrf_exempt on sensitive endpoints
        csrf_exempt_pattern = re.compile(
            r'@csrf_exempt.*\n.*def\s+(\w+)',
            re.IGNORECASE | re.MULTILINE
        )

        # Pattern 2: POST method without csrf_protect
        post_method_pattern = re.compile(
            r"methods?\s*=\s*\[?['\"]POST['\"]",
            re.IGNORECASE
        )

        # Check for @csrf_exempt usage
        for match in csrf_exempt_pattern.finditer(content):
            func_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1

            if any(sensitive in func_name.lower() for sensitive in self.SENSITIVE_OPERATIONS):
                findings.append(CSRFFinding(
                    line=line_num,
                    column=0,
                    code_snippet=match.group(0)[:100],
                    severity='CRITICAL',
                    confidence=90,
                    description=f'@csrf_exempt on sensitive endpoint: {func_name}',
                    endpoint=func_name,
                    http_method='POST'
                ))

        # Check for POST routes without CSRF protection
        for i, line in enumerate(lines, 1):
            if post_method_pattern.search(line):
                # Look for function definition nearby
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 10)
                context = '\n'.join(lines[context_start:context_end])

                # Check if CSRF protection is present
                has_protection = any(pattern in context.lower() for pattern in [
                    'csrf_protect', 'csrfprotect', 'csrf_token', 'x-csrftoken'
                ])

                if not has_protection:
                    findings.append(CSRFFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=75,
                        description='POST endpoint without CSRF protection',
                        endpoint='unknown',
                        http_method='POST'
                    ))

        return findings

    def _is_view_function(self, node: ast.FunctionDef) -> bool:
        """Check if function is likely a view."""
        # Check for 'request' parameter
        if node.args.args:
            if any(arg.arg == 'request' for arg in node.args.args):
                return True
        return False

    def _is_view_class(self, node: ast.ClassDef) -> bool:
        """Check if class is a view class."""
        # Check if inherits from View or APIView
        for base in node.bases:
            if isinstance(base, ast.Name):
                if 'View' in base.id or 'API' in base.id:
                    return True
        return False

    def _handles_state_changing_method(self, node: ast.FunctionDef, content: str) -> bool:
        """Check if function handles POST/PUT/DELETE."""
        # Look for request.method checks
        for child in ast.walk(node):
            if isinstance(child, ast.Compare):
                # Check for: request.method == 'POST'
                if isinstance(child.left, ast.Attribute):
                    if isinstance(child.left.value, ast.Name):
                        if child.left.value.id == 'request' and child.left.attr == 'method':
                            for comparator in child.comparators:
                                if isinstance(comparator, ast.Constant):
                                    if comparator.value in self.STATE_CHANGING_METHODS:
                                        return True

        # Check for @app.route decorators with methods=['POST']
        source = ast.get_source_segment(content, node)
        if source:
            if any(method in source for method in ['POST', 'PUT', 'DELETE', 'PATCH']):
                return True

        return False

    def _has_csrf_decorator(self, node, decorator_name: str) -> bool:
        """Check if node has CSRF decorator."""
        if not hasattr(node, 'decorator_list'):
            return False

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id == decorator_name:
                    return True
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    if decorator.func.id == decorator_name:
                        return True
                elif isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr == decorator_name:
                        return True

        return False

    def _is_sensitive_operation(self, name: str, content: str) -> bool:
        """Check if operation is sensitive."""
        name_lower = name.lower()
        return any(sensitive in name_lower for sensitive in self.SENSITIVE_OPERATIONS)
