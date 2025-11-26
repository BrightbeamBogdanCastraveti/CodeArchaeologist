"""
Email Header Injection Detector (CWE-93, CWE-80)

Detects email header injection vulnerabilities where user input is used
in email headers without sanitizing CRLF characters (\r\n).

OWASP: A03:2021 Injection
Zero Trust Reference: Section IV.B "Email Header Injection"
Research: "Zero Trust Email Ingestion Blueprint" (2025)

Attack Vector:
    User provides: "subject\nBcc: attacker@evil.com"
    Result: Email sent to attacker as Bcc

HBOSS Impact: CV forwarding feature vulnerable to:
- Spam relay
- Data exfiltration via Bcc
- Phishing campaigns
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class EmailInjectionFinding:
    """A detected email header injection vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    vulnerability_type: str
    cwe_id: str = "CWE-93"
    owasp_category: str = "A03:2021 - Injection"

    def to_dict(self) -> Dict:
        """Convert to dictionary format for scanner."""
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'vulnerability_type': self.vulnerability_type,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'hboss_impact': 'CV forwarding feature vulnerable to spam relay and data exfiltration',
            'fix': self._get_fix_example()
        }

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:
```python
def send_cv_email_secure(to_email, subject, candidate_name):
    # Layer 1: Remove ALL CRLF characters
    to_email = to_email.replace('\\r', '').replace('\\n', '')
    subject = subject.replace('\\r', '').replace('\\n', '')
    candidate_name = candidate_name.replace('\\r', '').replace('\\n', '')

    # Layer 2: Validate email format
    from email.utils import parseaddr
    name, addr = parseaddr(to_email)
    if not addr or '@' not in addr:
        raise ValueError("Invalid email address")

    # Layer 3: Use safe email library
    from django.core.mail import EmailMessage
    msg = EmailMessage(
        subject=subject,
        body=f"CV from {candidate_name}",
        from_email='noreply@hboss.com',
        to=[addr],
    )
    msg.send()
```
Reference: Zero Trust Email Ingestion Blueprint, Section IV.B
        """


class EmailInjectionDetector:
    """
    Detects email header injection vulnerabilities.

    Per "Zero Trust Email Ingestion Blueprint":
    "The critical mitigation is the strict removal of all newline
    characters (carriage return, \\r, and line feed, \\n) before
    the content is passed to any mail function."
    """

    # Email functions that are vulnerable if user input reaches them
    VULNERABLE_EMAIL_FUNCTIONS = [
        'send_mail',
        'EmailMessage',
        'EmailMultiAlternatives',
        'mail.send',
        'sendmail',
        'MIMEText',
        'MIMEMultipart',
    ]

    # Email headers that are injection targets
    VULNERABLE_HEADERS = [
        'To', 'From', 'Subject', 'Cc', 'Bcc',
        'Reply-To', 'Return-Path', 'Sender'
    ]

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """
        Main detection method.

        Checks for:
        1. User input in email headers (AST analysis)
        2. Missing CRLF sanitization (pattern matching)
        3. Direct header construction with user input
        """
        self.findings = []

        if file_path.endswith('.py'):
            # Python-specific detection
            self.findings.extend(self._detect_python_email_injection(file_content, file_path))

        # Generic pattern detection (works for all languages)
        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        # Convert findings to dict format
        return [f.to_dict() for f in self.findings]

    def _detect_python_email_injection(self, content: str, file_path: str) -> List[EmailInjectionFinding]:
        """
        AST-based detection for Python code.

        Looks for:
        - EmailMessage() with user input in headers
        - send_mail() with unsanitized strings
        - String formatting in email headers
        """
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Check for email function calls
            if isinstance(node, ast.Call):
                if self._is_email_function(node):
                    # Check if this call has unsafe user input
                    if self._has_unsafe_email_input(node, content):
                        findings.append(EmailInjectionFinding(
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=ast.get_source_segment(content, node) or '',
                            severity='CRITICAL',
                            confidence=85,
                            description='Email Header Injection: Missing CRLF sanitization in email function call',
                            vulnerability_type='EMAIL_INJECTION_FUNCTION_CALL'
                        ))

            # Check for direct header assignment
            if isinstance(node, ast.Assign):
                if self._is_email_header_assignment(node):
                    if self._contains_user_input(node):
                        findings.append(EmailInjectionFinding(
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=ast.get_source_segment(content, node) or '',
                            severity='CRITICAL',
                            confidence=80,
                            description='Email Header Injection: Direct assignment to email header without sanitization',
                            vulnerability_type='EMAIL_INJECTION_HEADER_ASSIGNMENT'
                        ))

        return findings

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[EmailInjectionFinding]:
        """
        Pattern-based detection that works across languages.

        Detects:
        - Email headers with string concatenation
        - User input (request.GET, request.POST, etc.) in email context
        - Missing CRLF sanitization
        """
        findings = []

        # Skip HTML/template files - they're not email code
        if file_path.endswith(('.html', '.htm', '.jinja', '.jinja2', '.j2', '.tpl', '.tmpl')):
            return findings

        lines = content.split('\n')

        # Pattern 1: User input in email headers without sanitization
        # MUST have explicit email context (send_mail, EmailMessage, etc.)
        email_with_user_input = re.compile(
            r'(send_mail|EmailMessage|mail\.send).*'
            r'(request\.(GET|POST|data)|params\[)',
            re.IGNORECASE
        )

        # Pattern 2: String formatting in actual email header assignments
        # Match explicit header assignments like: msg['Subject'] = f"{var}"
        string_format_in_header = re.compile(
            r'(msg|message|email)\[[\'\"](To|From|Subject|Cc|Bcc)[\'\"]\].*'
            r'(f\"|%s)',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for user input in email headers
            if email_with_user_input.search(line):
                # Check if CRLF removal is present in nearby lines
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not self._has_crlf_sanitization(context):
                    findings.append(EmailInjectionFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=90,
                        description='Email Header Injection: User input in email header without CRLF removal',
                        vulnerability_type='EMAIL_INJECTION_NO_CRLF_REMOVAL'
                    ))

            # Check for string formatting in headers
            if string_format_in_header.search(line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not self._has_crlf_sanitization(context):
                    findings.append(EmailInjectionFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=85,
                        description='Email Header Injection: String formatting in email header',
                        vulnerability_type='EMAIL_INJECTION_STRING_FORMATTING'
                    ))

        return findings

    def _is_email_function(self, node: ast.Call) -> bool:
        """Check if this is a call to an email function."""
        if isinstance(node.func, ast.Name):
            return node.func.id in self.VULNERABLE_EMAIL_FUNCTIONS

        if isinstance(node.func, ast.Attribute):
            return node.func.attr in self.VULNERABLE_EMAIL_FUNCTIONS

        return False

    def _has_unsafe_email_input(self, node: ast.Call, content: str) -> bool:
        """
        Check if email function has user input without sanitization.
        """
        # Check arguments and keywords for user input indicators
        for arg in node.args:
            if self._contains_user_input(arg):
                return True

        for keyword in node.keywords:
            if self._contains_user_input(keyword.value):
                return True

        return False

    def _is_email_header_assignment(self, node: ast.Assign) -> bool:
        """Check if this assigns to an email header."""
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                if isinstance(target.slice, ast.Constant):
                    if target.slice.value in self.VULNERABLE_HEADERS:
                        return True

            if isinstance(target, ast.Attribute):
                if target.attr in [h.lower() for h in self.VULNERABLE_HEADERS]:
                    return True

        return False

    def _contains_user_input(self, node) -> bool:
        """
        Check if AST node contains user input indicators.

        Looks for: request.GET, request.POST, request.data, params, etc.
        """
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                if node.value.id == 'request' and node.attr in ['GET', 'POST', 'data']:
                    return True

        if isinstance(node, ast.Name):
            if node.id in ['params', 'user_input', 'input_data']:
                return True

        # Check for string formatting with variables
        if isinstance(node, ast.JoinedStr):  # f-string
            return True

        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):  # + or %
                return True

        return False

    def _has_crlf_sanitization(self, code_context: str) -> bool:
        """
        Check if code has CRLF removal.

        Looks for:
        - .replace('\\r', '')
        - .replace('\\n', '')
        - re.sub(r'[\\r\\n]', '', ...)
        """
        crlf_removal_patterns = [
            r'\.replace\([\'"]\\r[\'"]\s*,\s*[\'"][\'"]',
            r'\.replace\([\'"]\\n[\'"]\s*,\s*[\'"][\'"]',
            r're\.sub\([^)]*\\r\\n[^)]*\)',
            r'strip_newlines',
            r'remove_crlf',
        ]

        for pattern in crlf_removal_patterns:
            if re.search(pattern, code_context):
                return True

        return False
