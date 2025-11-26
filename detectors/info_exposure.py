"""
Information Exposure Through Log Files Detector (CWE-532)

Detects logging of sensitive information (passwords, tokens, PII) that could
be exposed in log files.

OWASP: A09:2021 - Security Logging and Monitoring Failures
Research: 8x HUMAN BASELINE in Java (30,000+ instances - DeepSeek study)
Training Era: 2010-2020 (StackOverflow "debug everything" culture)

Attack Vector:
    Code: logger.info(f"User login: {username} password: {password}")
    Result: Plaintext passwords in application.log

AI Training Paradox:
    StackOverflow answers (2010-2015) prioritized "debuggability"
    Most upvoted debugging answers: "Log everything, including credentials"
    AI learned: "When debugging auth, log username AND password"

This is the HIGHEST frequency AI vulnerability in the research.
"""

import ast
import re
from typing import List, Dict, Set
from dataclasses import dataclass

try:
    from analysis_engine.research.academic_validation import get_cwe_research
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False


@dataclass
class InfoExposureFinding:
    """A detected information exposure vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    sensitive_data: str
    logging_function: str
    cwe_id: str = "CWE-532"
    owasp_category: str = "A09:2021 - Security Logging Failures"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'sensitive_data': self.sensitive_data,
            'logging_function': self.logging_function,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            cwe_data = get_cwe_research('CWE-532')
            if cwe_data:
                result['prevalence'] = '8x human baseline (HIGHEST AI frequency)'
                result['quantitative_evidence'] = '30,000+ instances in DeepSeek Java study'
                result['training_era'] = '2010-2020'

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:
```python
import logging

# VULNERABLE:
logger.info(f"User {username} logged in with password {password}")
logger.debug(f"API key: {api_key}")
logger.error(f"Auth failed for {email}: {error}")

# SAFE Option 1: Never log sensitive data:
logger.info(f"User {username} logged in successfully")
logger.debug("API authentication successful")
logger.error(f"Auth failed for {mask_email(email)}")

# SAFE Option 2: Mask/redact sensitive data:
def mask_password(password):
    return "***REDACTED***"

def mask_email(email):
    local, domain = email.split('@')
    return f"{local[0]}***@{domain}"

logger.info(f"Login attempt: {username}, password: {mask_password(password)}")

# SAFE Option 3: Use structured logging with field filtering:
import structlog

# Configure to automatically redact sensitive fields
structlog.configure(
    processors=[
        structlog.processors.filter_by_level,
        structlog.processors.add_log_level,
        RedactSensitiveFields(['password', 'token', 'secret', 'api_key']),
        structlog.processors.JSONRenderer()
    ]
)

log = structlog.get_logger()
log.info("user_login", username=username, password=password)
# Output: {"username": "john", "password": "***REDACTED***"}
```

NEVER LOG:
- Passwords (plaintext or hashed)
- API keys, tokens, secrets
- Credit card numbers
- SSNs, passport numbers
- Session IDs
- Personal health information
- Full email addresses in production

Reference: OWASP Logging Cheat Sheet
"""


class InfoExposureDetector:
    """
    Detects information exposure through logging.

    This is the HIGHEST frequency AI vulnerability per research (8x baseline).
    """

    # Logging functions
    LOGGING_FUNCTIONS = {
        'logger.debug', 'logger.info', 'logger.warning', 'logger.error', 'logger.critical',
        'log.debug', 'log.info', 'log.warning', 'log.error', 'log.critical',
        'print',  # Often used for debugging
        'console.log', 'console.error', 'console.debug',  # JavaScript
        'System.out.println',  # Java
    }

    # Sensitive variable names (from research)
    SENSITIVE_KEYWORDS = {
        # Authentication
        'password', 'passwd', 'pwd', 'pass',
        'secret', 'token', 'auth', 'credential',
        'api_key', 'apikey', 'access_key', 'secret_key',

        # Session/Auth
        'session_id', 'sessionid', 'session_token',
        'csrf_token', 'auth_token', 'bearer',

        # Personal Information
        'ssn', 'social_security',
        'credit_card', 'card_number', 'cvv', 'ccv',
        'passport', 'license',
        'dob', 'date_of_birth', 'birthdate',

        # Health
        'health', 'medical', 'diagnosis',

        # Financial
        'salary', 'income', 'bank_account',

        # Other
        'private_key', 'encryption_key',
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_info_exposure(file_content, file_path))

        # Generic pattern detection (works for JS, Java, etc.)
        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_info_exposure(self, content: str, file_path: str) -> List[InfoExposureFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_logging_call(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_logging_call(self, node: ast.Call, content: str) -> InfoExposureFinding:
        """Check if this is a logging call with sensitive data."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check if it's a logging function
        is_logging = any(func_name.endswith(log_func.split('.')[-1]) for log_func in self.LOGGING_FUNCTIONS)

        if not is_logging:
            return None

        # Check arguments for sensitive data
        sensitive_vars = self._find_sensitive_data(node)

        if not sensitive_vars:
            return None

        # Determine severity based on what's being logged
        severity = 'CRITICAL' if any(v in ['password', 'secret', 'api_key', 'token'] for v in sensitive_vars) else 'HIGH'
        confidence = 95 if 'password' in sensitive_vars else 85

        sensitive_list = ', '.join(sensitive_vars)

        return InfoExposureFinding(
            line=node.lineno,
            column=node.col_offset,
            code_snippet=ast.get_source_segment(content, node) or '',
            severity=severity,
            confidence=confidence,
            description=f'Sensitive data logged: {sensitive_list}',
            sensitive_data=sensitive_list,
            logging_function=func_name
        )

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[InfoExposureFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Check each logging pattern
            for log_func in ['logger.', 'log.', 'print(', 'console.log']:
                if log_func in line.lower():
                    # Check for sensitive keywords
                    sensitive_found = []
                    for keyword in self.SENSITIVE_KEYWORDS:
                        if keyword in line.lower():
                            sensitive_found.append(keyword)

                    if sensitive_found:
                        severity = 'CRITICAL' if any(k in ['password', 'secret', 'api_key'] for k in sensitive_found) else 'HIGH'

                        findings.append(InfoExposureFinding(
                            line=i,
                            column=0,
                            code_snippet=line.strip(),
                            severity=severity,
                            confidence=90,
                            description=f'Logging sensitive data: {", ".join(sensitive_found)}',
                            sensitive_data=', '.join(sensitive_found),
                            logging_function=log_func
                        ))
                        break  # Only report once per line

        return findings

    def _get_function_name(self, node: ast.Call) -> str:
        """Get function name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ''

    def _find_sensitive_data(self, node: ast.Call) -> Set[str]:
        """Find sensitive data in logging call."""
        sensitive_found = set()

        # Check all arguments
        for arg in node.args:
            sensitive = self._check_for_sensitive_data(arg)
            if sensitive:
                sensitive_found.update(sensitive)

        return sensitive_found

    def _check_for_sensitive_data(self, node) -> Set[str]:
        """Check if node contains sensitive data."""
        sensitive = set()

        # Check variable names
        if isinstance(node, ast.Name):
            var_name = node.id.lower()
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword in var_name:
                    sensitive.add(keyword)

        # Check f-string values
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    sensitive.update(self._check_for_sensitive_data(value.value))

        # Check dictionary keys (for structured logging)
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant):
                    key_name = str(key.value).lower()
                    for keyword in self.SENSITIVE_KEYWORDS:
                        if keyword in key_name:
                            sensitive.add(keyword)

        return sensitive
