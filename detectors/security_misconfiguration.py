"""
Security Misconfiguration Detector (CWE-16)

Detects insecure configuration settings that expose the application to attacks,
including debug mode in production, permissive CORS, weak secrets, etc.

OWASP: A05:2021 - Security Misconfiguration
Research: AI copies insecure defaults from tutorials
Training Era: 2010-2020 (StackOverflow examples used DEBUG=True)

Attack Vectors:
- DEBUG=True in production → Information disclosure
- ALLOWED_HOSTS=['*'] → Host header injection
- SECRET_KEY='default' → Session hijacking
- CORS allow_origins=['*'] → Credential theft
- Unnecessary features enabled → Increased attack surface

AI Training Paradox:
    StackOverflow tutorials (2010-2015) prioritized "make it work"
    "Django not working?" → "Set DEBUG=True and ALLOWED_HOSTS=['*']"
    AI learned: "These settings make things work"
    Reality: These settings are ONLY for development
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass

try:
    from analysis_engine.research.academic_validation import get_cwe_research
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False


@dataclass
class SecurityMisconfigFinding:
    """A detected security misconfiguration."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    config_type: str
    insecure_value: str
    cwe_id: str = "CWE-16"
    owasp_category: str = "A05:2021 - Security Misconfiguration"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'config_type': self.config_type,
            'insecure_value': self.insecure_value,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2010-2020'

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE CONFIGURATION:
```python
# DJANGO settings.py

# VULNERABLE:
DEBUG = True  # NEVER in production!
ALLOWED_HOSTS = ['*']  # Allows any host
SECRET_KEY = 'django-insecure-hardcoded-key'  # Predictable
CORS_ALLOW_ALL_ORIGINS = True  # Allows any origin
SECURE_SSL_REDIRECT = False  # No HTTPS enforcement

# SAFE:
import os

# Use environment variables
DEBUG = os.getenv('DEBUG', 'False') == 'True'
SECRET_KEY = os.environ['SECRET_KEY']  # Must be set in environment
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost').split(',')

# Security settings for production
SECURE_SSL_REDIRECT = True  # Force HTTPS
SECURE_HSTS_SECONDS = 31536000  # HSTS for 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True  # Only send over HTTPS
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'  # Prevent clickjacking

# CORS - be specific
CORS_ALLOWED_ORIGINS = [
    'https://yourdomain.com',
    'https://app.yourdomain.com',
]

# Database - never hardcode credentials
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ['DB_NAME'],
        'USER': os.environ['DB_USER'],
        'PASSWORD': os.environ['DB_PASSWORD'],
        'HOST': os.environ['DB_HOST'],
        'PORT': os.environ['DB_PORT'],
    }
}

# FLASK VULNERABLE:
from flask import Flask
app = Flask(__name__)
app.config['DEBUG'] = True  # NEVER in production
app.config['SECRET_KEY'] = 'dev'  # Predictable
app.config['TESTING'] = True  # Disables security

# FLASK SAFE:
import os
from flask import Flask

app = Flask(__name__)
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False') == 'True'
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# FASTAPI VULNERABLE:
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows any origin!
    allow_credentials=True,  # With credentials = CRITICAL
    allow_methods=["*"],
    allow_headers=["*"],
)

# FASTAPI SAFE:
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://yourdomain.com",
        "https://app.yourdomain.com"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# ENVIRONMENT FILE (.env):
# NEVER commit .env files to git!
# Add .env to .gitignore

DEBUG=False
SECRET_KEY=random-64-character-string-generated-securely
DATABASE_URL=postgresql://user:pass@localhost/db
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Generate secure SECRET_KEY:
import secrets
print(secrets.token_urlsafe(64))
```

CRITICAL PRODUCTION CHECKLIST:
- [ ] DEBUG = False
- [ ] SECRET_KEY from environment (long, random)
- [ ] ALLOWED_HOSTS specific (not ['*'])
- [ ] CORS origins specific (not ['*'])
- [ ] HTTPS enforced (SECURE_SSL_REDIRECT = True)
- [ ] Database credentials from environment
- [ ] No default passwords
- [ ] Error messages don't expose stack traces
- [ ] File permissions restrictive
- [ ] Unnecessary features disabled

Reference: OWASP Security Misconfiguration
"""


class SecurityMisconfigurationDetector:
    """
    Detects insecure configuration settings.

    Checks for:
    - DEBUG=True in production code
    - ALLOWED_HOSTS=['*']
    - Hardcoded SECRET_KEY
    - Permissive CORS settings
    - Weak security headers
    """

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        # Focus on config files
        is_config_file = any(pattern in file_path.lower() for pattern in [
            'settings', 'config', '.env', 'app.py', 'main.py'
        ])

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_misconfig(file_content, file_path, is_config_file))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_misconfig(self, content: str, file_path: str, is_config: bool) -> List[SecurityMisconfigFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                finding = self._check_assignment(node, content, is_config)
                if finding:
                    findings.append(finding)

            if isinstance(node, ast.Call):
                finding = self._check_function_call(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_assignment(self, node: ast.Assign, content: str, is_config: bool) -> SecurityMisconfigFinding:
        """Check for insecure configuration assignments."""
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            var_name = target.id

            # Check DEBUG = True
            if var_name == 'DEBUG':
                if isinstance(node.value, ast.Constant):
                    if node.value.value is True:
                        severity = 'CRITICAL' if is_config else 'HIGH'
                        return SecurityMisconfigFinding(
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=ast.get_source_segment(content, node) or '',
                            severity=severity,
                            confidence=95,
                            description='DEBUG=True in production code',
                            config_type='DEBUG_MODE',
                            insecure_value='True'
                        )

            # Check ALLOWED_HOSTS = ['*']
            if var_name == 'ALLOWED_HOSTS':
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant):
                            if elt.value in ['*', '.']:
                                return SecurityMisconfigFinding(
                                    line=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=ast.get_source_segment(content, node) or '',
                                    severity='CRITICAL',
                                    confidence=95,
                                    description="ALLOWED_HOSTS=['*'] allows host header injection",
                                    config_type='ALLOWED_HOSTS',
                                    insecure_value='*'
                                )

            # Check SECRET_KEY hardcoded
            if 'SECRET_KEY' in var_name:
                if isinstance(node.value, ast.Constant):
                    secret_value = str(node.value.value)
                    # Check for weak secrets
                    if len(secret_value) < 20 or any(weak in secret_value.lower() for weak in [
                        'secret', 'key', 'password', 'django', 'flask', 'dev', 'test', 'insecure'
                    ]):
                        return SecurityMisconfigFinding(
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=ast.get_source_segment(content, node)[:100] or '',
                            severity='CRITICAL',
                            confidence=90,
                            description='Weak or hardcoded SECRET_KEY',
                            config_type='SECRET_KEY',
                            insecure_value='hardcoded'
                        )

            # Check CORS_ALLOW_ALL_ORIGINS = True
            if 'CORS' in var_name and 'ALLOW' in var_name:
                if isinstance(node.value, ast.Constant):
                    if node.value.value is True:
                        return SecurityMisconfigFinding(
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=ast.get_source_segment(content, node) or '',
                            severity='CRITICAL',
                            confidence=95,
                            description='CORS allows all origins with credentials',
                            config_type='CORS',
                            insecure_value='allow_all'
                        )

            # Check SECURE_SSL_REDIRECT = False
            if var_name == 'SECURE_SSL_REDIRECT':
                if isinstance(node.value, ast.Constant):
                    if node.value.value is False:
                        return SecurityMisconfigFinding(
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=ast.get_source_segment(content, node) or '',
                            severity='HIGH',
                            confidence=85,
                            description='HTTPS not enforced (SECURE_SSL_REDIRECT=False)',
                            config_type='SSL_REDIRECT',
                            insecure_value='False'
                        )

        return None

    def _check_function_call(self, node: ast.Call, content: str) -> SecurityMisconfigFinding:
        """Check for insecure function calls."""
        func_name = self._get_function_name(node)

        # Check for CORS middleware with allow_origins=["*"]
        if 'CORSMiddleware' in func_name or 'add_middleware' in func_name:
            for keyword in node.keywords:
                if keyword.arg == 'allow_origins':
                    if isinstance(keyword.value, ast.List):
                        for elt in keyword.value.elts:
                            if isinstance(elt, ast.Constant):
                                if elt.value == '*':
                                    return SecurityMisconfigFinding(
                                        line=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=ast.get_source_segment(content, node)[:100] or '',
                                        severity='CRITICAL',
                                        confidence=95,
                                        description='CORS allows all origins',
                                        config_type='CORS',
                                        insecure_value='*'
                                    )

        return None

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[SecurityMisconfigFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: DEBUG = True
        debug_true = re.compile(r'DEBUG\s*=\s*True', re.IGNORECASE)

        # Pattern 2: ALLOWED_HOSTS = ['*']
        allowed_hosts_wildcard = re.compile(r"ALLOWED_HOSTS\s*=\s*\[['\"]?\*['\"]?\]", re.IGNORECASE)

        # Pattern 3: SECRET_KEY with weak values
        weak_secret = re.compile(
            r"SECRET_KEY\s*=\s*['\"](?:secret|key|password|django|flask|dev|test|insecure|123)",
            re.IGNORECASE
        )

        # Pattern 4: CORS allow all
        cors_allow_all = re.compile(
            r"(?:allow_origins?|CORS_ORIGIN)\s*=\s*\[['\"]?\*['\"]?\]",
            re.IGNORECASE
        )

        # Pattern 5: Hardcoded database credentials
        db_credentials = re.compile(
            r"(?:PASSWORD|USER|HOST)\s*:\s*['\"](?!os\.environ|os\.getenv)(\w+)['\"]",
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check DEBUG = True
            if debug_true.search(line):
                findings.append(SecurityMisconfigFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=95,
                    description='DEBUG=True exposes sensitive information',
                    config_type='DEBUG_MODE',
                    insecure_value='True'
                ))

            # Check ALLOWED_HOSTS
            if allowed_hosts_wildcard.search(line):
                findings.append(SecurityMisconfigFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=95,
                    description="ALLOWED_HOSTS=['*'] vulnerable to host header attacks",
                    config_type='ALLOWED_HOSTS',
                    insecure_value='*'
                ))

            # Check weak SECRET_KEY
            if weak_secret.search(line):
                findings.append(SecurityMisconfigFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip()[:100],
                    severity='CRITICAL',
                    confidence=90,
                    description='Weak or predictable SECRET_KEY',
                    config_type='SECRET_KEY',
                    insecure_value='weak'
                ))

            # Check CORS allow all
            if cors_allow_all.search(line):
                findings.append(SecurityMisconfigFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=90,
                    description='CORS allows all origins - credential theft risk',
                    config_type='CORS',
                    insecure_value='*'
                ))

            # Check hardcoded DB credentials
            if 'PASSWORD' in line and db_credentials.search(line):
                if 'environ' not in line and 'getenv' not in line:
                    findings.append(SecurityMisconfigFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip()[:100],
                        severity='CRITICAL',
                        confidence=85,
                        description='Hardcoded database credentials',
                        config_type='DB_CREDENTIALS',
                        insecure_value='hardcoded'
                    ))

        return findings

    def _get_function_name(self, node: ast.Call) -> str:
        """Get function name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ''
