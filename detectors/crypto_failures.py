"""
Cryptographic Failures Detector (CWE-327)

Detects use of broken or weak cryptographic algorithms.

OWASP: A02:2021 - Cryptographic Failures
Research: HIGH frequency in AI code (MD5/SHA1 for passwords)
Training Era: 2008-2015 (pre-modern crypto awareness)

Attack Vectors:
- MD5/SHA1 for password hashing (broken since 2005)
- Weak random number generation (not cryptographically secure)
- ECB mode encryption (deterministic, reveals patterns)
- Small key sizes (RSA < 2048, AES < 128)

AI Training Paradox:
    StackOverflow (2008-2012) had thousands of upvoted answers using MD5
    "How to hash passwords in Python?" → "Use hashlib.md5()"
    AI learned: "MD5 is standard for password hashing"
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
class CryptoFailureFinding:
    """A detected cryptographic failure."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    weak_algorithm: str
    context: str
    cwe_id: str = "CWE-327"
    owasp_category: str = "A02:2021 - Cryptographic Failures"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'weak_algorithm': self.weak_algorithm,
            'context': self.context,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2008-2015'
            result['prevalence'] = 'High in AI code (password hashing)'

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:
```python
# VULNERABLE: MD5/SHA1 for passwords
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha1(password.encode()).hexdigest()

# SAFE: Use bcrypt, scrypt, or Argon2
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Or use Django's built-in
from django.contrib.auth.hashers import make_password
password_hash = make_password(password)

# VULNERABLE: Weak random
import random
token = random.randint(1000, 9999)  # Predictable!

# SAFE: Cryptographically secure random
import secrets
token = secrets.token_urlsafe(32)

# VULNERABLE: ECB mode (deterministic)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)  # Reveals patterns

# SAFE: Use GCM or CBC with random IV
cipher = AES.new(key, AES.MODE_GCM)

# VULNERABLE: Small RSA key
from Crypto.PublicKey import RSA
key = RSA.generate(1024)  # Too small!

# SAFE: Modern key size
key = RSA.generate(2048)  # Minimum
key = RSA.generate(4096)  # Better
```

NEVER USE:
- MD5, SHA1 for passwords
- DES, 3DES, RC4
- ECB mode
- RSA < 2048 bits
- random module for security

Reference: OWASP Cryptographic Storage Cheat Sheet
"""


class CryptoFailuresDetector:
    """Detects use of weak/broken cryptographic algorithms."""

    # Broken hash functions (do not use for passwords)
    WEAK_HASHES = {'md5', 'sha1', 'sha', 'md4'}

    # Weak ciphers
    WEAK_CIPHERS = {'DES', 'RC4', 'RC2', 'Blowfish'}

    # Weak modes
    WEAK_MODES = {'ECB'}

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_crypto(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_crypto(self, content: str, file_path: str) -> List[CryptoFailureFinding]:
        """AST-based detection."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_crypto_call(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_crypto_call(self, node: ast.Call, content: str) -> CryptoFailureFinding:
        """Check if using weak crypto."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check for weak hash functions
        for weak_hash in self.WEAK_HASHES:
            if func_name.endswith(weak_hash):
                # Determine context (is it for passwords?)
                context = self._determine_context(node, content)
                severity = 'CRITICAL' if context == 'password_hashing' else 'HIGH'

                return CryptoFailureFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node) or '',
                    severity=severity,
                    confidence=95,
                    description=f'Weak cryptographic hash: {weak_hash.upper()}',
                    weak_algorithm=weak_hash.upper(),
                    context=context
                )

        # Check for weak ciphers
        if 'AES.MODE_ECB' in func_name or 'MODE_ECB' in content[max(0, node.lineno-1):node.lineno]:
            return CryptoFailureFinding(
                line=node.lineno,
                column=node.col_offset,
                code_snippet=ast.get_source_segment(content, node) or '',
                severity='HIGH',
                confidence=90,
                description='Weak cipher mode: ECB (deterministic encryption)',
                weak_algorithm='ECB',
                context='encryption'
            )

        # Check for random (not secrets)
        if func_name.startswith('random.') and func_name not in ['random.SystemRandom']:
            # Check if used for security (tokens, keys, etc.)
            if self._is_security_context(content, node.lineno):
                return CryptoFailureFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node) or '',
                    severity='HIGH',
                    confidence=85,
                    description='Weak random for security: use secrets module',
                    weak_algorithm='random',
                    context='random_generation'
                )

        return None

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[CryptoFailureFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: hashlib.md5 for passwords
        md5_password = re.compile(
            r'(hashlib\.(md5|sha1)|md5\(|sha1\().*password',
            re.IGNORECASE
        )

        # Pattern 2: Weak random for security
        weak_random_security = re.compile(
            r'random\.(randint|choice|random).*(?:token|key|secret|password)',
            re.IGNORECASE
        )

        # Pattern 3: Small RSA key
        small_rsa = re.compile(
            r'RSA\.generate\s*\(\s*(512|1024)\s*\)',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check MD5/SHA1 for passwords
            if md5_password.search(line):
                findings.append(CryptoFailureFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=95,
                    description='MD5/SHA1 used for password hashing',
                    weak_algorithm='MD5/SHA1',
                    context='password_hashing'
                ))

            # Check weak random for security
            if weak_random_security.search(line):
                findings.append(CryptoFailureFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='HIGH',
                    confidence=85,
                    description='Weak random used for security tokens/keys',
                    weak_algorithm='random',
                    context='security_tokens'
                ))

            # Check small RSA keys
            if small_rsa.search(line):
                findings.append(CryptoFailureFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='HIGH',
                    confidence=90,
                    description='RSA key size too small (< 2048 bits)',
                    weak_algorithm='RSA',
                    context='key_generation'
                ))

        return findings

    def _get_function_name(self, node: ast.Call) -> str:
        """Get function name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                if isinstance(node.func.value.value, ast.Name):
                    return f"{node.func.value.value.id}.{node.func.value.attr}.{node.func.attr}"
        return ''

    def _determine_context(self, node: ast.Call, content: str) -> str:
        """Determine context of crypto usage."""
        # Look at variable names and surrounding code
        lines = content.split('\n')
        line_num = node.lineno - 1

        # Check current line and nearby lines for context
        context_lines = lines[max(0, line_num-2):min(len(lines), line_num+3)]
        context_text = ' '.join(context_lines).lower()

        if any(keyword in context_text for keyword in ['password', 'passwd', 'pwd', 'credential']):
            return 'password_hashing'
        elif any(keyword in context_text for keyword in ['checksum', 'integrity', 'hash_file']):
            return 'integrity_check'
        else:
            return 'unknown'

    def _is_security_context(self, content: str, line_num: int) -> bool:
        """Check if random is used in security context."""
        lines = content.split('\n')
        context_lines = lines[max(0, line_num-2):min(len(lines), line_num+2)]
        context_text = ' '.join(context_lines).lower()

        security_keywords = ['token', 'key', 'secret', 'password', 'salt', 'nonce', 'session']
        return any(keyword in context_text for keyword in security_keywords)
