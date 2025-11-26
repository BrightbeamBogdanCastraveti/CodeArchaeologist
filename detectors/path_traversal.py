"""
Path Traversal Detector (CWE-22)

Detects path traversal vulnerabilities where user input is used to construct
file paths without proper validation, allowing access to files outside
intended directories.

OWASP: A01:2021 - Broken Access Control
Research: AI-generated code frequently lacks path validation
Training Era: 2008-2015 (StackOverflow examples rarely validated paths)

Attack Vector:
    User input: "../../etc/passwd"
    Code: open(f"/uploads/{filename}")
    Result: Reads /etc/passwd instead of uploaded file

HBOSS Impact: CV file operations vulnerable to:
- Reading arbitrary files (database.yml, .env)
- Accessing other users' CVs
- Reading application source code
"""

import ast
import re
from typing import List, Dict
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
class PathTraversalFinding:
    """A detected path traversal vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    file_operation: str
    user_variable: str
    cwe_id: str = "CWE-22"
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
            'file_operation': self.file_operation,
            'user_variable': self.user_variable,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2008-2015'
            result['why_ai_generates'] = explain_why_ai_generates('CWE-22')

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:
```python
import os
from pathlib import Path

# VULNERABLE:
filename = request.GET.get('file')
with open(f'/uploads/{filename}') as f:  # Path traversal!
    content = f.read()

# SAFE Option 1: Validate with allowlist:
ALLOWED_EXTENSIONS = {'.pdf', '.docx', '.txt'}
def is_safe_filename(filename):
    # Check extension
    if not any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        return False
    # Check for path traversal
    if '..' in filename or '/' in filename or '\\\\' in filename:
        return False
    # Check for special characters
    if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
        return False
    return True

filename = request.GET.get('file')
if not is_safe_filename(filename):
    raise ValueError("Invalid filename")
with open(f'/uploads/{filename}') as f:
    content = f.read()

# SAFE Option 2: Use Path.resolve() and check:
UPLOAD_DIR = Path('/uploads').resolve()
filename = request.GET.get('file')
file_path = (UPLOAD_DIR / filename).resolve()

# Ensure resolved path is still under UPLOAD_DIR
if not str(file_path).startswith(str(UPLOAD_DIR)):
    raise ValueError("Path traversal attempt detected")

with open(file_path) as f:
    content = f.read()

# SAFE Option 3: Use secure_filename():
from werkzeug.utils import secure_filename
filename = secure_filename(request.GET.get('file'))
with open(f'/uploads/{filename}') as f:
    content = f.read()
```

Reference: OWASP Path Traversal Prevention
"""


class PathTraversalDetector:
    """
    Detects path traversal vulnerabilities.

    High-risk patterns:
    - open() with user input
    - Path operations with concatenation
    - os.path.join() without validation
    """

    FILE_OPERATIONS = [
        'open',
        'os.open',
        'os.remove',
        'os.unlink',
        'os.rmdir',
        'shutil.copy',
        'shutil.move',
        'shutil.rmtree',
        'Path',
    ]

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_path_traversal(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_path_traversal(self, content: str, file_path: str) -> List[PathTraversalFinding]:
        """AST-based detection."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_file_operation(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_file_operation(self, node: ast.Call, content: str) -> PathTraversalFinding:
        """Check if this is a file operation with user input."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check if it's a file operation
        is_file_op = any(func_name == op or func_name.endswith(f'.{op}') for op in self.FILE_OPERATIONS)

        if not is_file_op:
            return None

        # Check for user input in path
        user_var, has_validation = self._check_path_argument(node)

        if not user_var:
            return None

        # If validation is present, lower severity
        if has_validation:
            return None  # Skip if properly validated

        # Check for dangerous patterns
        has_concatenation = self._has_path_concatenation(node)
        has_fstring = self._has_fstring_path(node)

        severity = 'CRITICAL' if (has_concatenation or has_fstring) else 'HIGH'
        confidence = 90 if has_fstring else 80

        return PathTraversalFinding(
            line=node.lineno,
            column=node.col_offset,
            code_snippet=ast.get_source_segment(content, node) or '',
            severity=severity,
            confidence=confidence,
            description=f'Path traversal in {func_name}() with user input: {user_var}',
            file_operation=func_name,
            user_variable=user_var
        )

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[PathTraversalFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: open() with f-string
        open_fstring = re.compile(
            r'open\s*\(\s*f["\'][^"\']*\{[^}]+\}',
            re.IGNORECASE
        )

        # Pattern 2: os.path.join with request/input
        path_join_input = re.compile(
            r'os\.path\.join\([^)]*(?:request\.|input|filename|path)[^)]*\)',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for open() with f-string
            if open_fstring.search(line):
                # Check if validation is present in surrounding lines
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                if not self._has_path_validation(context):
                    findings.append(PathTraversalFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=85,
                        description='Path traversal: f-string in file path without validation',
                        file_operation='open',
                        user_variable='f-string'
                    ))

            # Check for os.path.join with user input
            if path_join_input.search(line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])
                if not self._has_path_validation(context):
                    findings.append(PathTraversalFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=80,
                        description='Path traversal: os.path.join with user input',
                        file_operation='os.path.join',
                        user_variable='user_input'
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

    def _check_path_argument(self, node: ast.Call) -> tuple:
        """Check if path argument contains user input."""
        for arg in node.args:
            user_var = self._find_user_input_in_path(arg)
            if user_var:
                # Check if there's validation
                has_validation = self._check_for_validation(arg)
                return user_var, has_validation

        return '', False

    def _find_user_input_in_path(self, node) -> str:
        """Find user input in path construction."""
        # Check for request.GET, request.POST
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                if node.value.id == 'request':
                    return f'request.{node.attr}'

        # Check for common path variable names
        if isinstance(node, ast.Name):
            if node.id in ['filename', 'path', 'file', 'filepath', 'name']:
                return node.id

        # Check for f-string
        if isinstance(node, ast.JoinedStr):
            return 'f-string'

        # Check for concatenation
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return 'string concatenation'

        return ''

    def _check_for_validation(self, node) -> bool:
        """Check if node has path validation."""
        # This is simplified - in reality would need to check surrounding code
        return False

    def _has_path_concatenation(self, node: ast.Call) -> bool:
        """Check if using string concatenation for paths."""
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                return True
        return False

    def _has_fstring_path(self, node: ast.Call) -> bool:
        """Check if using f-string for paths."""
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                return True
        return False

    def _has_path_validation(self, code_context: str) -> bool:
        """Check if code has path validation."""
        validation_patterns = [
            r'secure_filename',
            r'\.\..*not in',
            r'startswith\(',
            r'resolve\(\)',
            r'if.*\.\.',
            r'raise.*traversal',
            r're\.match.*filename',
        ]

        for pattern in validation_patterns:
            if re.search(pattern, code_context, re.IGNORECASE):
                return True

        return False
