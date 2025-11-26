"""
Insecure File Upload Detector (CWE-434)

Detects insecure file upload vulnerabilities in CV/document upload features.

OWASP: A04:2021 - Insecure Design
Zero Trust Reference: Section IV.D "File Upload Security"
Research: "Zero Trust Email Ingestion Blueprint" (2025)

Attack Vector:
    Attacker uploads: resume.pdf.php
    Result: PHP code execution on server

HBOSS Impact: CV upload vulnerable to:
- Remote Code Execution (RCE)
- Web shell upload
- Malware distribution
- XSS via SVG uploads

3-Layer Defense Required:
1. Extension validation (whitelist)
2. Content-Type validation
3. Magic bytes validation
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class FileUploadFinding:
    """A detected insecure file upload vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    missing_layers: List[str]
    cwe_id: str = "CWE-434"
    owasp_category: str = "A04:2021 - Insecure Design"

    def to_dict(self) -> Dict:
        """Convert to dictionary format for scanner."""
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'missing_layers': self.missing_layers,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'hboss_impact': 'CV upload vulnerable to RCE and web shell upload',
            'fix': self._get_fix_example()
        }

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION (3-Layer Defense):
```python
import magic
import os
from pathlib import Path

ALLOWED_EXTENSIONS = {'.pdf', '.docx', '.doc', '.txt'}
ALLOWED_MIME_TYPES = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain'
}

def upload_cv_secure(uploaded_file):
    # Layer 1: Extension validation (whitelist)
    file_ext = Path(uploaded_file.name).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid file extension: {file_ext}")

    # Layer 2: Content-Type validation
    content_type = uploaded_file.content_type
    if content_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Invalid content type: {content_type}")

    # Layer 3: Magic bytes validation
    file_content = uploaded_file.read()
    mime = magic.from_buffer(file_content, mime=True)
    if mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"File content doesn't match extension: {mime}")

    # Layer 4: Antivirus scan (production requirement)
    if not scan_with_antivirus(file_content):
        raise ValueError("Malware detected")

    # Layer 5: Store outside web root
    safe_filename = generate_random_filename() + file_ext
    storage_path = '/secure/uploads/cvs/' + safe_filename

    with open(storage_path, 'wb') as f:
        f.write(file_content)

    return storage_path
```
Reference: Zero Trust Email Ingestion Blueprint, Section IV.D
        """


class FileUploadDetector:
    """
    Detects insecure file upload vulnerabilities.

    Per "Zero Trust Email Ingestion Blueprint":
    "File upload requires 3-layer validation: extension whitelist,
    Content-Type validation, and magic bytes verification."
    """

    # File upload frameworks/functions
    FILE_UPLOAD_INDICATORS = [
        'request.FILES',
        'FileField',
        'ImageField',
        'request.files',
        'MultipartFile',
        'UploadedFile',
        'file_get_contents',
        'move_uploaded_file',
    ]

    # Dangerous extensions that should never be allowed
    DANGEROUS_EXTENSIONS = [
        '.php', '.php3', '.php4', '.phtml',
        '.jsp', '.jspx',
        '.asp', '.aspx',
        '.exe', '.dll', '.so',
        '.sh', '.bash',
        '.py', '.rb', '.pl',
        '.cgi',
    ]

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """
        Main detection method.

        Checks for:
        1. File upload without validation (AST analysis)
        2. Missing 3-layer defense (pattern matching)
        3. Dangerous file types allowed
        """
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_file_upload(file_content, file_path))

        # Generic pattern detection
        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        # Convert findings to dict format
        return [f.to_dict() for f in self.findings]

    def _detect_python_file_upload(self, content: str, file_path: str) -> List[FileUploadFinding]:
        """
        AST-based detection for Python code.

        Looks for:
        - request.FILES access without validation
        - FileField/ImageField without validators
        - Direct file saving without checks
        """
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Check for file upload handling
            if isinstance(node, ast.Attribute):
                if self._is_file_upload_access(node):
                    # Get the context around this access
                    parent_func = self._get_parent_function(tree, node)
                    if parent_func:
                        missing_layers = self._check_validation_layers(
                            ast.get_source_segment(content, parent_func) or ''
                        )
                        if missing_layers:
                            findings.append(FileUploadFinding(
                                line=node.lineno,
                                column=node.col_offset,
                                code_snippet=ast.get_source_segment(content, node) or '',
                                severity='CRITICAL',
                                confidence=85,
                                description=f'Insecure file upload: Missing validation layers',
                                missing_layers=missing_layers
                            ))

        return findings

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[FileUploadFinding]:
        """
        Pattern-based detection that works across languages.

        Detects:
        - File upload without extension validation
        - No Content-Type checking
        - No magic bytes validation
        - Dangerous extensions allowed
        """
        findings = []
        lines = content.split('\n')

        # Pattern 1: File upload access
        file_upload_pattern = re.compile(
            r'(request\.FILES|request\.files|uploaded_file|MultipartFile)',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            if file_upload_pattern.search(line):
                # Check for validation in surrounding context
                context_start = max(0, i - 10)
                context_end = min(len(lines), i + 20)
                context = '\n'.join(lines[context_start:context_end])

                missing_layers = self._check_validation_layers(context)

                if missing_layers:
                    findings.append(FileUploadFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=80,
                        description=f'Insecure file upload: Missing {len(missing_layers)} validation layers',
                        missing_layers=missing_layers
                    ))

            # Pattern 2: Dangerous extension check
            extension_check = re.compile(
                r'(\.php|\.jsp|\.asp|\.exe|\.sh)\b',
                re.IGNORECASE
            )
            if extension_check.search(line):
                # Check if this is in an allowed extensions list
                if 'allowed' in line.lower() or 'whitelist' in line.lower():
                    findings.append(FileUploadFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=90,
                        description='Dangerous file extension in allowed list',
                        missing_layers=['Safe extension whitelist']
                    ))

        return findings

    def _is_file_upload_access(self, node: ast.Attribute) -> bool:
        """Check if this attribute access is related to file upload."""
        if isinstance(node.value, ast.Name):
            if node.value.id == 'request' and node.attr in ['FILES', 'files']:
                return True
        return False

    def _get_parent_function(self, tree: ast.AST, target_node: ast.AST) -> ast.FunctionDef:
        """Find the function containing the target node."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for child in ast.walk(node):
                    if child is target_node:
                        return node
        return None

    def _check_validation_layers(self, code_context: str) -> List[str]:
        """
        Check which validation layers are missing.

        Required layers:
        1. Extension validation (whitelist)
        2. Content-Type validation
        3. Magic bytes validation
        """
        missing = []

        # Layer 1: Extension validation
        extension_patterns = [
            r'ALLOWED_EXTENSIONS',
            r'allowed_ext',
            r'\.suffix\s+in\s+',
            r'endswith\([\'"]\.pdf',
            r'extension\s*==',
        ]
        if not any(re.search(p, code_context, re.IGNORECASE) for p in extension_patterns):
            missing.append('Layer 1: Extension whitelist validation')

        # Layer 2: Content-Type validation
        content_type_patterns = [
            r'content_type',
            r'MIME.*type',
            r'application/pdf',
            r'Content-Type',
        ]
        if not any(re.search(p, code_context, re.IGNORECASE) for p in content_type_patterns):
            missing.append('Layer 2: Content-Type validation')

        # Layer 3: Magic bytes validation
        magic_bytes_patterns = [
            r'magic\.from_buffer',
            r'python-magic',
            r'filetype\.guess',
            r'magic\s+bytes',
        ]
        if not any(re.search(p, code_context, re.IGNORECASE) for p in magic_bytes_patterns):
            missing.append('Layer 3: Magic bytes validation')

        return missing
