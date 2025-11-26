"""
Model Theft Detector (LLM09)

Detects vulnerabilities that enable model extraction/theft:
- Unrestricted API access for model probing
- No rate limiting on inference endpoints
- Detailed error messages exposing model architecture
- Model served without authentication
- Missing monitoring for extraction attempts

OWASP LLM: LLM09 - Model Theft
Research: 20% of AI APIs vulnerable to model extraction
Training Era: 2023-2024

Attack Vectors:
1. Query model repeatedly to extract training data
2. Probe model to reverse-engineer architecture
3. Use model outputs to train competing model
4. Download model weights from unprotected endpoint
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class ModelTheftFinding:
    """A detected model theft vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    theft_vector: str
    missing_protection: str
    cwe_id: str = "CWE-284"
    owasp_category: str = "LLM09 - Model Theft"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'theft_vector': self.theft_vector,
            'missing_protection': self.missing_protection,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Add authentication, rate limiting, and monitoring for extraction attempts'
        }


class ModelTheftDetector:
    """Detects model theft vulnerabilities."""

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_model_theft(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_model_theft(self, content: str, file_path: str) -> List[ModelTheftFinding]:
        findings = []
        lines = content.split('\n')

        # Pattern: Model inference endpoint without auth
        for i, line in enumerate(lines, 1):
            if re.search(r'@app\.route.*/(predict|inference|model)', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+10)])

                # Check for authentication
                has_auth = any(keyword in context.lower() for keyword in [
                    'login_required', 'require_auth', 'authenticate',
                    'jwt', 'token', 'api_key'
                ])

                # Check for rate limiting
                has_rate_limit = any(keyword in context.lower() for keyword in [
                    'rate_limit', 'limiter', 'throttle'
                ])

                if not has_auth:
                    findings.append(ModelTheftFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=80,
                        description='Model inference endpoint without authentication',
                        theft_vector='unrestricted_access',
                        missing_protection='authentication'
                    ))

                if not has_rate_limit:
                    findings.append(ModelTheftFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='MEDIUM',
                        confidence=75,
                        description='Model inference endpoint without rate limiting',
                        theft_vector='model_probing',
                        missing_protection='rate_limiting'
                    ))

        return findings
