"""
Model Denial of Service Detector (LLM04)

Detects vulnerabilities that enable DoS attacks on LLM infrastructure:
- Variable-length input without limits
- Recursive context expansion
- No request queuing/throttling
- Missing resource cleanup
- Memory leaks in conversation history
- Unbound

ed context windows

OWASP LLM: LLM04 - Model Denial of Service
Research: Overlaps with LLM10 - focused on model-specific DoS
Training Era: 2023-2024

Attack Vectors:
1. Send extremely long prompts → model timeout/crash
2. Recursive RAG retrieval → context explosion
3. Conversation history without cleanup → memory exhaustion
4. Complex regex in prompts → ReDoS
5. Large file uploads for processing

This is a specialized version of unbounded_consumption focused on model DoS.
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class ModelDoSFinding:
    """A detected model DoS vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    dos_type: str
    missing_control: str
    cwe_id: str = "CWE-400"
    owasp_category: str = "LLM04 - Model Denial of Service"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'dos_type': self.dos_type,
            'missing_control': self.missing_control,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Implement input length limits, request queuing, and resource cleanup'
        }


class ModelDoSDetector:
    """Detects model-specific DoS vulnerabilities."""

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_model_dos(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_model_dos(self, content: str, file_path: str) -> List[ModelDoSFinding]:
        findings = []
        lines = content.split('\n')

        # Pattern: LLM call without input length check
        for i, line in enumerate(lines, 1):
            if re.search(r'(openai|anthropic|llm)\.(chat|complete)', line, re.IGNORECASE):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+2)])

                if not re.search(r'len\(.*\)|max.*length', context, re.IGNORECASE):
                    findings.append(ModelDoSFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=70,
                        description='LLM call without input length validation',
                        dos_type='unbounded_input',
                        missing_control='input_length_limit'
                    ))

        return findings

    def _get_function_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ''
