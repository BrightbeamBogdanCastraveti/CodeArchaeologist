"""
Excessive Agency/Overreliance Detector (LLM08)

Detects overreliance on LLM outputs without human oversight:
- Critical decisions made by LLM without review
- Medical/legal/financial advice without disclaimers
- Automated actions without confirmation
- No fact-checking of LLM outputs
- Missing human-in-the-loop for sensitive operations

OWASP LLM: LLM08 - Excessive Agency (overlaps with LLM06)
Research: 50% of AI apps lack human oversight for critical decisions
Training Era: 2023-2024

Attack Vectors:
1. LLM provides medical advice → acted on without verification
2. LLM generates legal documents → signed without review
3. LLM approves financial transactions → no human check
4. LLM makes hiring decisions → discrimination risk
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class OverrelianceFinding:
    """A detected overreliance vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    decision_type: str
    missing_oversight: str
    cwe_id: str = "CWE-693"
    owasp_category: str = "LLM08 - Excessive Agency"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'decision_type': self.decision_type,
            'missing_oversight': self.missing_oversight,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Add human review, disclaimers, and fact-checking for critical decisions'
        }


class OverrelianceDetector:
    """Detects overreliance on LLM outputs."""

    CRITICAL_DOMAINS = {
        'medical', 'health', 'diagnosis', 'prescription',
        'legal', 'contract', 'lawsuit',
        'financial', 'investment', 'trading', 'loan',
        'hiring', 'firing', 'promotion'
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_overreliance(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_overreliance(self, content: str, file_path: str) -> List[OverrelianceFinding]:
        findings = []
        lines = content.split('\n')

        # Pattern: LLM making critical decisions
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()

            # Check if critical domain
            critical_domain = None
            for domain in self.CRITICAL_DOMAINS:
                if domain in line_lower:
                    critical_domain = domain
                    break

            if critical_domain and re.search(r'(llm|gpt|claude|openai)', line_lower):
                # Check for human oversight
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])

                has_oversight = any(keyword in context.lower() for keyword in [
                    'review', 'approve', 'confirm', 'verify', 'human',
                    'disclaimer', 'warning', 'check'
                ])

                if not has_oversight:
                    findings.append(OverrelianceFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=70,
                        description=f'LLM making {critical_domain} decisions without human oversight',
                        decision_type=critical_domain,
                        missing_oversight='human_review'
                    ))

        return findings
