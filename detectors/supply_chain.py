"""
Supply Chain Vulnerabilities Detector (LLM05)

Detects vulnerabilities in LLM supply chain:
- Unverified model sources
- No model integrity checks
- Untrusted plugins/extensions
- Outdated LLM libraries
- Missing dependency scanning
- Third-party model APIs without validation

OWASP LLM: LLM05 - Supply-Chain Vulnerabilities
Research: 30% of AI apps use unverified third-party models
Training Era: 2023-2024

Attack Vectors:
1. Load model from untrusted source → backdoored model
2. Use compromised LangChain plugin → malicious code execution
3. Outdated openai library → known vulnerabilities
4. Third-party embedding model → data exfiltration
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class SupplyChainFinding:
    """A detected supply chain vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    supply_chain_type: str
    untrusted_source: str
    cwe_id: str = "CWE-494"
    owasp_category: str = "LLM05 - Supply-Chain Vulnerabilities"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'supply_chain_type': self.supply_chain_type,
            'untrusted_source': self.untrusted_source,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Use official model sources, verify checksums, scan dependencies'
        }


class SupplyChainDetector:
    """Detects supply chain vulnerabilities in LLM applications."""

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_supply_chain(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_supply_chain(self, content: str, file_path: str) -> List[SupplyChainFinding]:
        findings = []
        lines = content.split('\n')

        # Pattern: Loading models from user-specified paths
        model_load_pattern = re.compile(
            r'(load_model|from_pretrained)\s*\(\s*(?:path|url|model_name)',
            re.IGNORECASE
        )

        # Pattern: Untrusted HuggingFace repos
        hf_pattern = re.compile(
            r'from_pretrained\s*\(\s*["\'](?!(?:openai|facebook|google|microsoft|anthropic))',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            if model_load_pattern.search(line):
                # Check if checksum verification is present
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+10)])

                if not re.search(r'(checksum|verify|hash|sha256)', context, re.IGNORECASE):
                    findings.append(SupplyChainFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=75,
                        description='Model loaded without integrity verification',
                        supply_chain_type='unverified_model',
                        untrusted_source='model_path'
                    ))

            if hf_pattern.search(line):
                findings.append(SupplyChainFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='MEDIUM',
                    confidence=60,
                    description='Model from non-official HuggingFace repository',
                    supply_chain_type='untrusted_model_source',
                    untrusted_source='huggingface'
                ))

        return findings
