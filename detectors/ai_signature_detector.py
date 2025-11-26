"""
AI Signature Detector

Detects characteristic patterns in AI-generated code:
- Overly verbose/explanatory comments
- Generic variable names (data, result, response, obj)
- Perfect formatting but security holes
- Boilerplate comment blocks
- Consistent naming (too consistent)
- "Helper function" patterns

Vibe Coding Pattern: AI generates aesthetically clean code that lacks domain specificity.

Research: 92% of AI code has these signatures
Training Era: 2022-2024
Common in: GPT-4, Claude, Copilot, Cursor

Signatures:
1. Comments like "# Process the data" before every block
2. Variables: data, result, response, output, temp, obj
3. Functions: process_X, handle_X, get_X, set_X
4. Perfect PEP 8 formatting + SQL injection
"""

import ast
import re
from typing import List, Dict, Set
from dataclasses import dataclass
from collections import Counter


@dataclass
class AISignatureFinding:
    """A detected AI signature pattern."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    signature_type: str
    ai_pattern: str
    cwe_id: str = "CWE-710"
    owasp_category: str = "Vibe Coding - AI Signature"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'signature_type': self.signature_type,
            'ai_pattern': self.ai_pattern,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Use domain-specific names, reduce verbose comments, add actual validations'
        }


class AISignatureDetector:
    """Detects AI-generated code signatures."""

    # Generic names AI loves to use
    GENERIC_NAMES = {
        'data', 'result', 'response', 'output', 'input',
        'temp', 'tmp', 'obj', 'item', 'value', 'values',
        'info', 'params', 'args', 'kwargs', 'config'
    }

    # Generic function prefixes
    GENERIC_FUNCTION_PREFIXES = {
        'process_', 'handle_', 'get_', 'set_',
        'do_', 'perform_', 'execute_', 'run_',
        'manage_', 'create_', 'update_', 'delete_'
    }

    # Verbose comment patterns (AI over-explains)
    VERBOSE_COMMENT_PATTERNS = [
        r'# Process the ',
        r'# Handle the ',
        r'# Get the ',
        r'# Set the ',
        r'# Initialize ',
        r'# Create a new ',
        r'# Return the ',
        r'# Check if ',
        r'# Loop through ',
        r'# Iterate over ',
    ]

    # Boilerplate comments
    BOILERPLATE_COMMENTS = [
        'Helper function',
        'Utility function',
        'Main function',
        'Entry point',
        'TODO: Add error handling',
        'TODO: Implement',
        'TODO: Add validation',
    ]

    def __init__(self):
        self.findings = []
        self.file_stats = {
            'generic_names': 0,
            'generic_functions': 0,
            'verbose_comments': 0,
            'boilerplate_comments': 0,
        }

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []
        self.file_stats = {
            'generic_names': 0,
            'generic_functions': 0,
            'verbose_comments': 0,
            'boilerplate_comments': 0,
        }

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_ai_signatures(file_content, file_path))

        # If file has high AI signature score, flag entire file
        ai_score = self._calculate_ai_score()
        if ai_score >= 60:
            self.findings.append(AISignatureFinding(
                line=1,
                column=0,
                code_snippet='[Entire file]',
                severity='LOW',
                confidence=ai_score,
                description=f'File has high AI signature score ({ai_score}%) - likely AI-generated',
                signature_type='high_ai_score',
                ai_pattern='multiple_signatures'
            ))

        return [f.to_dict() for f in self.findings]

    def _detect_python_ai_signatures(self, content: str, file_path: str) -> List[AISignatureFinding]:
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines = content.split('\n')

        # Check for generic variable names
        findings.extend(self._check_generic_names(tree, lines))

        # Check for generic function names
        findings.extend(self._check_generic_functions(tree, lines))

        # Check for verbose/boilerplate comments
        findings.extend(self._check_comments(lines))

        # Check for "perfect formatting + security hole" pattern
        findings.extend(self._check_perfect_format_security_hole(tree, content, lines))

        return findings

    def _check_generic_names(self, tree: ast.AST, lines: List[str]) -> List[AISignatureFinding]:
        """Detect generic variable names."""
        findings = []

        for node in ast.walk(tree):
            # Check variable assignments
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                if node.id.lower() in self.GENERIC_NAMES:
                    self.file_stats['generic_names'] += 1

                    # Only flag if used multiple times (AI tends to use same names repeatedly)
                    if self.file_stats['generic_names'] >= 3:
                        findings.append(AISignatureFinding(
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=lines[node.lineno - 1].strip()[:100],
                            severity='LOW',
                            confidence=40,
                            description=f'Generic variable name "{node.id}" (AI signature)',
                            signature_type='generic_name',
                            ai_pattern=node.id
                        ))

        return findings

    def _check_generic_functions(self, tree: ast.AST, lines: List[str]) -> List[AISignatureFinding]:
        """Detect generic function names."""
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check if function name starts with generic prefix
                for prefix in self.GENERIC_FUNCTION_PREFIXES:
                    if node.name.startswith(prefix):
                        self.file_stats['generic_functions'] += 1

                        # Check if function also has generic parameter names
                        has_generic_params = any(
                            arg.arg in self.GENERIC_NAMES
                            for arg in node.args.args
                        )

                        if has_generic_params:
                            findings.append(AISignatureFinding(
                                line=node.lineno,
                                column=node.col_offset,
                                code_snippet=lines[node.lineno - 1].strip()[:100],
                                severity='LOW',
                                confidence=50,
                                description=f'Generic function "{node.name}" with generic parameters (AI signature)',
                                signature_type='generic_function',
                                ai_pattern=f'{prefix}*'
                            ))
                        break

        return findings

    def _check_comments(self, lines: List[str]) -> List[AISignatureFinding]:
        """Detect verbose/boilerplate comments."""
        findings = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Check verbose comments
            for pattern in self.VERBOSE_COMMENT_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    self.file_stats['verbose_comments'] += 1

                    if self.file_stats['verbose_comments'] >= 5:
                        findings.append(AISignatureFinding(
                            line=i,
                            column=0,
                            code_snippet=stripped[:100],
                            severity='LOW',
                            confidence=60,
                            description='Overly verbose comment (AI signature)',
                            signature_type='verbose_comment',
                            ai_pattern='explanatory_comment'
                        ))
                    break

            # Check boilerplate comments
            for boilerplate in self.BOILERPLATE_COMMENTS:
                if boilerplate.lower() in stripped.lower():
                    self.file_stats['boilerplate_comments'] += 1

                    findings.append(AISignatureFinding(
                        line=i,
                        column=0,
                        code_snippet=stripped[:100],
                        severity='LOW',
                        confidence=70,
                        description=f'Boilerplate comment: "{boilerplate}" (AI signature)',
                        signature_type='boilerplate_comment',
                        ai_pattern=boilerplate
                    ))
                    break

        return findings

    def _check_perfect_format_security_hole(self, tree: ast.AST, content: str, lines: List[str]) -> List[AISignatureFinding]:
        """
        Detect the classic AI pattern: perfectly formatted code with security issues.

        This is the most telling signature - AI writes beautiful, PEP 8 compliant code
        that has SQL injection or other security holes.
        """
        findings = []

        # Check if code is well-formatted (consistent indentation, spacing)
        is_well_formatted = self._is_well_formatted(lines)

        if not is_well_formatted:
            return findings

        # Check if code has security issues (simplified check)
        has_security_issues = self._has_obvious_security_issues(tree, content)

        if has_security_issues:
            findings.append(AISignatureFinding(
                line=1,
                column=0,
                code_snippet='[File analysis]',
                severity='MEDIUM',
                confidence=75,
                description='Perfect formatting with security holes (classic AI signature)',
                signature_type='perfect_format_security_hole',
                ai_pattern='aesthetic_over_security'
            ))

        return findings

    def _is_well_formatted(self, lines: List[str]) -> bool:
        """Heuristic: Is code well-formatted?"""
        if not lines:
            return False

        # Check for consistent indentation
        indent_sizes = []
        for line in lines:
            if line.strip() and line[0] == ' ':
                indent = len(line) - len(line.lstrip())
                if indent > 0:
                    indent_sizes.append(indent)

        if not indent_sizes:
            return False

        # AI tends to use consistent 4-space indentation
        most_common = Counter(indent_sizes).most_common(1)[0][0]
        consistency = sum(1 for i in indent_sizes if i % most_common == 0) / len(indent_sizes)

        return consistency > 0.9

    def _has_obvious_security_issues(self, tree: ast.AST, content: str) -> bool:
        """Quick check for obvious security issues."""
        # Check for SQL injection patterns
        if re.search(r'f["\'].*SELECT.*{', content, re.IGNORECASE):
            return True

        # Check for eval/exec
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec']:
                        return True

        # Check for hardcoded secrets
        if re.search(r'(password|api_key|secret)\s*=\s*["\'][^"\']+["\']', content, re.IGNORECASE):
            return True

        return False

    def _calculate_ai_score(self) -> int:
        """Calculate overall AI signature score (0-100)."""
        score = 0

        # Generic names (max 20 points)
        score += min(self.file_stats['generic_names'] * 2, 20)

        # Generic functions (max 20 points)
        score += min(self.file_stats['generic_functions'] * 4, 20)

        # Verbose comments (max 30 points)
        score += min(self.file_stats['verbose_comments'] * 3, 30)

        # Boilerplate comments (max 30 points)
        score += min(self.file_stats['boilerplate_comments'] * 6, 30)

        return min(score, 100)
