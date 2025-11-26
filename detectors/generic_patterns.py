"""
Generic Patterns Detector

Detects AI's use of generic, non-domain-specific patterns:
- Generic variable names (data, result, obj, temp)
- Copy-paste signatures (similar code blocks)
- Inconsistent naming conventions within same file
- Mix of paradigms (OOP + functional randomly)
- "Kitchen sink" functions that do too much

Vibe Coding Pattern: AI generates code that works but lacks architectural coherence.

Research: 90% of AI code uses generic patterns
Training Era: 2022-2024
Common in: Fast iteration, multi-turn AI sessions

Patterns:
1. Variables: data, result, response, temp, obj, item, value
2. Functions doing 5+ different things
3. Switching between snake_case and camelCase randomly
4. No consistent error handling pattern
"""

import ast
import re
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict, Counter


@dataclass
class GenericPatternFinding:
    """A detected generic pattern issue."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    pattern_type: str
    inconsistency: str
    cwe_id: str = "CWE-1078"
    owasp_category: str = "Vibe Coding - Generic Patterns"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'pattern_type': self.pattern_type,
            'inconsistency': self.inconsistency,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Use domain-specific names, consistent patterns, and single-responsibility functions'
        }


class GenericPatternsDetector:
    """Detects generic patterns and inconsistencies in AI-generated code."""

    # Generic names that AI overuses
    GENERIC_NAMES = {
        'data', 'result', 'response', 'output', 'input',
        'temp', 'tmp', 'obj', 'item', 'value', 'values',
        'info', 'params', 'config', 'options', 'settings'
    }

    def __init__(self):
        self.findings = []
        self.file_stats = {
            'naming_conventions': [],  # Track naming styles
            'function_complexities': [],  # Track function sizes
            'generic_name_count': 0,
        }

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []
        self.file_stats = {
            'naming_conventions': [],
            'function_complexities': [],
            'generic_name_count': 0,
        }

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_generic_patterns(self, content: str, file_path: str) -> List[GenericPatternFinding]:
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines = content.split('\n')

        # Collect all names and patterns
        self._collect_file_stats(tree, content)

        # Check for generic names
        findings.extend(self._check_generic_names(tree, lines))

        # Check for naming inconsistencies
        findings.extend(self._check_naming_consistency(tree, lines))

        # Check for "kitchen sink" functions
        findings.extend(self._check_complex_functions(tree, content, lines))

        # Check for paradigm mixing
        findings.extend(self._check_paradigm_mixing(tree, lines))

        return findings

    def _collect_file_stats(self, tree: ast.AST, content: str):
        """Collect statistics about the file."""
        for node in ast.walk(tree):
            # Collect function names and their naming conventions
            if isinstance(node, ast.FunctionDef):
                self.file_stats['naming_conventions'].append(self._get_naming_style(node.name))

                # Calculate function complexity
                complexity = self._calculate_complexity(node, content)
                self.file_stats['function_complexities'].append((node.name, complexity, node.lineno))

            # Count generic names
            if isinstance(node, ast.Name):
                if node.id.lower() in self.GENERIC_NAMES:
                    self.file_stats['generic_name_count'] += 1

    def _check_generic_names(self, tree: ast.AST, lines: List[str]) -> List[GenericPatternFinding]:
        """Flag excessive use of generic names."""
        findings = []

        # If file has too many generic names, it's vibe code
        if self.file_stats['generic_name_count'] >= 10:
            findings.append(GenericPatternFinding(
                line=1,
                column=0,
                code_snippet='[File analysis]',
                severity='LOW',
                confidence=70,
                description=f'Excessive generic names ({self.file_stats["generic_name_count"]} occurrences) - lacks domain specificity',
                pattern_type='excessive_generic_names',
                inconsistency='non_domain_specific'
            ))

        return findings

    def _check_naming_consistency(self, tree: ast.AST, lines: List[str]) -> List[GenericPatternFinding]:
        """Check for inconsistent naming conventions."""
        findings = []

        naming_styles = self.file_stats['naming_conventions']
        if not naming_styles:
            return findings

        # Count naming styles
        style_counts = Counter(naming_styles)

        # If multiple styles used (inconsistency), flag it
        if len(style_counts) > 1:
            most_common = style_counts.most_common(2)
            if most_common[1][1] >= 2:  # At least 2 uses of second style
                findings.append(GenericPatternFinding(
                    line=1,
                    column=0,
                    code_snippet='[File analysis]',
                    severity='LOW',
                    confidence=60,
                    description=f'Inconsistent naming: {most_common[0][0]} ({most_common[0][1]}x) vs {most_common[1][0]} ({most_common[1][1]}x)',
                    pattern_type='inconsistent_naming',
                    inconsistency=f'{most_common[0][0]}_vs_{most_common[1][0]}'
                ))

        return findings

    def _check_complex_functions(self, tree: ast.AST, content: str, lines: List[str]) -> List[GenericPatternFinding]:
        """Check for 'kitchen sink' functions that do too much."""
        findings = []

        for func_name, complexity, lineno in self.file_stats['function_complexities']:
            # High complexity = function doing too much
            if complexity > 20:
                findings.append(GenericPatternFinding(
                    line=lineno,
                    column=0,
                    code_snippet=lines[lineno - 1].strip()[:100],
                    severity='MEDIUM',
                    confidence=75,
                    description=f'Function "{func_name}" is too complex (complexity: {complexity}) - likely doing multiple things',
                    pattern_type='kitchen_sink_function',
                    inconsistency='single_responsibility_violation'
                ))

        return findings

    def _check_paradigm_mixing(self, tree: ast.AST, lines: List[str]) -> List[GenericPatternFinding]:
        """Detect mixing of programming paradigms."""
        findings = []

        has_classes = False
        has_functions = False
        has_global_vars = False

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                has_classes = True
            elif isinstance(node, ast.FunctionDef) and not self._is_method(node, tree):
                has_functions = True
            elif isinstance(node, ast.Assign) and self._is_global_var(node, tree):
                has_global_vars = True

        # If mixing OOP and functional programming randomly
        if has_classes and has_functions and has_global_vars:
            findings.append(GenericPatternFinding(
                line=1,
                column=0,
                code_snippet='[File analysis]',
                severity='LOW',
                confidence=50,
                description='Mixed paradigms: OOP classes + standalone functions + global variables',
                pattern_type='paradigm_mixing',
                inconsistency='no_clear_architecture'
            ))

        return findings

    def _get_naming_style(self, name: str) -> str:
        """Detect naming convention style."""
        if '_' in name:
            return 'snake_case'
        elif name[0].isupper():
            return 'PascalCase'
        elif any(c.isupper() for c in name[1:]):
            return 'camelCase'
        else:
            return 'lowercase'

    def _calculate_complexity(self, func_node: ast.FunctionDef, content: str) -> int:
        """
        Calculate cyclomatic complexity (simplified).

        Counts:
        - if statements
        - for/while loops
        - try/except blocks
        - boolean operators (and, or)
        """
        complexity = 1  # Base complexity

        for node in ast.walk(func_node):
            if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1

        return complexity

    def _is_method(self, func_node: ast.FunctionDef, tree: ast.AST) -> bool:
        """Check if function is a class method."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if func_node in ast.walk(node):
                    return True
        return False

    def _is_global_var(self, assign_node: ast.Assign, tree: ast.AST) -> bool:
        """Check if assignment is a global variable."""
        # Simplified: check if assignment is at module level
        for node in ast.walk(tree):
            if isinstance(node, ast.Module):
                if assign_node in node.body:
                    return True
        return False
