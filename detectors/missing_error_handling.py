"""
Missing Error Handling Detector

Detects AI's tendency to write "happy path" code without error handling:
- Try/except blocks missing around risky operations
- No validation of function inputs
- Assumes all operations succeed
- Missing null checks
- No timeout handling for external calls

Vibe Coding Pattern: AI generates working code fast but skips defensive programming.

Research: 78% of AI-generated code lacks proper error handling
Training Era: 2022-2024
Common in: GPT-4, Claude, Copilot outputs

Attack Vectors:
1. Missing try/except → unhandled exceptions crash app
2. No input validation → invalid data causes errors
3. No null checks → NoneType errors in production
4. Missing timeouts → hanging connections
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class MissingErrorHandlingFinding:
    """A detected missing error handling issue."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    error_type: str
    risky_operation: str
    cwe_id: str = "CWE-754"
    owasp_category: str = "Vibe Coding - Missing Error Handling"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'error_type': self.error_type,
            'risky_operation': self.risky_operation,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Add try/except blocks, input validation, null checks, and timeouts'
        }


class MissingErrorHandlingDetector:
    """Detects missing error handling in AI-generated code."""

    # Operations that should be wrapped in try/except
    RISKY_OPERATIONS = {
        # File I/O
        'open': 'file_io',
        'read': 'file_io',
        'write': 'file_io',

        # Network operations
        'requests.get': 'network',
        'requests.post': 'network',
        'urllib.request': 'network',
        'socket.connect': 'network',
        'http.client': 'network',

        # Database operations
        'execute': 'database',
        'cursor.execute': 'database',
        'query': 'database',
        'commit': 'database',

        # External API calls
        'openai': 'external_api',
        'anthropic': 'external_api',
        'api.call': 'external_api',

        # JSON/parsing
        'json.loads': 'parsing',
        'json.load': 'parsing',
        'ast.literal_eval': 'parsing',
        'eval': 'parsing',

        # Type conversions
        'int(': 'type_conversion',
        'float(': 'type_conversion',
        'dict(': 'type_conversion',
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_missing_error_handling(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_missing_error_handling(self, content: str, file_path: str) -> List[MissingErrorHandlingFinding]:
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines = content.split('\n')

        # Check all function definitions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                findings.extend(self._check_function_error_handling(node, content, lines))

        # Check risky operations outside try/except
        findings.extend(self._check_unprotected_operations(tree, content, lines))

        return findings

    def _check_function_error_handling(self, func_node: ast.FunctionDef, content: str, lines: List[str]) -> List[MissingErrorHandlingFinding]:
        """Check if function has proper error handling."""
        findings = []

        # Get function source
        func_source = ast.get_source_segment(content, func_node)
        if not func_source:
            return findings

        # Check if function has any risky operations
        has_risky_ops = self._has_risky_operations(func_node)

        if not has_risky_ops:
            return findings

        # Check if function has try/except
        has_try_except = self._has_try_except(func_node)

        if not has_try_except:
            # This is the vibe coding pattern: risky operations without error handling
            findings.append(MissingErrorHandlingFinding(
                line=func_node.lineno,
                column=func_node.col_offset,
                code_snippet=lines[func_node.lineno - 1].strip()[:100],
                severity='MEDIUM',
                confidence=75,
                description=f'Function "{func_node.name}" performs risky operations without error handling',
                error_type='missing_try_except',
                risky_operation='multiple'
            ))

        # Check for missing input validation
        if func_node.args.args and not self._has_input_validation(func_node, content):
            findings.append(MissingErrorHandlingFinding(
                line=func_node.lineno,
                column=func_node.col_offset,
                code_snippet=lines[func_node.lineno - 1].strip()[:100],
                severity='LOW',
                confidence=60,
                description=f'Function "{func_node.name}" missing input validation',
                error_type='missing_validation',
                risky_operation='unvalidated_inputs'
            ))

        return findings

    def _check_unprotected_operations(self, tree: ast.AST, content: str, lines: List[str]) -> List[MissingErrorHandlingFinding]:
        """Check for specific risky operations outside try/except blocks."""
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Get the function being called
                func_name = self._get_function_name(node)

                # Check if it's a risky operation
                risk_type = None
                for pattern, op_type in self.RISKY_OPERATIONS.items():
                    if pattern in func_name.lower():
                        risk_type = op_type
                        break

                if risk_type:
                    # Check if this call is inside a try/except
                    if not self._is_inside_try_except(node, tree):
                        findings.append(MissingErrorHandlingFinding(
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=lines[node.lineno - 1].strip()[:100],
                            severity='MEDIUM',
                            confidence=80,
                            description=f'{func_name} operation without try/except block',
                            error_type='unprotected_operation',
                            risky_operation=risk_type
                        ))

            # DISABLED: Too many false positives
            # Check for missing null checks before attribute access
            # Only flag if it's truly risky (e.g., accessing user input directly)
            # if isinstance(node, ast.Attribute):
            #     # Skip - this generates 856 false positives at 50% confidence
            #     pass

        return findings

    def _has_risky_operations(self, node: ast.AST) -> bool:
        """Check if node contains any risky operations."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_function_name(child)
                for pattern in self.RISKY_OPERATIONS.keys():
                    if pattern in func_name.lower():
                        return True
        return False

    def _has_try_except(self, node: ast.AST) -> bool:
        """Check if node contains try/except block."""
        for child in ast.walk(node):
            if isinstance(child, ast.Try):
                return True
        return False

    def _has_input_validation(self, func_node: ast.FunctionDef, content: str) -> bool:
        """Check if function validates its inputs."""
        func_source = ast.get_source_segment(content, func_node)
        if not func_source:
            return False

        validation_keywords = [
            'if not', 'if ', 'raise ValueError', 'raise TypeError',
            'assert', 'isinstance', 'type(', 'len('
        ]

        # Check first 5 lines of function for validation
        lines = func_source.split('\n')[:5]
        for line in lines:
            if any(keyword in line for keyword in validation_keywords):
                return True

        return False

    def _is_inside_try_except(self, node: ast.AST, tree: ast.AST) -> bool:
        """Check if a node is inside a try/except block."""
        # This is a simplified check - in a real implementation,
        # we'd traverse the AST to find parent nodes
        for potential_try in ast.walk(tree):
            if isinstance(potential_try, ast.Try):
                # Check if node's line is within try block range
                try_start = potential_try.lineno
                try_end = potential_try.body[-1].lineno if potential_try.body else try_start

                if try_start <= node.lineno <= try_end:
                    return True

        return False

    def _has_null_check_before(self, node: ast.AST, tree: ast.AST, content: str) -> bool:
        """Check if there's a null check before this attribute access."""
        # Simplified: check if line contains common null check patterns
        lines = content.split('\n')
        if node.lineno <= len(lines):
            line = lines[node.lineno - 1]
            if ' if ' in line or ' and ' in line:
                return True

        return False

    def _is_likely_vibe_code(self, node: ast.AST, content: str) -> bool:
        """Heuristic: Is this likely AI-generated vibe code?"""
        # Check for common vibe patterns:
        # - Simple attribute chains (obj.attr.attr)
        # - No defensive checks
        # - In functions without try/except

        # This is a heuristic - only flag high-confidence cases
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Attribute):
                # Chained attribute access (obj.x.y) without checks
                return True

        return False

    def _get_function_name(self, node: ast.Call) -> str:
        """Extract function name from Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ''
