"""
Missing Validation Detector

Detects AI's tendency to trust all inputs without validation:
- No type checking on function parameters
- No range/bounds checking
- No format validation (email, phone, etc.)
- Missing length limits
- No whitelist validation
- Trust all user input

Vibe Coding Pattern: AI assumes inputs are always valid and well-formed.

Research: 85% of AI-generated functions lack input validation
Training Era: 2022-2024
Common in: All AI coding assistants

Attack Vectors:
1. No type checking → TypeError in production
2. No bounds checking → buffer overflow, array index errors
3. No format validation → invalid data in database
4. No length limits → DoS via large inputs
"""

import ast
import re
from typing import List, Dict, Set
from dataclasses import dataclass


@dataclass
class MissingValidationFinding:
    """A detected missing validation issue."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    validation_type: str
    parameter_name: str
    cwe_id: str = "CWE-20"
    owasp_category: str = "Vibe Coding - Missing Validation"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'validation_type': self.validation_type,
            'parameter_name': self.parameter_name,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Add type checks, bounds validation, format validation, and length limits'
        }


class MissingValidationDetector:
    """Detects missing input validation in AI-generated code."""

    # Parameters that should ALWAYS be validated
    SENSITIVE_PARAM_NAMES = {
        'user_id', 'id', 'username', 'email', 'phone',
        'password', 'token', 'key', 'file', 'path',
        'url', 'query', 'amount', 'price', 'quantity'
    }

    # Types that need validation
    RISKY_PARAM_TYPES = {
        'str', 'int', 'float', 'list', 'dict', 'Any'
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_missing_validation(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_missing_validation(self, content: str, file_path: str) -> List[MissingValidationFinding]:
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines = content.split('\n')

        # Check all function definitions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                findings.extend(self._check_function_validation(node, content, lines))

        return findings

    def _check_function_validation(self, func_node: ast.FunctionDef, content: str, lines: List[str]) -> List[MissingValidationFinding]:
        """Check if function validates its parameters."""
        findings = []

        # Skip if no parameters
        if not func_node.args.args:
            return findings

        # Skip special methods
        if func_node.name.startswith('__'):
            return findings

        # Get function source
        func_source = ast.get_source_segment(content, func_node)
        if not func_source:
            return findings

        # Check each parameter
        for arg in func_node.args.args:
            param_name = arg.arg

            # Skip 'self' and 'cls'
            if param_name in ['self', 'cls']:
                continue

            # Check if this parameter needs validation
            needs_validation = (
                param_name in self.SENSITIVE_PARAM_NAMES or
                self._is_sensitive_param(param_name) or
                self._has_risky_type_hint(arg)
            )

            if not needs_validation:
                continue

            # Check if parameter is validated
            validation_checks = self._find_validations(func_source, param_name)

            if not validation_checks:
                # No validation found - classic vibe code
                findings.append(MissingValidationFinding(
                    line=func_node.lineno,
                    column=func_node.col_offset,
                    code_snippet=lines[func_node.lineno - 1].strip()[:100],
                    severity='MEDIUM',
                    confidence=70,
                    description=f'Parameter "{param_name}" used without validation',
                    validation_type='no_validation',
                    parameter_name=param_name
                ))
            else:
                # Check for missing specific validations
                findings.extend(self._check_validation_completeness(
                    func_node, param_name, validation_checks, lines
                ))

        # Check for API endpoints without request validation
        if self._is_api_endpoint(func_node, content):
            if not self._has_request_validation(func_source):
                findings.append(MissingValidationFinding(
                    line=func_node.lineno,
                    column=func_node.col_offset,
                    code_snippet=lines[func_node.lineno - 1].strip()[:100],
                    severity='HIGH',
                    confidence=80,
                    description=f'API endpoint "{func_node.name}" missing request validation',
                    validation_type='missing_request_validation',
                    parameter_name='request'
                ))

        return findings

    def _is_sensitive_param(self, param_name: str) -> bool:
        """Check if parameter name suggests it needs validation."""
        sensitive_keywords = [
            'id', 'user', 'email', 'file', 'path', 'url',
            'query', 'amount', 'price', 'data', 'input'
        ]

        param_lower = param_name.lower()
        return any(keyword in param_lower for keyword in sensitive_keywords)

    def _has_risky_type_hint(self, arg: ast.arg) -> bool:
        """Check if parameter has a risky type hint."""
        if not arg.annotation:
            return True  # No type hint = risky

        # Check if type hint is 'Any' or str/int/float (needs validation)
        if isinstance(arg.annotation, ast.Name):
            return arg.annotation.id in self.RISKY_PARAM_TYPES

        return False

    def _find_validations(self, func_source: str, param_name: str) -> Set[str]:
        """Find what validations are performed on a parameter."""
        validations = set()

        # Type checking
        if re.search(rf'isinstance\s*\(\s*{param_name}\s*,', func_source):
            validations.add('type_check')

        if re.search(rf'type\s*\(\s*{param_name}\s*\)', func_source):
            validations.add('type_check')

        # None/null checking
        if re.search(rf'if\s+not\s+{param_name}', func_source):
            validations.add('null_check')

        if re.search(rf'if\s+{param_name}\s+is\s+None', func_source):
            validations.add('null_check')

        # Length checking
        if re.search(rf'len\s*\(\s*{param_name}\s*\)', func_source):
            validations.add('length_check')

        # Range checking
        if re.search(rf'{param_name}\s*[<>]=?', func_source):
            validations.add('range_check')

        # Format validation (regex, email, etc.)
        if re.search(rf're\.(match|search|findall).*{param_name}', func_source):
            validations.add('format_check')

        # Raise ValueError/TypeError
        if 'raise ValueError' in func_source or 'raise TypeError' in func_source:
            validations.add('error_handling')

        return validations

    def _check_validation_completeness(self, func_node: ast.FunctionDef, param_name: str,
                                      validations: Set[str], lines: List[str]) -> List[MissingValidationFinding]:
        """Check if validations are complete."""
        findings = []

        # Check for specific missing validations based on parameter name
        if 'email' in param_name.lower():
            if 'format_check' not in validations:
                findings.append(MissingValidationFinding(
                    line=func_node.lineno,
                    column=func_node.col_offset,
                    code_snippet=lines[func_node.lineno - 1].strip()[:100],
                    severity='MEDIUM',
                    confidence=80,
                    description=f'Email parameter "{param_name}" missing format validation',
                    validation_type='missing_format_validation',
                    parameter_name=param_name
                ))

        if 'id' in param_name.lower():
            if 'type_check' not in validations:
                findings.append(MissingValidationFinding(
                    line=func_node.lineno,
                    column=func_node.col_offset,
                    code_snippet=lines[func_node.lineno - 1].strip()[:100],
                    severity='MEDIUM',
                    confidence=70,
                    description=f'ID parameter "{param_name}" missing type validation',
                    validation_type='missing_type_validation',
                    parameter_name=param_name
                ))

        if any(keyword in param_name.lower() for keyword in ['amount', 'price', 'quantity']):
            if 'range_check' not in validations:
                findings.append(MissingValidationFinding(
                    line=func_node.lineno,
                    column=func_node.col_offset,
                    code_snippet=lines[func_node.lineno - 1].strip()[:100],
                    severity='MEDIUM',
                    confidence=75,
                    description=f'Numeric parameter "{param_name}" missing range validation',
                    validation_type='missing_range_validation',
                    parameter_name=param_name
                ))

        if any(keyword in param_name.lower() for keyword in ['path', 'file', 'url']):
            if 'format_check' not in validations:
                findings.append(MissingValidationFinding(
                    line=func_node.lineno,
                    column=func_node.col_offset,
                    code_snippet=lines[func_node.lineno - 1].strip()[:100],
                    severity='HIGH',
                    confidence=85,
                    description=f'Path/URL parameter "{param_name}" missing format validation (path traversal risk)',
                    validation_type='missing_format_validation',
                    parameter_name=param_name
                ))

        return findings

    def _is_api_endpoint(self, func_node: ast.FunctionDef, content: str) -> bool:
        """Check if function is an API endpoint."""
        # Check for decorators like @app.route, @api_view, etc.
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr in ['route', 'get', 'post', 'put', 'delete']:
                        return True
            elif isinstance(decorator, ast.Name):
                if decorator.id in ['api_view', 'csrf_exempt']:
                    return True

        # Check function parameters
        for arg in func_node.args.args:
            if arg.arg == 'request':
                return True

        return False

    def _has_request_validation(self, func_source: str) -> bool:
        """Check if API endpoint validates request data."""
        validation_keywords = [
            'validate', 'is_valid', 'clean', 'serializer',
            'schema', 'form', 'validator', 'pydantic'
        ]

        return any(keyword in func_source.lower() for keyword in validation_keywords)
