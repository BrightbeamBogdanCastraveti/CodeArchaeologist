"""
Vibe Code Patterns Detector

Detects patterns extracted from real production audits of AI-generated code.
These patterns represent common issues found in "vibe coded" projects where
code works but lacks production-readiness qualities.

Based on audit findings:
- 846 dict.get() without defaults
- 62 array access without bounds checking
- 160 functions without error handling
- 749 type conversions without try/except
- 126 debug print statements
- 19 bare except:pass blocks
- 795 regex operations (potential ReDoS)
- 31 timezone-naive datetime usage
"""

import ast
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class VibeIssue:
    """Represents a vibe code issue detected in the codebase."""
    pattern_type: str
    severity: str
    line: int
    column: int
    description: str
    code_snippet: str
    cwe: Optional[str] = None
    fix_suggestion: Optional[str] = None


class VibePatternsDetector:
    """
    Detects vibe code patterns from real audit findings.

    Focuses on issues where code works but isn't production-ready:
    - Missing defensive programming
    - Incomplete error handling
    - Debugging artifacts in production
    - Unsafe type operations
    """

    def __init__(self):
        self.issues: List[VibeIssue] = []
        self.stats = {
            'dict_get_no_default': 0,
            'array_access_no_bounds': 0,
            'function_no_error_handling': 0,
            'unsafe_type_conversion': 0,
            'debug_prints': 0,
            'bare_except_pass': 0,
            'unsafe_regex': 0,
            'naive_datetime': 0,
        }

    def detect(self, file_path: str, source_code: str) -> List[VibeIssue]:
        """
        Run all vibe pattern detections on source code.

        Args:
            file_path: Path to the file being analyzed
            source_code: The source code content

        Returns:
            List of detected vibe issues
        """
        self.issues = []

        try:
            tree = ast.parse(source_code)
            lines = source_code.split('\n')

            # Run all detection methods
            self._detect_dict_get_no_default(tree, lines)
            self._detect_array_access_no_bounds(tree, lines)
            self._detect_function_no_error_handling(tree, lines)
            self._detect_unsafe_type_conversion(tree, lines)
            self._detect_debug_prints(tree, lines)
            self._detect_bare_except_pass(tree, lines)
            self._detect_unsafe_regex(tree, lines)
            self._detect_naive_datetime(tree, lines)

        except SyntaxError:
            pass  # Skip files with syntax errors

        return self.issues

    def _detect_dict_get_no_default(self, tree: ast.AST, lines: List[str]):
        """
        Detect: dict.get() without default value

        Audit finding: 846 instances
        Risk: NoneType errors in production

        Pattern:
            value = data.get('key')  # VULNERABLE
            # Later: value.upper() -> AttributeError if key missing

        Fix:
            value = data.get('key', '')  # Safe default
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for .get() method calls
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'get':
                    # dict.get('key') with 1 arg = no default
                    if len(node.args) == 1 and len(node.keywords) == 0:
                        self.stats['dict_get_no_default'] += 1

                        # Get the dict name
                        dict_name = ast.unparse(node.func.value) if hasattr(ast, 'unparse') else 'dict'
                        key_name = ast.unparse(node.args[0]) if hasattr(ast, 'unparse') else 'key'

                        self.issues.append(VibeIssue(
                            pattern_type='dict_get_no_default',
                            severity='MEDIUM',
                            line=node.lineno,
                            column=node.col_offset,
                            description=f"dict.get() without default value: {dict_name}.get({key_name})",
                            code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else '',
                            cwe='CWE-252',
                            fix_suggestion=f"Add default value: {dict_name}.get({key_name}, '')"
                        ))

    def _detect_array_access_no_bounds(self, tree: ast.AST, lines: List[str]):
        """
        Detect: Array/list access without bounds checking

        Audit finding: 62 instances
        Risk: IndexError crashes

        Pattern:
            first_item = items[0]  # VULNERABLE if items is empty

        Fix:
            first_item = items[0] if items else None
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                # Check if it's list/array access with integer index
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
                    # Look for surrounding if statement checking length
                    parent_checks_bounds = self._has_bounds_check_ancestor(node, tree)

                    if not parent_checks_bounds:
                        self.stats['array_access_no_bounds'] += 1

                        var_name = ast.unparse(node.value) if hasattr(ast, 'unparse') else 'array'
                        index = node.slice.value

                        self.issues.append(VibeIssue(
                            pattern_type='array_access_no_bounds',
                            severity='MEDIUM',
                            line=node.lineno,
                            column=node.col_offset,
                            description=f"Array access without bounds check: {var_name}[{index}]",
                            code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else '',
                            cwe='CWE-129',
                            fix_suggestion=f"Add bounds check: {var_name}[{index}] if len({var_name}) > {index} else None"
                        ))

    def _has_bounds_check_ancestor(self, node: ast.AST, tree: ast.AST) -> bool:
        """Check if node is inside a bounds-checking if statement."""
        # This is a simplified check - would need parent tracking for full accuracy
        # For now, we'll be conservative and flag most cases
        return False

    def _detect_function_no_error_handling(self, tree: ast.AST, lines: List[str]):
        """
        Detect: Functions without any error handling

        Audit finding: 160 instances
        Risk: Unhandled exceptions crash the application

        Pattern:
            def process_payment(amount):
                charge = stripe.Charge.create(amount=amount)  # Can fail
                return charge.id  # No try/except

        Fix:
            def process_payment(amount):
                try:
                    charge = stripe.Charge.create(amount=amount)
                    return charge.id
                except stripe.error.CardError as e:
                    logger.error(f"Payment failed: {e}")
                    raise PaymentError(str(e))
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check if function has any try/except blocks
                has_error_handling = any(
                    isinstance(child, ast.Try)
                    for child in ast.walk(node)
                )

                # Check if function makes risky calls (I/O, network, parsing)
                has_risky_operations = self._has_risky_operations(node)

                if has_risky_operations and not has_error_handling:
                    self.stats['function_no_error_handling'] += 1

                    self.issues.append(VibeIssue(
                        pattern_type='function_no_error_handling',
                        severity='HIGH',
                        line=node.lineno,
                        column=node.col_offset,
                        description=f"Function '{node.name}' has risky operations but no error handling",
                        code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else '',
                        cwe='CWE-755',
                        fix_suggestion=f"Add try/except block around risky operations in '{node.name}'"
                    ))

    def _has_risky_operations(self, func_node: ast.FunctionDef) -> bool:
        """Check if function performs operations that can raise exceptions."""
        risky_functions = {
            'open', 'read', 'write', 'json.loads', 'json.dumps',
            'requests.get', 'requests.post', 'urlopen',
            'int', 'float', 'datetime.strptime',
            'subprocess.call', 'subprocess.run', 'os.system',
            'connect', 'execute', 'commit',  # Database
        }

        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                func_name = ast.unparse(node.func) if hasattr(ast, 'unparse') else ''
                if any(risky in func_name for risky in risky_functions):
                    return True

        return False

    def _detect_unsafe_type_conversion(self, tree: ast.AST, lines: List[str]):
        """
        Detect: Type conversions without try/except

        Audit finding: 749 instances
        Risk: ValueError crashes

        Pattern:
            user_id = int(request.GET.get('id'))  # VULNERABLE
            # Attacker sends: ?id=abc -> ValueError

        Fix:
            try:
                user_id = int(request.GET.get('id'))
            except (ValueError, TypeError):
                return JsonResponse({'error': 'Invalid ID'}, status=400)
        """
        conversion_functions = {'int', 'float', 'bool', 'str', 'list', 'dict', 'set', 'tuple'}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check if it's a type conversion call
                if isinstance(node.func, ast.Name) and node.func.id in conversion_functions:
                    # Check if it's inside a try block
                    inside_try = self._is_inside_try_block(node, tree)

                    if not inside_try:
                        self.stats['unsafe_type_conversion'] += 1

                        func_name = node.func.id
                        arg_str = ast.unparse(node.args[0]) if hasattr(ast, 'unparse') and node.args else 'value'

                        self.issues.append(VibeIssue(
                            pattern_type='unsafe_type_conversion',
                            severity='MEDIUM',
                            line=node.lineno,
                            column=node.col_offset,
                            description=f"Unsafe type conversion: {func_name}({arg_str}) without try/except",
                            code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else '',
                            cwe='CWE-704',
                            fix_suggestion=f"Wrap in try/except to handle ValueError/TypeError"
                        ))

    def _is_inside_try_block(self, node: ast.AST, tree: ast.AST) -> bool:
        """Check if node is inside a try block."""
        # Simplified check - would need parent tracking for full accuracy
        # For now, we'll be conservative and flag most cases
        return False

    def _detect_debug_prints(self, tree: ast.AST, lines: List[str]):
        """
        Detect: Debug print statements in production code

        Audit finding: 126 instances
        Risk: Information disclosure, performance issues

        Pattern:
            print(f"User data: {user.email}")  # VULNERABLE
            print("DEBUG:", secret_key)

        Fix:
            logger.debug(f"User data: {user.email}")  # Use logging instead
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for print() calls
                if isinstance(node.func, ast.Name) and node.func.id == 'print':
                    self.stats['debug_prints'] += 1

                    # Try to get the printed value
                    arg_preview = ''
                    if node.args:
                        arg_preview = ast.unparse(node.args[0]) if hasattr(ast, 'unparse') else 'value'

                    self.issues.append(VibeIssue(
                        pattern_type='debug_print_statement',
                        severity='LOW',
                        line=node.lineno,
                        column=node.col_offset,
                        description=f"Debug print() statement in production code: print({arg_preview})",
                        code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else '',
                        cwe='CWE-215',
                        fix_suggestion="Replace with logger.debug() or remove if not needed"
                    ))

    def _detect_bare_except_pass(self, tree: ast.AST, lines: List[str]):
        """
        Detect: Bare except:pass blocks that swallow all errors

        Audit finding: 19 instances
        Risk: Silent failures, impossible to debug

        Pattern:
            try:
                critical_operation()
            except:  # VULNERABLE - catches everything including KeyboardInterrupt
                pass  # Silent failure

        Fix:
            try:
                critical_operation()
            except SpecificException as e:
                logger.error(f"Operation failed: {e}")
                raise  # Or handle appropriately
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    # Check for bare except (no exception type)
                    is_bare_except = handler.type is None

                    # Check if handler body is just 'pass'
                    is_pass_only = (
                        len(handler.body) == 1 and
                        isinstance(handler.body[0], ast.Pass)
                    )

                    if is_bare_except and is_pass_only:
                        self.stats['bare_except_pass'] += 1

                        self.issues.append(VibeIssue(
                            pattern_type='bare_except_pass',
                            severity='HIGH',
                            line=handler.lineno,
                            column=handler.col_offset,
                            description="Bare 'except: pass' silently swallows all errors",
                            code_snippet=lines[handler.lineno - 1].strip() if handler.lineno <= len(lines) else '',
                            cwe='CWE-391',
                            fix_suggestion="Catch specific exceptions and log errors: except SpecificError as e: logger.error(e)"
                        ))

    def _detect_unsafe_regex(self, tree: ast.AST, lines: List[str]):
        """
        Detect: Regex operations that could cause ReDoS

        Audit finding: 795 instances
        Risk: CPU exhaustion via malicious input (ReDoS attack)

        Pattern:
            re.match(r'(a+)+b', user_input)  # VULNERABLE to ReDoS
            # Input: 'aaaaaaaaaaaaaaaa!' causes exponential backtracking

        Fix:
            # Use atomic groups or possessive quantifiers
            re.match(r'(?:a+)+b', user_input, timeout=1)
            # Or validate input length first
        """
        redos_patterns = [
            r'\(.*\+\).*\+',  # (a+)+
            r'\(.*\*\).*\+',  # (a*)+
            r'\(.*\+\).*\*',  # (a+)*
            r'.*\..*\*.*\+',  # .*.*+
        ]

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for re.match, re.search, re.findall, etc.
                is_regex_call = False
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['match', 'search', 'findall', 'finditer', 'sub', 'split']:
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == 're':
                            is_regex_call = True

                if is_regex_call and node.args:
                    # Get the regex pattern (first argument)
                    pattern_node = node.args[0]

                    if isinstance(pattern_node, ast.Constant) and isinstance(pattern_node.value, str):
                        pattern = pattern_node.value

                        # Check for ReDoS-prone patterns
                        is_vulnerable = any(
                            re.search(redos, pattern)
                            for redos in redos_patterns
                        )

                        if is_vulnerable:
                            self.stats['unsafe_regex'] += 1

                            self.issues.append(VibeIssue(
                                pattern_type='unsafe_regex_redos',
                                severity='HIGH',
                                line=node.lineno,
                                column=node.col_offset,
                                description=f"Regex pattern susceptible to ReDoS attack: {pattern[:50]}",
                                code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else '',
                                cwe='CWE-1333',
                                fix_suggestion="Simplify regex or add input length validation before matching"
                            ))

    def _detect_naive_datetime(self, tree: ast.AST, lines: List[str]):
        """
        Detect: Timezone-naive datetime usage

        Audit finding: 31 instances
        Risk: Incorrect time calculations across timezones

        Pattern:
            now = datetime.now()  # VULNERABLE - naive datetime
            # Later: now < deadline -> wrong if timezones differ

        Fix:
            from django.utils import timezone
            now = timezone.now()  # Timezone-aware

            # Or with standard library:
            now = datetime.now(timezone.utc)
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for datetime.now() without timezone
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'now':
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'datetime':
                            # datetime.now() with no args = naive
                            if len(node.args) == 0 and len(node.keywords) == 0:
                                self.stats['naive_datetime'] += 1

                                self.issues.append(VibeIssue(
                                    pattern_type='naive_datetime',
                                    severity='MEDIUM',
                                    line=node.lineno,
                                    column=node.col_offset,
                                    description="Timezone-naive datetime.now() usage",
                                    code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else '',
                                    cwe='CWE-1285',
                                    fix_suggestion="Use timezone-aware datetime: datetime.now(timezone.utc) or django.utils.timezone.now()"
                                ))

    def get_statistics(self) -> Dict[str, Any]:
        """Return detection statistics."""
        return {
            'total_issues': len(self.issues),
            'patterns': self.stats,
            'severity_breakdown': {
                'CRITICAL': sum(1 for i in self.issues if i.severity == 'CRITICAL'),
                'HIGH': sum(1 for i in self.issues if i.severity == 'HIGH'),
                'MEDIUM': sum(1 for i in self.issues if i.severity == 'MEDIUM'),
                'LOW': sum(1 for i in self.issues if i.severity == 'LOW'),
            }
        }

    def generate_report(self) -> str:
        """Generate human-readable report of vibe code issues."""
        report = []
        report.append("=" * 70)
        report.append("VIBE CODE PATTERNS DETECTION REPORT")
        report.append("From Real Production Audit Findings")
        report.append("=" * 70)
        report.append("")

        stats = self.get_statistics()
        report.append(f"Total Issues Found: {stats['total_issues']}")
        report.append("")

        report.append("Pattern Breakdown:")
        report.append("-" * 70)
        for pattern, count in stats['patterns'].items():
            if count > 0:
                report.append(f"  {pattern:.<50} {count:>5}")
        report.append("")

        report.append("Severity Breakdown:")
        report.append("-" * 70)
        for severity, count in stats['severity_breakdown'].items():
            if count > 0:
                report.append(f"  {severity:.<50} {count:>5}")
        report.append("")

        # Group issues by pattern type
        issues_by_pattern = {}
        for issue in self.issues:
            if issue.pattern_type not in issues_by_pattern:
                issues_by_pattern[issue.pattern_type] = []
            issues_by_pattern[issue.pattern_type].append(issue)

        report.append("Detailed Issues:")
        report.append("=" * 70)

        for pattern_type, pattern_issues in issues_by_pattern.items():
            report.append("")
            report.append(f"{pattern_type.upper().replace('_', ' ')} ({len(pattern_issues)} issues)")
            report.append("-" * 70)

            # Show first 5 issues of each type
            for issue in pattern_issues[:5]:
                report.append(f"  Line {issue.line}: {issue.description}")
                report.append(f"    Code: {issue.code_snippet}")
                report.append(f"    Fix: {issue.fix_suggestion}")
                report.append("")

            if len(pattern_issues) > 5:
                report.append(f"  ... and {len(pattern_issues) - 5} more")
                report.append("")

        report.append("=" * 70)
        report.append("RECOMMENDATIONS")
        report.append("=" * 70)
        report.append("")
        report.append("This code shows signs of 'vibe coding' - rapid AI-assisted development")
        report.append("where features work but lack production-readiness qualities.")
        report.append("")
        report.append("Priority fixes:")
        report.append("1. Add error handling to all functions with I/O operations")
        report.append("2. Replace bare 'except: pass' with specific exception handling")
        report.append("3. Add try/except around all type conversions of user input")
        report.append("4. Add default values to all dict.get() calls")
        report.append("5. Remove debug print() statements, use logging instead")
        report.append("")

        return "\n".join(report)


# Convenience function for standalone usage
def detect_vibe_patterns(file_path: str, source_code: str) -> List[VibeIssue]:
    """
    Detect vibe code patterns in a Python file.

    Args:
        file_path: Path to the file being analyzed
        source_code: The source code content

    Returns:
        List of detected vibe issues
    """
    detector = VibePatternsDetector()
    return detector.detect(file_path, source_code)
