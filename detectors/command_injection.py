"""
Command Injection Detector (CWE-78)

Detects OS command injection vulnerabilities where user input is passed
to shell commands without proper sanitization.

OWASP: A03:2021 - Injection
Research: AI generates at significantly higher rates (per academic research)
Training Era: 2008-2015 (StackOverflow examples used shell=True)

Attack Vector:
    User input: "file.txt; rm -rf /"
    Code: os.system(f"cat {filename}")
    Result: Deletes entire filesystem

AI Training Paradox:
    StackOverflow (2008-2012) examples prioritized "quick solutions"
    over security. Most upvoted answers used shell=True for convenience.
    AI learned: "Use os.system() or subprocess with shell=True for file ops"
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass

# Try to import research
try:
    from analysis_engine.research.academic_validation import (
        get_cwe_research,
        explain_why_ai_generates
    )
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False


@dataclass
class CommandInjectionFinding:
    """A detected command injection vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    command_function: str
    user_variable: str
    cwe_id: str = "CWE-78"
    owasp_category: str = "A03:2021 - Injection"

    def to_dict(self) -> Dict:
        """Convert to dictionary format for scanner."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'command_function': self.command_function,
            'user_variable': self.user_variable,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            cwe_data = get_cwe_research('CWE-78')
            if cwe_data:
                result['prevalence'] = cwe_data.get('prevalence', '')
                result['training_era'] = '2008-2015'
                result['why_ai_generates'] = explain_why_ai_generates('CWE-78')

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:
```python
# VULNERABLE:
import os
filename = request.GET.get('file')
os.system(f"cat {filename}")  # Command injection!

# SAFE Option 1: Use subprocess with list (no shell):
import subprocess
filename = request.GET.get('file')
# Validate filename first
if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
    raise ValueError("Invalid filename")
result = subprocess.run(['cat', filename], capture_output=True, check=True)

# SAFE Option 2: Use Python file operations (no shell at all):
with open(filename, 'r') as f:
    content = f.read()

# SAFE Option 3: Use shlex.quote() if shell is unavoidable:
import shlex
filename = shlex.quote(request.GET.get('file'))
os.system(f"cat {filename}")  # Still not recommended
```

Reference: OWASP Injection Prevention Cheat Sheet
"""


class CommandInjectionDetector:
    """
    Detects OS command injection vulnerabilities.

    High-risk functions:
    - os.system()
    - os.popen()
    - subprocess.call/run/Popen with shell=True
    - eval() with shell commands
    """

    # Dangerous shell command functions
    DANGEROUS_FUNCTIONS = {
        'os.system',
        'os.popen',
        'os.popen2',
        'os.popen3',
        'os.popen4',
        'subprocess.call',
        'subprocess.run',
        'subprocess.Popen',
        'subprocess.check_output',
        'subprocess.check_call',
        'commands.getoutput',
        'commands.getstatusoutput',
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """
        Main detection method.

        Checks for:
        1. os.system() with user input
        2. subprocess with shell=True and user input
        3. String formatting in shell commands
        """
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_command_injection(file_content, file_path))

        # Generic pattern detection
        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_command_injection(self, content: str, file_path: str) -> List[CommandInjectionFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_command_call(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_command_call(self, node: ast.Call, content: str) -> CommandInjectionFinding:
        """Check if this is a dangerous command execution."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check if it's a dangerous function
        is_dangerous = any(func_name.endswith(dangerous) for dangerous in [
            'system', 'popen', 'call', 'run', 'Popen', 'check_output', 'check_call', 'getoutput', 'getstatusoutput'
        ])

        if not is_dangerous:
            return None

        # Check for user input in arguments
        user_var = self._find_user_input(node)
        if not user_var:
            # Check for shell=True (dangerous even without obvious user input)
            has_shell_true = self._has_shell_true(node)
            if has_shell_true:
                user_var = "shell=True"
            else:
                return None

        # Check for string formatting (high risk)
        has_formatting = self._has_string_formatting(node)

        severity = 'CRITICAL' if has_formatting else 'HIGH'
        confidence = 90 if has_formatting else 75

        return CommandInjectionFinding(
            line=node.lineno,
            column=node.col_offset,
            code_snippet=ast.get_source_segment(content, node) or '',
            severity=severity,
            confidence=confidence,
            description=f'Command injection via {func_name}() with user input: {user_var}',
            command_function=func_name,
            user_variable=user_var
        )

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[CommandInjectionFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: os.system with f-string or concatenation
        system_pattern = re.compile(
            r'(os\.system|subprocess\.call|subprocess\.run|os\.popen)\s*\(\s*f["\']',
            re.IGNORECASE
        )

        # Pattern 2: shell=True with variable
        shell_true_pattern = re.compile(
            r'(subprocess\.\w+)\s*\([^)]*shell\s*=\s*True',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for os.system with f-string
            if system_pattern.search(line):
                findings.append(CommandInjectionFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=90,
                    description='Command injection: f-string in shell command',
                    command_function='os.system/subprocess',
                    user_variable='f-string'
                ))

            # Check for shell=True
            if shell_true_pattern.search(line):
                # Check if there's a variable in the command
                if any(indicator in line for indicator in ['request.', 'input', 'args', 'kwargs']):
                    findings.append(CommandInjectionFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=85,
                        description='Command injection: shell=True with user input',
                        command_function='subprocess',
                        user_variable='shell=True'
                    ))

        return findings

    def _get_function_name(self, node: ast.Call) -> str:
        """Get the full function name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ''

    def _find_user_input(self, node: ast.Call) -> str:
        """Find user input indicators in arguments."""
        for arg in node.args:
            user_var = self._check_for_user_input(arg)
            if user_var:
                return user_var

        for keyword in node.keywords:
            user_var = self._check_for_user_input(keyword.value)
            if user_var:
                return user_var

        return ''

    def _check_for_user_input(self, node) -> str:
        """Check if node contains user input."""
        # Check for request.GET, request.POST, etc.
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                if node.value.id == 'request' and node.attr in ['GET', 'POST', 'data', 'args']:
                    return f'request.{node.attr}'

        # Check for common input variable names
        if isinstance(node, ast.Name):
            if node.id in ['filename', 'path', 'command', 'args', 'input', 'user_input']:
                return node.id

        # Check for f-string (always risky)
        if isinstance(node, ast.JoinedStr):
            return 'f-string'

        # Check for string concatenation
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return 'string concatenation'

        return ''

    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if call has shell=True."""
        for keyword in node.keywords:
            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is True:
                    return True
        return False

    def _has_string_formatting(self, node: ast.Call) -> bool:
        """Check if arguments use string formatting."""
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):  # f-string
                return True
            if isinstance(arg, ast.BinOp):  # concatenation
                return True
        return False
