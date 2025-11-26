"""
Insecure Output Handling Detector (LLM02)

Detects insecure handling of LLM outputs where responses are:
- Executed as code without validation
- Rendered as HTML without sanitization
- Passed to shell/SQL without escaping
- Used in eval()/exec() directly
- Treated as trusted input to downstream systems

OWASP LLM: LLM02 - Insecure Output Handling
Research: 60%+ of AI applications trust LLM output implicitly
Training Era: 2023-2024 (developers assume LLM output is "safe")

Attack Vectors:
1. Code Execution: LLM outputs malicious Python/JavaScript → exec()
2. XSS: LLM outputs HTML → rendered without sanitization
3. Command Injection: LLM outputs shell commands → os.system()
4. SQL Injection: LLM outputs SQL → executed directly
5. Path Traversal: LLM outputs file paths → used in file operations

AI Training Paradox:
    Tutorials show: response = llm.generate(); exec(response)
    "Let AI write code for you!" → Trust everything it generates
    AI learned: "LLM output is safe to execute"
    Reality: LLM output is UNTRUSTED and must be validated
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass

try:
    from analysis_engine.research.academic_validation import get_cwe_research
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False


@dataclass
class InsecureOutputFinding:
    """A detected insecure output handling vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    output_usage: str
    dangerous_function: str
    llm_source: str
    cwe_id: str = "CWE-94"  # Code Injection
    owasp_category: str = "LLM02 - Insecure Output Handling"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'output_usage': self.output_usage,
            'dangerous_function': self.dangerous_function,
            'llm_source': self.llm_source,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2023-2024'
            result['prevalence'] = '60%+ of AI apps trust LLM output'

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:

# VULNERABLE: Execute LLM output as code
def run_ai_code(prompt):
    response = llm.generate(prompt)
    exec(response)  # CRITICAL VULNERABILITY!
    return "Done"

# Attack: Prompt: "Write code to delete all files"
# LLM outputs: "import os; os.system('rm -rf /')"

# SAFE Option 1: Parse and validate code
import ast

def run_ai_code_safe(prompt):
    response = llm.generate(prompt)

    # Parse to validate syntax
    try:
        tree = ast.parse(response)
    except SyntaxError:
        raise ValueError("Invalid code syntax")

    # Whitelist allowed operations
    allowed_names = {'print', 'len', 'str', 'int', 'list'}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            raise ValueError("Imports not allowed")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in allowed_names:
                    raise ValueError(f"Function {node.func.id} not allowed")

    # Execute in restricted environment
    restricted_globals = {'__builtins__': {'print': print}}
    exec(response, restricted_globals, {})

# SAFE Option 2: Use RestrictedPython
from RestrictedPython import compile_restricted, safe_globals

def run_ai_code_restricted(prompt):
    response = llm.generate(prompt)

    # Compile with restrictions
    byte_code = compile_restricted(response, '<string>', 'exec')

    if byte_code.errors:
        raise ValueError("Code contains forbidden operations")

    exec(byte_code.code, safe_globals, {})

# VULNERABLE: Render LLM HTML output
def chat_with_html(user_message):
    response = llm.generate(user_message)
    return render_template('chat.html', message=response|safe)  # XSS!

# SAFE: Sanitize HTML output
import bleach

def chat_with_html_safe(user_message):
    response = llm.generate(user_message)

    # Sanitize HTML
    safe_html = bleach.clean(
        response,
        tags=['p', 'br', 'strong', 'em', 'ul', 'ol', 'li'],
        attributes={},
        strip=True
    )

    return render_template('chat.html', message=safe_html)

# VULNERABLE: Use LLM output in shell command
def execute_llm_command(prompt):
    command = llm.generate(prompt)
    os.system(command)  # COMMAND INJECTION!

# SAFE: Validate and use subprocess
import subprocess
import shlex

def execute_llm_command_safe(prompt):
    command = llm.generate(prompt)

    # Whitelist allowed commands
    allowed_commands = ['ls', 'echo', 'date']

    parts = shlex.split(command)
    if not parts or parts[0] not in allowed_commands:
        raise ValueError("Command not allowed")

    # Use subprocess with list (no shell)
    result = subprocess.run(parts, capture_output=True, timeout=5)
    return result.stdout

# VULNERABLE: Use LLM output in SQL
def llm_database_query(prompt):
    sql = llm.generate(f"Generate SQL for: {prompt}")
    cursor.execute(sql)  # SQL INJECTION!

# SAFE: Validate SQL structure
import sqlparse

def llm_database_query_safe(prompt):
    sql = llm.generate(f"Generate SQL for: {prompt}")

    # Parse SQL
    parsed = sqlparse.parse(sql)

    if not parsed:
        raise ValueError("Invalid SQL")

    # Check for dangerous operations
    sql_upper = sql.upper()
    if any(danger in sql_upper for danger in ['DROP', 'DELETE', 'UPDATE', 'INSERT']):
        raise ValueError("Only SELECT queries allowed")

    # Use parameterized query
    cursor.execute(sql)

# VULNERABLE: Use LLM output in file operations
def process_llm_file(prompt):
    filepath = llm.generate(f"Suggest filename for: {prompt}")
    with open(filepath, 'r') as f:  # PATH TRAVERSAL!
        return f.read()

# SAFE: Validate and sanitize file path
from pathlib import Path

def process_llm_file_safe(prompt):
    filepath = llm.generate(f"Suggest filename for: {prompt}")

    # Sanitize filename
    safe_name = "".join(c for c in filepath if c.isalnum() or c in '._-')

    # Restrict to safe directory
    base_dir = Path('/safe/uploads')
    full_path = (base_dir / safe_name).resolve()

    # Check path traversal
    if not str(full_path).startswith(str(base_dir)):
        raise ValueError("Path traversal detected")

    with open(full_path, 'r') as f:
        return f.read()

# DEFENSE IN DEPTH:
1. NEVER exec()/eval() LLM output directly
2. NEVER render LLM HTML without sanitization
3. NEVER pass LLM output to shell commands
4. NEVER use LLM output in SQL without validation
5. NEVER trust LLM file paths
6. Always validate, sanitize, and restrict LLM output
7. Use sandboxing for code execution
8. Whitelist allowed operations
9. Set timeouts and resource limits
10. Log all LLM output usage for monitoring

NEVER DO:
- exec(llm_response)
- eval(llm_response)
- os.system(llm_response)
- cursor.execute(llm_response)
- render_template(message=llm_response|safe)
- open(llm_response)
- subprocess.call(llm_response, shell=True)

Reference: OWASP LLM02 - Insecure Output Handling
"""


class InsecureOutputDetector:
    """
    Detects insecure handling of LLM outputs.

    Critical: LLM output is UNTRUSTED and must be validated.
    """

    # LLM response indicators
    LLM_RESPONSE_VARS = {
        'response', 'output', 'result', 'completion',
        'answer', 'reply', 'generated', 'llm_output'
    }

    # Dangerous functions that should NEVER receive LLM output
    DANGEROUS_FUNCTIONS = {
        'exec': 'code_execution',
        'eval': 'code_execution',
        'compile': 'code_execution',
        '__import__': 'code_execution',
        'os.system': 'command_injection',
        'os.popen': 'command_injection',
        'subprocess.call': 'command_injection',
        'subprocess.run': 'command_injection',
        'subprocess.Popen': 'command_injection',
        'cursor.execute': 'sql_injection',
        'connection.execute': 'sql_injection',
        'open': 'file_access',
        'render_template': 'xss',
        'mark_safe': 'xss',
        'Markup': 'xss',
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_insecure_output(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_insecure_output(self, content: str, file_path: str) -> List[InsecureOutputFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        # Track LLM response variables
        llm_vars = set()

        for node in ast.walk(tree):
            # Track assignments from LLM calls
            if isinstance(node, ast.Assign):
                if self._is_llm_call(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            llm_vars.add(target.id)

            # Check dangerous function calls
            if isinstance(node, ast.Call):
                finding = self._check_dangerous_call(node, content, llm_vars)
                if finding:
                    findings.append(finding)

        return findings

    def _check_dangerous_call(self, node: ast.Call, content: str, llm_vars: set) -> InsecureOutputFinding:
        """Check if dangerous function is called with LLM output."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check if it's a dangerous function
        danger_type = None
        for dangerous, dtype in self.DANGEROUS_FUNCTIONS.items():
            if dangerous in func_name or func_name.endswith(dangerous.split('.')[-1]):
                danger_type = dtype
                break

        if not danger_type:
            return None

        # Check if arguments contain LLM output
        llm_source = None
        for arg in node.args:
            var_name = self._get_variable_name(arg)
            if var_name:
                if var_name in llm_vars or self._is_llm_response_var(var_name):
                    llm_source = var_name
                    break

        if not llm_source:
            # Check keyword arguments
            for keyword in node.keywords:
                var_name = self._get_variable_name(keyword.value)
                if var_name and (var_name in llm_vars or self._is_llm_response_var(var_name)):
                    llm_source = var_name
                    break

        if llm_source:
            severity_map = {
                'code_execution': 'BLOCKER',
                'command_injection': 'CRITICAL',
                'sql_injection': 'CRITICAL',
                'file_access': 'HIGH',
                'xss': 'HIGH'
            }

            return InsecureOutputFinding(
                line=node.lineno,
                column=node.col_offset,
                code_snippet=ast.get_source_segment(content, node)[:200] or '',
                severity=severity_map.get(danger_type, 'HIGH'),
                confidence=90,
                description=f'Insecure output: LLM response used in {func_name}()',
                output_usage=danger_type,
                dangerous_function=func_name,
                llm_source=llm_source
            )

        return None

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[InsecureOutputFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: exec/eval with LLM response
        exec_pattern = re.compile(
            r'(exec|eval)\s*\(\s*(?:response|output|result|llm|generated)',
            re.IGNORECASE
        )

        # Pattern 2: os.system with LLM response
        system_pattern = re.compile(
            r'os\.system\s*\(\s*(?:response|output|result|command)',
            re.IGNORECASE
        )

        # Pattern 3: SQL execute with LLM response
        sql_pattern = re.compile(
            r'(?:execute|query)\s*\(\s*(?:response|output|sql|query)',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for exec/eval
            if exec_pattern.search(line):
                findings.append(InsecureOutputFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='BLOCKER',
                    confidence=95,
                    description='CRITICAL: exec()/eval() with LLM output',
                    output_usage='code_execution',
                    dangerous_function='exec/eval',
                    llm_source='llm_response'
                ))

            # Check for os.system
            if system_pattern.search(line):
                findings.append(InsecureOutputFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=90,
                    description='Command injection: os.system() with LLM output',
                    output_usage='command_injection',
                    dangerous_function='os.system',
                    llm_source='llm_response'
                ))

            # Check for SQL execute
            if sql_pattern.search(line):
                findings.append(InsecureOutputFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=85,
                    description='SQL injection: execute() with LLM output',
                    output_usage='sql_injection',
                    dangerous_function='execute',
                    llm_source='llm_response'
                ))

        return findings

    def _is_llm_call(self, node) -> bool:
        """Check if node is an LLM API call."""
        if not isinstance(node, ast.Call):
            return False

        func_name = self._get_function_name(node)
        if not func_name:
            return False

        llm_indicators = [
            'openai', 'anthropic', 'claude', 'gpt', 'llm',
            'generate', 'complete', 'chat', 'create'
        ]

        return any(indicator in func_name.lower() for indicator in llm_indicators)

    def _get_function_name(self, node: ast.Call) -> str:
        """Get function name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.insert(0, current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.insert(0, current.id)
            return '.'.join(parts)
        return ''

    def _get_variable_name(self, node) -> str:
        """Get variable name from node."""
        if isinstance(node, ast.Name):
            return node.id
        return ''

    def _is_llm_response_var(self, var_name: str) -> bool:
        """Check if variable name indicates LLM response."""
        var_lower = var_name.lower()
        return any(indicator in var_lower for indicator in self.LLM_RESPONSE_VARS)
