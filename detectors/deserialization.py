"""
Insecure Deserialization Detector (CWE-502)

Detects insecure deserialization vulnerabilities where untrusted data is
deserialized without proper validation, allowing remote code execution.

OWASP: A08:2021 - Software and Data Integrity Failures
Research: AI-generated code frequently uses pickle/yaml unsafely
Training Era: 2010-2020 (StackOverflow examples prioritized convenience)

Attack Vector:
    User input: Malicious pickled object
    Code: pickle.loads(user_data)
    Result: Remote code execution, full system compromise

AI Training Paradox:
    StackOverflow (2010-2015) examples showed pickle/yaml without warnings
    "How to serialize Python objects?" → "Use pickle.dumps/loads"
    AI learned: "pickle is the standard Python serialization format"
    Reality: pickle is NEVER safe for untrusted data
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass

try:
    from analysis_engine.research.academic_validation import (
        get_cwe_research,
        explain_why_ai_generates
    )
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False


@dataclass
class DeserializationFinding:
    """A detected insecure deserialization vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    deserialization_function: str
    user_variable: str
    cwe_id: str = "CWE-502"
    owasp_category: str = "A08:2021 - Software and Data Integrity Failures"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'deserialization_function': self.deserialization_function,
            'user_variable': self.user_variable,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2010-2020'
            result['why_ai_generates'] = explain_why_ai_generates('CWE-502')

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:
```python
import pickle
import yaml
import json

# VULNERABLE: pickle with user input
import pickle
data = request.body
obj = pickle.loads(data)  # RCE vulnerability!

# SAFE: Never use pickle with untrusted data. Use JSON instead:
import json
data = request.body
obj = json.loads(data)  # Safe - can only deserialize JSON primitives

# VULNERABLE: yaml.load (unsafe)
import yaml
config = request.POST.get('config')
data = yaml.load(config)  # RCE vulnerability!

# SAFE: Use safe_load
import yaml
config = request.POST.get('config')
data = yaml.safe_load(config)  # Safe - restricted to simple types

# VULNERABLE: eval with user input
user_code = request.GET.get('code')
result = eval(user_code)  # Arbitrary code execution!

# SAFE: Use ast.literal_eval for safe evaluation
import ast
user_code = request.GET.get('code')
result = ast.literal_eval(user_code)  # Only evaluates literals

# VULNERABLE: exec with user input
user_script = request.body
exec(user_script)  # Complete system compromise!

# SAFE: Don't use exec. If you must evaluate code, use a sandbox:
from RestrictedPython import compile_restricted
code = compile_restricted(user_script, '<string>', 'exec')
# Even better: redesign to avoid dynamic code execution

# SAFE PATTERNS FOR SERIALIZATION:
# 1. Use JSON for simple data
import json
data = json.dumps({'key': 'value'})
obj = json.loads(data)

# 2. Use MessagePack for binary efficiency
import msgpack
data = msgpack.packb({'key': 'value'})
obj = msgpack.unpackb(data)

# 3. Use Protocol Buffers for structured data
# Define schema, use generated code

# 4. If you MUST use pickle (internal data only):
import pickle
import hmac
import hashlib

SECRET_KEY = os.environ['PICKLE_SECRET_KEY']

def secure_pickle_dumps(obj):
    data = pickle.dumps(obj)
    signature = hmac.new(SECRET_KEY.encode(), data, hashlib.sha256).digest()
    return signature + data

def secure_pickle_loads(signed_data):
    signature = signed_data[:32]
    data = signed_data[32:]
    expected_sig = hmac.new(SECRET_KEY.encode(), data, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("Invalid signature")
    return pickle.loads(data)
```

NEVER USE:
- pickle.loads() with untrusted data
- yaml.load() (use yaml.safe_load())
- eval() or exec() with user input
- marshal.loads() with untrusted data
- shelve with untrusted keys

Reference: OWASP Deserialization Cheat Sheet
"""


class DeserializationDetector:
    """
    Detects insecure deserialization vulnerabilities.

    High-risk functions:
    - pickle.loads(), pickle.load()
    - yaml.load() (without SafeLoader)
    - eval(), exec()
    - marshal.loads()
    """

    # Dangerous deserialization functions
    DANGEROUS_FUNCTIONS = {
        'pickle.loads',
        'pickle.load',
        'yaml.load',
        'yaml.unsafe_load',
        'marshal.loads',
        'marshal.load',
        'jsonpickle.decode',
        'dill.loads',
        'shelve.open',
    }

    # Code execution functions
    CODE_EXEC_FUNCTIONS = {
        'eval',
        'exec',
        'compile',
        '__import__',
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_deserialization(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_deserialization(self, content: str, file_path: str) -> List[DeserializationFinding]:
        """AST-based detection."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_deserialization_call(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_deserialization_call(self, node: ast.Call, content: str) -> DeserializationFinding:
        """Check if this is a dangerous deserialization call."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check for dangerous deserialization functions
        is_dangerous_deser = any(
            func_name.endswith(dangerous.split('.')[-1])
            for dangerous in self.DANGEROUS_FUNCTIONS
        )

        # Check for code execution functions
        is_code_exec = any(
            func_name == exec_func or func_name.endswith(f'.{exec_func}')
            for exec_func in self.CODE_EXEC_FUNCTIONS
        )

        if not (is_dangerous_deser or is_code_exec):
            return None

        # Special case: yaml.safe_load is OK
        if 'safe_load' in func_name:
            return None

        # Check for user input in arguments
        user_var = self._find_user_input(node)

        # yaml.load is dangerous even without obvious user input
        if 'yaml.load' in func_name or func_name.endswith('yaml.load'):
            # Check if SafeLoader is specified
            has_safe_loader = self._has_safe_loader(node)
            if not has_safe_loader:
                severity = 'CRITICAL' if user_var else 'HIGH'
                confidence = 95 if user_var else 80

                return DeserializationFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node) or '',
                    severity=severity,
                    confidence=confidence,
                    description=f'Unsafe YAML deserialization: {func_name}() without SafeLoader',
                    deserialization_function=func_name,
                    user_variable=user_var or 'no SafeLoader'
                )

        # pickle/marshal are CRITICAL with user input
        if any(dangerous in func_name for dangerous in ['pickle', 'marshal', 'dill']):
            if user_var:
                return DeserializationFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node) or '',
                    severity='BLOCKER',  # Highest severity - RCE
                    confidence=95,
                    description=f'Remote Code Execution: {func_name}() with user input',
                    deserialization_function=func_name,
                    user_variable=user_var
                )

        # eval/exec are CRITICAL with user input
        if is_code_exec and user_var:
            return DeserializationFinding(
                line=node.lineno,
                column=node.col_offset,
                code_snippet=ast.get_source_segment(content, node) or '',
                severity='BLOCKER',
                confidence=95,
                description=f'Arbitrary code execution: {func_name}() with user input',
                deserialization_function=func_name,
                user_variable=user_var
            )

        return None

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[DeserializationFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: pickle.loads with user input
        pickle_pattern = re.compile(
            r'pickle\.(loads?|load)\s*\([^)]*(?:request\.|input|data|body)',
            re.IGNORECASE
        )

        # Pattern 2: yaml.load without safe_load
        yaml_unsafe_pattern = re.compile(
            r'yaml\.load\s*\([^)]*\)',
            re.IGNORECASE
        )

        # Pattern 3: eval/exec with user input
        eval_pattern = re.compile(
            r'(eval|exec)\s*\([^)]*(?:request\.|input|user|args)',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for pickle with user input
            if pickle_pattern.search(line):
                findings.append(DeserializationFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='BLOCKER',
                    confidence=90,
                    description='Remote Code Execution: pickle with user input',
                    deserialization_function='pickle.loads',
                    user_variable='user_input'
                ))

            # Check for unsafe yaml.load
            if yaml_unsafe_pattern.search(line):
                # Skip if safe_load is used
                if 'safe_load' not in line.lower() and 'safeloader' not in line.lower():
                    findings.append(DeserializationFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=85,
                        description='Unsafe YAML deserialization: use yaml.safe_load()',
                        deserialization_function='yaml.load',
                        user_variable='yaml.load'
                    ))

            # Check for eval/exec with user input
            if eval_pattern.search(line):
                findings.append(DeserializationFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='BLOCKER',
                    confidence=90,
                    description='Arbitrary code execution: eval/exec with user input',
                    deserialization_function='eval/exec',
                    user_variable='user_input'
                ))

        return findings

    def _get_function_name(self, node: ast.Call) -> str:
        """Get function name."""
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

        return ''

    def _check_for_user_input(self, node) -> str:
        """Check if node contains user input."""
        # Check for request.GET, request.POST, request.body
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                if node.value.id == 'request':
                    return f'request.{node.attr}'

        # Check for common input variable names
        if isinstance(node, ast.Name):
            if node.id in ['data', 'input', 'user_input', 'body', 'payload', 'content']:
                return node.id

        return ''

    def _has_safe_loader(self, node: ast.Call) -> bool:
        """Check if yaml.load has SafeLoader specified."""
        for keyword in node.keywords:
            if keyword.arg == 'Loader':
                if isinstance(keyword.value, ast.Attribute):
                    if 'Safe' in keyword.value.attr:
                        return True
        return False
