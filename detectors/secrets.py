"""
Module: secrets.py
Author: Code Archaeologist Team
Purpose: Detect hardcoded secrets and credentials in source code.

This detector finds secrets that AI commonly hardcodes:
- API keys (AWS, Stripe, OpenAI, etc.)
- Database passwords
- Encryption keys
- Private keys
- Access tokens

Uses multiple detection methods:
- Regex patterns for known formats
- Entropy analysis for random-looking strings
- Variable name analysis
- Context awareness

CRITICAL: Max 400 lines per CLAUDE.md standards.
"""

import ast
import re
import math
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass


@dataclass
class SecretFinding:
    """A detected hardcoded secret."""
    pattern_id: str
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    secret_type: str
    fix_suggestion: str


class SecretsDetector:
    """
    Detects hardcoded secrets and credentials in source code.

    Uses multiple detection strategies for high accuracy.
    """

    # Regex patterns for known secret formats
    SECRET_PATTERNS = {
        'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'aws_secret_key': re.compile(r'[A-Za-z0-9/+=]{40}'),
        'github_token': re.compile(r'ghp_[a-zA-Z0-9]{36}'),
        'gitlab_token': re.compile(r'glpat-[a-zA-Z0-9\-]{20}'),
        'stripe_key': re.compile(r'sk_live_[a-zA-Z0-9]{24,}'),
        'openai_key': re.compile(r'sk-proj-[a-zA-Z0-9]{48,}'),
        'slack_webhook': re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        'private_key_header': re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
        'jwt_pattern': re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
    }

    # Variable names that indicate secrets
    SECRET_VARIABLE_NAMES = {
        'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
        'access_token', 'auth_token', 'private_key', 'secret_key',
        'aws_secret', 'db_password', 'database_password', 'encryption_key',
        'client_secret', 'app_secret', 'master_key', 'jwt_secret'
    }

    # Minimum entropy for random-looking strings (bits per character)
    ENTROPY_THRESHOLD = 4.5

    # Minimum string length to analyze for entropy
    MIN_STRING_LENGTH = 16

    def __init__(self):
        """Initialize the secrets detector."""
        self.findings: List[SecretFinding] = []

    def detect(
        self,
        source_code: str,
        file_path: str
    ) -> List[SecretFinding]:
        """
        Detect hardcoded secrets in source code.

        Args:
            source_code: Python source code to analyze
            file_path: Path to the file being analyzed

        Returns:
            List of secret findings
        """
        self.findings = []

        try:
            tree = ast.parse(source_code)
            self._analyze_ast(tree, source_code)
        except SyntaxError:
            return self.findings

        return self.findings

    def _analyze_ast(self, tree: ast.AST, source_code: str) -> None:
        """
        Analyze the AST for hardcoded secrets.

        Args:
            tree: AST of the source code
            source_code: Original source code for context
        """
        for node in ast.walk(tree):
            # Check variable assignments
            if isinstance(node, ast.Assign):
                self._check_assignment(node, source_code)

            # Check function call arguments (boto3.client('s3', aws_access_key_id=...))
            if isinstance(node, ast.Call):
                self._check_function_call(node, source_code)

            # Check dictionary literals (config = {'password': '...'})
            if isinstance(node, ast.Dict):
                self._check_dict_literal(node, source_code)

    def _check_assignment(
        self,
        node: ast.Assign,
        source_code: str
    ) -> None:
        """
        Check variable assignments for secrets.

        Pattern: SECRET_KEY = "hardcoded_value"
        """
        if not node.targets:
            return

        target = node.targets[0]
        variable_name = self._get_variable_name(target)

        if not variable_name:
            return

        # Check if variable name indicates a secret
        is_secret_name = self._is_secret_variable_name(variable_name)

        # Check the assigned value
        if isinstance(node.value, ast.Constant):
            value = node.value.value

            if isinstance(value, str):
                # Method 1: Regex pattern matching
                secret_type, pattern_id = self._match_secret_pattern(value)

                if secret_type:
                    self._add_finding(
                        pattern_id=pattern_id,
                        node=node,
                        source_code=source_code,
                        secret_type=secret_type,
                        variable_name=variable_name,
                        confidence=95
                    )
                    return

                # Method 2: High entropy strings with secret variable names
                if is_secret_name and len(value) >= self.MIN_STRING_LENGTH:
                    entropy = self._calculate_entropy(value)

                    if entropy >= self.ENTROPY_THRESHOLD:
                        self._add_finding(
                            pattern_id=self._get_pattern_id_for_name(variable_name),
                            node=node,
                            source_code=source_code,
                            secret_type=self._infer_secret_type(variable_name),
                            variable_name=variable_name,
                            confidence=85
                        )
                        return

                # Method 3: Suspicious variable names with non-empty values
                if is_secret_name and len(value) > 8:
                    self._add_finding(
                        pattern_id=self._get_pattern_id_for_name(variable_name),
                        node=node,
                        source_code=source_code,
                        secret_type=self._infer_secret_type(variable_name),
                        variable_name=variable_name,
                        confidence=75
                    )

    def _check_function_call(
        self,
        node: ast.Call,
        source_code: str
    ) -> None:
        """
        Check function call arguments for hardcoded secrets.

        Pattern: boto3.client('s3', aws_access_key_id='AKIA...')
        """
        # Check keyword arguments
        for keyword in node.keywords:
            arg_name = keyword.arg

            # Safety check: arg_name can be None for **kwargs
            if not arg_name:
                continue

            if self._is_secret_variable_name(arg_name):
                if isinstance(keyword.value, ast.Constant):
                    value = keyword.value.value

                    if isinstance(value, str) and len(value) > 8:
                        secret_type, pattern_id = self._match_secret_pattern(value)

                        if not secret_type:
                            pattern_id = self._get_pattern_id_for_name(arg_name)
                            secret_type = self._infer_secret_type(arg_name)

                        self._add_finding(
                            pattern_id=pattern_id,
                            node=keyword.value,
                            source_code=source_code,
                            secret_type=secret_type,
                            variable_name=arg_name,
                            confidence=90
                        )

    def _check_dict_literal(
        self,
        node: ast.Dict,
        source_code: str
    ) -> None:
        """
        Check dictionary literals for secrets.

        Pattern: {'password': 'hardcoded123'}
        """
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant):
                key_str = str(key.value).lower()

                if self._is_secret_variable_name(key_str):
                    if isinstance(value, ast.Constant):
                        val_str = value.value

                        if isinstance(val_str, str) and len(val_str) > 8:
                            secret_type, pattern_id = self._match_secret_pattern(val_str)

                            if not secret_type:
                                pattern_id = self._get_pattern_id_for_name(key_str)
                                secret_type = self._infer_secret_type(key_str)

                            self._add_finding(
                                pattern_id=pattern_id,
                                node=value,
                                source_code=source_code,
                                secret_type=secret_type,
                                variable_name=key_str,
                                confidence=85
                            )

    def _match_secret_pattern(self, value: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Match string against known secret patterns.

        Args:
            value: String to check

        Returns:
            Tuple of (secret_type, pattern_id) or (None, None)
        """
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            if pattern.search(value):
                pattern_id = self._get_pattern_id_for_type(secret_type)
                return secret_type, pattern_id

        return None, None

    def _is_secret_variable_name(self, name: str) -> bool:
        """
        Check if variable name indicates a secret.

        Args:
            name: Variable name to check

        Returns:
            True if name indicates a secret
        """
        # Safety check: handle None or empty names
        if not name:
            return False

        name_lower = name.lower().replace('_', '').replace('-', '')

        for secret_name in self.SECRET_VARIABLE_NAMES:
            clean_secret = secret_name.replace('_', '').replace('-', '')
            if clean_secret in name_lower:
                return True

        return False

    def _calculate_entropy(self, s: str) -> float:
        """
        Calculate Shannon entropy of a string.

        High entropy indicates random-looking strings (likely secrets).

        Args:
            s: String to analyze

        Returns:
            Entropy in bits per character
        """
        if not s:
            return 0.0

        # Count character frequencies
        frequencies = {}
        for char in s:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        length = len(s)

        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _get_variable_name(self, node: ast.AST) -> Optional[str]:
        """Get variable name from assignment target."""
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _infer_secret_type(self, variable_name: str) -> str:
        """Infer secret type from variable name."""
        name_lower = variable_name.lower()

        if 'aws' in name_lower:
            return 'aws_credentials'
        elif 'password' in name_lower or 'passwd' in name_lower:
            return 'password'
        elif 'api' in name_lower or 'key' in name_lower:
            return 'api_key'
        elif 'token' in name_lower:
            return 'access_token'
        elif 'private' in name_lower:
            return 'private_key'
        else:
            return 'secret'

    def _get_pattern_id_for_name(self, variable_name: str) -> str:
        """Get pattern ID based on variable name."""
        secret_type = self._infer_secret_type(variable_name)
        return self._get_pattern_id_for_type(secret_type)

    def _get_pattern_id_for_type(self, secret_type: str) -> str:
        """Get pattern ID for a secret type."""
        type_to_id = {
            'aws_access_key': 'SECRET_001',
            'aws_secret_key': 'SECRET_001',
            'aws_credentials': 'SECRET_001',
            'password': 'SECRET_002',
            'database_password': 'SECRET_002',
            'api_key': 'SECRET_003',
            'stripe_key': 'SECRET_003',
            'openai_key': 'SECRET_004',
            'github_token': 'SECRET_009',
            'gitlab_token': 'SECRET_022',
            'private_key': 'SECRET_011',
            'slack_webhook': 'SECRET_010',
            'access_token': 'SECRET_009',
            'secret': 'SECRET_020',
        }

        return type_to_id.get(secret_type, 'SECRET_GENERIC')

    def _add_finding(
        self,
        pattern_id: str,
        node: ast.AST,
        source_code: str,
        secret_type: str,
        variable_name: str,
        confidence: int
    ) -> None:
        """Add a secret finding to the results."""
        code_snippet = ast.get_source_segment(source_code, node)

        # Mask the secret in the snippet
        if code_snippet and '=' in code_snippet:
            parts = code_snippet.split('=', 1)
            code_snippet = f"{parts[0]}= '***REDACTED***'"

        finding = SecretFinding(
            pattern_id=pattern_id,
            line=node.lineno,
            column=node.col_offset,
            code_snippet=code_snippet or f"{variable_name} = '***REDACTED***'",
            severity="CRITICAL" if confidence >= 90 else "HIGH",
            confidence=confidence,
            description=f"Hardcoded {secret_type} in source code",
            secret_type=secret_type,
            fix_suggestion=(
                f"Move {variable_name} to environment variables:\n"
                f"import os\n"
                f"{variable_name} = os.getenv('{variable_name.upper()}')"
            )
        )

        self.findings.append(finding)
