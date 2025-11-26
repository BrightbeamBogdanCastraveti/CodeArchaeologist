"""
Module: sql_injection.py
Author: Code Archaeologist Team
Purpose: Detect SQL injection vulnerabilities in Python code.

This detector finds SQL injection patterns that AI commonly generates:
- String concatenation in SQL queries
- f-string formatting with user input
- .format() method with unsanitized data
- % operator for SQL construction
- ORM raw() and extra() bypasses

ACADEMIC VALIDATION:
This detector is backed by peer-reviewed research:
"The Generative Code Security Crisis: Mapping Legacy OWASP Vulnerabilities
(2015-2025) Inherited by Large Language Models"

KEY RESEARCH FINDINGS:
- CWE-89 (SQL Injection): HIGH prevalence in AI-generated code
- Training era: 2005-2015 (string concatenation was dominant pattern)
- AI generates this because: parameterized queries less common in training data
- OWASP: A05:2025 - Injection (has been in Top 10 since 2015)

CRITICAL: Max 400 lines per CLAUDE.md standards.
"""

import ast
import re
import sys
import os
from typing import List, Optional, Set
from dataclasses import dataclass

# Add research directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'research'))
try:
    from analysis_engine.research.academic_validation import get_cwe_research, explain_why_ai_generates
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False

# from core.patterns import VulnerabilityPattern, PatternType
# from core.confidence import ConfidenceScorer
# from core.data_flow import DataFlowAnalyzer, TaintLevel


@dataclass
class SQLInjectionFinding:
    """
    A detected SQL injection vulnerability with academic research backing.

    This finding includes not just the vulnerability, but WHY AI generated it,
    backed by peer-reviewed research.
    """
    pattern_id: str
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    exploit_example: str
    fix_suggestion: str

    # Academic research backing (new fields)
    cwe_id: str = "CWE-89"
    training_era: str = "2005-2015"
    owasp_category: str = "A05:2025 - Injection"
    prevalence_vs_human: str = "High"
    academic_citation: str = "Page 9, Section IV.B"

    def get_research_explanation(self) -> str:
        """
        Generate research-backed explanation of why AI generated this vulnerability.

        Returns:
            Detailed explanation with academic citations
        """
        if not RESEARCH_AVAILABLE:
            return self.description

        try:
            explanation = explain_why_ai_generates(self.cwe_id)
            return explanation
        except:
            return self.description

    def get_full_report(self) -> str:
        """
        Generate complete report with vulnerability details AND research context.

        This makes Code Archaeologist unique - every finding explains the
        root cause in AI training data.
        """
        report = f"""
SQL INJECTION DETECTED ({self.cwe_id})
================================================================================
Location: Line {self.line}, Column {self.column}
Severity: {self.severity} | Confidence: {self.confidence}%
Pattern: {self.pattern_id}

VULNERABLE CODE:
{self.code_snippet}

DESCRIPTION:
{self.description}

EXPLOITATION EXAMPLE:
{self.exploit_example}

FIX SUGGESTION:
{self.fix_suggestion}

================================================================================
ACADEMIC RESEARCH VALIDATION
================================================================================
"""
        if RESEARCH_AVAILABLE:
            cwe_research = get_cwe_research(self.cwe_id)
            if cwe_research:
                report += f"""
PREVALENCE IN AI CODE: {cwe_research['prevalence']}
TRAINING ERA: {cwe_research['training_era']}
OWASP CATEGORY: {cwe_research['owasp_mapping']}

WHY AI GENERATES THIS VULNERABILITY:
{cwe_research['why_ai_generates']}

REAL-WORLD IMPACT:
{cwe_research.get('real_world_impact', 'See research paper')}

ACADEMIC SOURCE:
{cwe_research.get('academic_citation', 'The Generative Code Security Crisis (2025)')}
"""
        return report


class SQLInjectionDetector:
    """
    Detects SQL injection vulnerabilities using AST analysis and pattern matching.

    This detector is specialized for AI-generated code patterns where
    developers prioritize functionality over security.
    """

    # Regex patterns for SQL keywords
    SQL_KEYWORDS = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b',
        re.IGNORECASE
    )

    # Dangerous ORM methods that bypass parameterization
    DANGEROUS_ORM_METHODS = {
        'raw', 'extra', 'execute', 'executemany',
        'RawSQL', 'cursor.execute'
    }

    # User input sources (taint sources)
    USER_INPUT_SOURCES = {
        'request.GET', 'request.POST', 'request.DATA',
        'request.query_params', 'request.data', 'request.body',
        'request.form', 'request.args', 'request.values'
    }

    def __init__(self):
        """Initialize the SQL injection detector."""
        # self.confidence_scorer = ConfidenceScorer()
        # self.data_flow_analyzer = DataFlowAnalyzer()
        self.findings: List[SQLInjectionFinding] = []

    def detect(self, source_code: str, file_path: str) -> List[SQLInjectionFinding]:
        """
        Detect SQL injection vulnerabilities in source code.

        Args:
            source_code: Python source code to analyze
            file_path: Path to the file being analyzed

        Returns:
            List of SQL injection findings
        """
        self.findings = []

        try:
            tree = ast.parse(source_code)
            self._analyze_ast(tree, source_code)
        except SyntaxError as e:
            # Cannot analyze files with syntax errors
            return self.findings

        return self.findings

    def _analyze_ast(self, tree: ast.AST, source_code: str) -> None:
        """
        Analyze the AST for SQL injection patterns.

        Args:
            tree: AST of the source code
            source_code: Original source code for context
        """
        for node in ast.walk(tree):
            # Pattern 1: String concatenation with +
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                self._check_string_concatenation(node, source_code)

            # Pattern 2: f-strings (JoinedStr)
            if isinstance(node, ast.JoinedStr):
                self._check_fstring(node, source_code)

            # Pattern 3: .format() method
            if isinstance(node, ast.Call):
                self._check_format_method(node, source_code)
                self._check_dangerous_orm_methods(node, source_code)

            # Pattern 4: % operator formatting
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                self._check_percent_formatting(node, source_code)

    def _check_string_concatenation(
        self,
        node: ast.BinOp,
        source_code: str
    ) -> None:
        """
        Detect SQL injection via string concatenation.

        Pattern: "SELECT * FROM " + table_name
        """
        # Check if any operand is a string containing SQL
        left_is_sql = self._contains_sql(node.left)
        right_is_sql = self._contains_sql(node.right)

        if left_is_sql or right_is_sql:
            # Check if the other operand could be user input
            tainted = self._is_potentially_tainted(node.left) or \
                     self._is_potentially_tainted(node.right)

            if tainted or True:  # Conservative: flag all SQL concatenation
                code_snippet = ast.get_source_segment(source_code, node)

                finding = SQLInjectionFinding(
                    pattern_id="SQL_INJECTION_001",
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=code_snippet or "Unable to extract snippet",
                    severity="CRITICAL",
                    confidence=self._calculate_confidence(node, tainted),
                    description="SQL query constructed with string concatenation",
                    exploit_example="?param=' OR '1'='1",
                    fix_suggestion="Use parameterized queries or ORM methods"
                )

                self.findings.append(finding)

    def _check_fstring(self, node: ast.JoinedStr, source_code: str) -> None:
        """
        Detect SQL injection via f-strings.

        Pattern: f"SELECT * FROM {table}"
        """
        # Check if f-string contains SQL keywords
        has_sql = False
        has_variable = len(node.values) > 1  # f-strings with variables

        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if self.SQL_KEYWORDS.search(value.value):
                    has_sql = True
                    break

        if has_sql and has_variable:
            code_snippet = ast.get_source_segment(source_code, node)

            finding = SQLInjectionFinding(
                pattern_id="SQL_INJECTION_002",
                line=node.lineno,
                column=node.col_offset,
                code_snippet=code_snippet or "Unable to extract snippet",
                severity="CRITICAL",
                confidence=90,  # f-strings with SQL are highly suspicious
                description="SQL query constructed with f-string formatting",
                exploit_example="?id=1 OR 1=1",
                fix_suggestion="Use parameterized queries instead of f-strings"
            )

            self.findings.append(finding)

    def _check_format_method(self, node: ast.Call, source_code: str) -> None:
        """
        Detect SQL injection via .format() method.

        Pattern: "SELECT * FROM {}".format(table)
        """
        if not isinstance(node.func, ast.Attribute):
            return

        if node.func.attr != 'format':
            return

        # Check if the string being formatted contains SQL
        if isinstance(node.func.value, ast.Constant):
            if isinstance(node.func.value.value, str):
                if self.SQL_KEYWORDS.search(node.func.value.value):
                    code_snippet = ast.get_source_segment(source_code, node)

                    finding = SQLInjectionFinding(
                        pattern_id="SQL_INJECTION_003",
                        line=node.lineno,
                        column=node.col_offset,
                        code_snippet=code_snippet or "Unable to extract snippet",
                        severity="CRITICAL",
                        confidence=90,
                        description="SQL query constructed with .format() method",
                        exploit_example="?table=users WHERE 1=1--",
                        fix_suggestion="Use parameterized queries or ORM filter()"
                    )

                    self.findings.append(finding)

    def _check_percent_formatting(
        self,
        node: ast.BinOp,
        source_code: str
    ) -> None:
        """
        Detect SQL injection via % operator formatting.

        Pattern: "SELECT * FROM %s" % table
        """
        # Check if left side contains SQL
        if self._contains_sql(node.left):
            code_snippet = ast.get_source_segment(source_code, node)

            finding = SQLInjectionFinding(
                pattern_id="SQL_INJECTION_004",
                line=node.lineno,
                column=node.col_offset,
                code_snippet=code_snippet or "Unable to extract snippet",
                severity="CRITICAL",
                confidence=90,
                description="SQL query constructed with % operator formatting",
                exploit_example="?param=' OR '1'='1",
                fix_suggestion="Use parameterized queries with ? or %s placeholders"
            )

            self.findings.append(finding)

    def _check_dangerous_orm_methods(
        self,
        node: ast.Call,
        source_code: str
    ) -> None:
        """
        Detect dangerous ORM methods that bypass parameterization.

        Pattern: Model.objects.raw("SELECT...")
        """
        method_name = self._get_method_name(node)

        if method_name in self.DANGEROUS_ORM_METHODS:
            # Check if arguments contain variables (not just constants)
            has_variable_args = any(
                not isinstance(arg, ast.Constant)
                for arg in node.args
            )

            if has_variable_args or len(node.args) > 1:
                code_snippet = ast.get_source_segment(source_code, node)

                finding = SQLInjectionFinding(
                    pattern_id="SQL_INJECTION_ORM_BYPASS",
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=code_snippet or "Unable to extract snippet",
                    severity="HIGH",
                    confidence=85,
                    description=f"ORM bypass using {method_name}() with variables",
                    exploit_example="Use ORM filter() instead of raw SQL",
                    fix_suggestion=f"Avoid {method_name}() or use parameterized arguments"
                )

                self.findings.append(finding)

    def _contains_sql(self, node: ast.AST) -> bool:
        """
        Check if an AST node contains SQL keywords.

        Args:
            node: AST node to check

        Returns:
            True if node contains SQL keywords
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return bool(self.SQL_KEYWORDS.search(node.value))
        return False

    def _is_potentially_tainted(self, node: ast.AST) -> bool:
        """
        Check if a node could contain user input.

        Args:
            node: AST node to check

        Returns:
            True if node might be tainted by user input
        """
        # Check for request.GET, request.POST, etc.
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                if node.value.id == 'request':
                    return True

        # Check for function parameters (could be tainted)
        if isinstance(node, ast.Name):
            # Conservative: assume all variables might be tainted
            return True

        return False

    def _get_method_name(self, node: ast.Call) -> Optional[str]:
        """
        Extract method name from a Call node.

        Args:
            node: ast.Call node

        Returns:
            Method name or None
        """
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return None

    def _calculate_confidence(
        self,
        node: ast.AST,
        is_tainted: bool
    ) -> int:
        """
        Calculate confidence score for a finding.

        Args:
            node: AST node of the finding
            is_tainted: Whether the input is known to be tainted

        Returns:
            Confidence score (0-100)
        """
        base_score = 85  # High confidence for SQL concatenation

        if is_tainted:
            base_score = 95  # Very high if taint confirmed

        # Reduce confidence if in test files
        # (would need file path context)

        return min(base_score, 100)
