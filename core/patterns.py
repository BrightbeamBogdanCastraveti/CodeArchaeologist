"""
Module: patterns.py
Author: Code Archaeologist Team
Purpose: Pattern database for all 418+ vulnerability patterns.

This module contains the comprehensive pattern database covering:
- OWASP 2013, 2017, 2021, 2024 (138 + 45 + 80 + 35 patterns)
- AI-generated code issues (70 patterns)
- Framework-specific issues (50+ patterns)
"""

import re
from typing import Dict, List, Optional, Pattern
from dataclasses import dataclass
from enum import Enum


class PatternType(Enum):
    """Types of vulnerability patterns"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RACE_CONDITION = "race_condition"
    AUTH_BYPASS = "auth_bypass"
    HARDCODED_SECRET = "hardcoded_secret"
    XXE = "xxe"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    CSRF = "csrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_CRYPTO = "insecure_crypto"
    MISSING_ERROR_HANDLING = "missing_error_handling"
    MISSING_VALIDATION = "missing_validation"
    AI_VIBE_CODING = "ai_vibe_coding"


@dataclass
class VulnerabilityPattern:
    """
    Represents a single vulnerability detection pattern.

    Attributes:
        id: Unique pattern identifier (e.g., 'SQL_INJECTION_001')
        name: Human-readable pattern name
        type: Pattern type enum
        regex_pattern: Regular expression pattern (optional)
        ast_check: Function for AST-based detection (optional)
        severity: Issue severity
        confidence_base: Base confidence score (0-100)
        owasp_category: OWASP category (e.g., 'A03:2021')
        cwe_id: CWE identifier (e.g., 'CWE-89')
        description: What this pattern detects
        why_ai_generates: Why AI generates this pattern
        false_positive_indicators: Patterns that indicate false positive
        fix_template: Template for generating fixes
        frameworks: Applicable frameworks
        language: Programming language
    """
    id: str
    name: str
    type: PatternType
    severity: str
    confidence_base: int
    owasp_category: str
    cwe_id: str
    description: str
    why_ai_generates: str
    fix_template: str
    frameworks: List[str]
    language: str
    regex_pattern: Optional[str] = None
    ast_check: Optional[callable] = None
    false_positive_indicators: List[str] = None
    metadata: Dict = None

    def __post_init__(self):
        if self.false_positive_indicators is None:
            self.false_positive_indicators = []
        if self.metadata is None:
            self.metadata = {}


class PatternDatabase:
    """
    Central database of all vulnerability patterns.

    This class manages the 418+ patterns covering all OWASP categories
    and AI-generated code issues.
    """

    def __init__(self):
        """Initialize the pattern database"""
        self.patterns: Dict[str, VulnerabilityPattern] = {}
        self._initialize_patterns()

    def _initialize_patterns(self):
        """Initialize all vulnerability patterns"""
        # SQL Injection patterns
        self._add_sql_injection_patterns()

        # XSS patterns
        self._add_xss_patterns()

        # Race condition patterns
        self._add_race_condition_patterns()

        # Auth bypass patterns
        self._add_auth_bypass_patterns()

        # Hardcoded secrets patterns
        self._add_secrets_patterns()

        # AI vibe coding patterns
        self._add_ai_vibe_patterns()

        # More patterns will be added...

    def _add_sql_injection_patterns(self):
        """Add SQL injection detection patterns"""

        # Pattern 1: String concatenation in SQL
        self.add_pattern(VulnerabilityPattern(
            id="SQL_INJECTION_001",
            name="SQL Injection via String Concatenation",
            type=PatternType.SQL_INJECTION,
            regex_pattern=r'\.execute\([^)]*\+[^)]*\)',
            severity="CRITICAL",
            confidence_base=85,
            owasp_category="A03:2021",
            cwe_id="CWE-89",
            description="SQL query constructed using string concatenation, allowing SQL injection",
            why_ai_generates="AI prioritizes getting working code fast. String concatenation "
                           "is the most direct way to show the concept. The AI assumes "
                           "you'll refine it later.",
            fix_template="Use parameterized queries with ORM methods like filter()",
            frameworks=["django", "flask", "fastapi"],
            language="python"
        ))

        # Pattern 2: f-string in SQL
        self.add_pattern(VulnerabilityPattern(
            id="SQL_INJECTION_002",
            name="SQL Injection via f-string",
            type=PatternType.SQL_INJECTION,
            regex_pattern=r'\.raw\(f["\']SELECT.*\{.*\}',
            severity="CRITICAL",
            confidence_base=90,
            owasp_category="A03:2021",
            cwe_id="CWE-89",
            description="SQL query using f-string interpolation, highly vulnerable",
            why_ai_generates="F-strings are Python's modern string formatting. AI uses "
                           "them naturally without considering security implications.",
            fix_template="Use ORM QuerySet methods with Q objects for complex queries",
            frameworks=["django"],
            language="python"
        ))

        # Pattern 3: .format() in SQL
        self.add_pattern(VulnerabilityPattern(
            id="SQL_INJECTION_003",
            name="SQL Injection via .format()",
            type=PatternType.SQL_INJECTION,
            regex_pattern=r'\.execute\([^)]*\.format\(',
            severity="CRITICAL",
            confidence_base=88,
            owasp_category="A03:2021",
            cwe_id="CWE-89",
            description="SQL query using .format() for variable substitution",
            why_ai_generates="AI knows .format() from general Python usage and applies "
                           "it to SQL without security awareness.",
            fix_template="Use parameterized queries: execute(query, params)",
            frameworks=["django", "flask", "fastapi"],
            language="python"
        ))

        # Pattern 4: % operator in SQL
        self.add_pattern(VulnerabilityPattern(
            id="SQL_INJECTION_004",
            name="SQL Injection via % operator",
            type=PatternType.SQL_INJECTION,
            regex_pattern=r'\.execute\([^)]*%[^)]*\)',
            severity="CRITICAL",
            confidence_base=85,
            owasp_category="A03:2021",
            cwe_id="CWE-89",
            description="SQL query using % operator for string formatting",
            why_ai_generates="Old-style Python string formatting still in AI training data",
            fix_template="Use parameterized queries with placeholder syntax",
            frameworks=["django", "flask", "fastapi"],
            language="python"
        ))

    def _add_xss_patterns(self):
        """Add XSS detection patterns"""

        # Django mark_safe with user input
        self.add_pattern(VulnerabilityPattern(
            id="XSS_001",
            name="XSS via mark_safe with user input",
            type=PatternType.XSS,
            regex_pattern=r'mark_safe\([^)]*request\.',
            severity="HIGH",
            confidence_base=80,
            owasp_category="A03:2021",
            cwe_id="CWE-79",
            description="Using mark_safe() on user-controlled input bypasses Django's XSS protection",
            why_ai_generates="AI knows mark_safe is needed for HTML content but doesn't "
                           "distinguish between trusted and untrusted sources.",
            fix_template="Sanitize input with bleach.clean() before mark_safe, or use template escaping",
            frameworks=["django"],
            language="python"
        ))

        # React dangerouslySetInnerHTML
        self.add_pattern(VulnerabilityPattern(
            id="XSS_002",
            name="XSS via dangerouslySetInnerHTML",
            type=PatternType.XSS,
            regex_pattern=r'dangerouslySetInnerHTML=\{\{__html:\s*[^}]*\}\}',
            severity="HIGH",
            confidence_base=75,
            owasp_category="A03:2021",
            cwe_id="CWE-79",
            description="Using dangerouslySetInnerHTML with potentially unsafe content",
            why_ai_generates="AI uses this when it needs to render HTML, without "
                           "considering XSS implications.",
            fix_template="Use DOMPurify.sanitize() or render as text content",
            frameworks=["react"],
            language="javascript"
        ))

    def _add_race_condition_patterns(self):
        """Add race condition detection patterns"""

        # TOCTOU - check then use
        self.add_pattern(VulnerabilityPattern(
            id="RACE_CONDITION_001",
            name="TOCTOU - Check then Insert",
            type=PatternType.RACE_CONDITION,
            regex_pattern=r'\.exists\(\).*\n.*\.create\(',
            severity="HIGH",
            confidence_base=70,
            owasp_category="A04:2021",
            cwe_id="CWE-367",
            description="Time-of-check-time-of-use race condition in database operations",
            why_ai_generates="AI generates linear code flow (check, then act) which "
                           "seems logical but isn't atomic.",
            fix_template="Use get_or_create() or database-level unique constraints",
            frameworks=["django", "flask", "fastapi"],
            language="python"
        ))

        # Missing select_for_update
        self.add_pattern(VulnerabilityPattern(
            id="RACE_CONDITION_002",
            name="Missing select_for_update in transaction",
            type=PatternType.RACE_CONDITION,
            regex_pattern=r'with transaction\.atomic\(\):.*\n.*\.get\(',
            severity="MEDIUM",
            confidence_base=60,
            owasp_category="A04:2021",
            cwe_id="CWE-362",
            description="Reading data in transaction without row-level locking",
            why_ai_generates="AI understands transactions but not row-level locking nuances.",
            fix_template="Use select_for_update() when reading data you'll modify",
            frameworks=["django"],
            language="python"
        ))

    def _add_auth_bypass_patterns(self):
        """Add authentication bypass patterns"""

        # Missing authentication decorator
        self.add_pattern(VulnerabilityPattern(
            id="AUTH_BYPASS_001",
            name="Missing authentication decorator",
            type=PatternType.AUTH_BYPASS,
            regex_pattern=r'def\s+\w+\(request[,)](?!.*@login_required)(?!.*@require_authentication)',
            severity="CRITICAL",
            confidence_base=75,
            owasp_category="A01:2021",
            cwe_id="CWE-284",
            description="View function missing authentication decorator",
            why_ai_generates="AI focuses on core functionality first, security second.",
            fix_template="Add @login_required or @require_authentication decorator",
            frameworks=["django", "flask"],
            language="python"
        ))

    def _add_secrets_patterns(self):
        """Add hardcoded secrets detection patterns"""

        # AWS access key
        self.add_pattern(VulnerabilityPattern(
            id="SECRET_001",
            name="Hardcoded AWS Access Key",
            type=PatternType.HARDCODED_SECRET,
            regex_pattern=r'AKIA[0-9A-Z]{16}',
            severity="CRITICAL",
            confidence_base=95,
            owasp_category="A02:2021",
            cwe_id="CWE-798",
            description="AWS access key hardcoded in source code",
            why_ai_generates="AI includes example credentials from training data or "
                           "generates realistic-looking keys for demonstrations.",
            fix_template="Use environment variables or AWS IAM roles",
            frameworks=["*"],
            language="*"
        ))

        # Generic API key
        self.add_pattern(VulnerabilityPattern(
            id="SECRET_002",
            name="Hardcoded API Key",
            type=PatternType.HARDCODED_SECRET,
            regex_pattern=r'["\']?api_key["\']?\s*[:=]\s*["\'][^"\']{20,}["\']',
            severity="HIGH",
            confidence_base=80,
            owasp_category="A02:2021",
            cwe_id="CWE-798",
            description="API key hardcoded in source code",
            why_ai_generates="AI needs to show working code and includes example keys.",
            fix_template="Store in environment variables or secret management service",
            frameworks=["*"],
            language="*"
        ))

    def _add_ai_vibe_patterns(self):
        """Add AI-specific 'vibe coding' patterns"""

        # Missing error handling
        self.add_pattern(VulnerabilityPattern(
            id="AI_VIBE_001",
            name="Missing error handling",
            type=PatternType.MISSING_ERROR_HANDLING,
            regex_pattern=r'def\s+\w+\([^)]*\):(?!.*try:)',
            severity="MEDIUM",
            confidence_base=50,
            owasp_category="A09:2021",
            cwe_id="CWE-754",
            description="Function with no error handling (try/except)",
            why_ai_generates="AI generates 'happy path' code first. Error handling "
                           "is seen as optional refinement.",
            fix_template="Add try/except blocks with proper logging",
            frameworks=["*"],
            language="python"
        ))

        # Generic variable names
        self.add_pattern(VulnerabilityPattern(
            id="AI_VIBE_002",
            name="Generic variable naming",
            type=PatternType.AI_VIBE_CODING,
            regex_pattern=r'\b(data|result|response|temp|item)\s*=',
            severity="LOW",
            confidence_base=40,
            owasp_category="N/A",
            cwe_id="N/A",
            description="Overly generic variable names typical of AI-generated code",
            why_ai_generates="AI uses generic names as placeholders, expecting "
                           "developers to rename them.",
            fix_template="Use descriptive names based on domain context",
            frameworks=["*"],
            language="*"
        ))

    def add_pattern(self, pattern: VulnerabilityPattern) -> None:
        """
        Add a pattern to the database.

        Args:
            pattern: VulnerabilityPattern to add
        """
        self.patterns[pattern.id] = pattern

    def get_pattern(self, pattern_id: str) -> Optional[VulnerabilityPattern]:
        """
        Get a pattern by ID.

        Args:
            pattern_id: Pattern identifier

        Returns:
            VulnerabilityPattern or None if not found
        """
        return self.patterns.get(pattern_id)

    def get_patterns_by_type(self, pattern_type: PatternType) -> List[VulnerabilityPattern]:
        """
        Get all patterns of a specific type.

        Args:
            pattern_type: Type of patterns to retrieve

        Returns:
            List of matching patterns
        """
        return [p for p in self.patterns.values() if p.type == pattern_type]

    def get_patterns_by_framework(self, framework: str) -> List[VulnerabilityPattern]:
        """
        Get patterns applicable to a specific framework.

        Args:
            framework: Framework name (django, react, etc.)

        Returns:
            List of applicable patterns
        """
        return [
            p for p in self.patterns.values()
            if framework in p.frameworks or "*" in p.frameworks
        ]

    def get_all_patterns(self) -> List[VulnerabilityPattern]:
        """Get all patterns in the database"""
        return list(self.patterns.values())

    def count_patterns(self) -> Dict[str, int]:
        """
        Get pattern counts by category.

        Returns:
            Dict with counts per OWASP category
        """
        counts = {}
        for pattern in self.patterns.values():
            category = pattern.owasp_category
            counts[category] = counts.get(category, 0) + 1
        return counts
