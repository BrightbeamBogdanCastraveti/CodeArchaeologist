"""
Module: race_conditions.py
Author: Code Archaeologist Team
Purpose: Detect race condition vulnerabilities in concurrent code.

This detector is UNIQUE and specialized for race conditions that AI
commonly generates in web applications. Most scanners miss these.

Key patterns detected:
- TOCTOU (Time-of-check Time-of-use)
- Missing select_for_update() in Django ORM
- Missing transaction.atomic()
- Concurrent counter increments without locking
- Double-booking scenarios
- Inventory overselling
- File system race conditions

CRITICAL: Max 400 lines per CLAUDE.md standards.
"""

import ast
import re
from typing import List, Optional, Set, Tuple
from dataclasses import dataclass

# from core.patterns import VulnerabilityPattern, PatternType


@dataclass
class RaceConditionFinding:
    """A detected race condition vulnerability."""
    pattern_id: str
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    race_scenario: str
    fix_suggestion: str
    cwe_id: str = "CWE-362"
    owasp_category: str = "A04:2021 - Insecure Design"

    def to_dict(self) -> dict:
        """Convert to dictionary format for scanner compatibility."""
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'race_scenario': self.race_scenario,
            'fix': self.fix_suggestion,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category
        }


class RaceConditionDetector:
    """
    Detects race condition vulnerabilities in concurrent Python code.

    This is a specialized detector that identifies patterns where
    concurrent access to shared resources can cause bugs.
    """

    # Django ORM query methods
    QUERY_METHODS = {
        'filter', 'get', 'all', 'exclude', 'exists',
        'count', 'first', 'last'
    }

    # Mutating operations
    MUTATING_OPERATIONS = {
        'create', 'update', 'save', 'delete',
        'bulk_create', 'bulk_update'
    }

    # File system operations
    FILE_OPERATIONS = {
        'open', 'os.path.exists', 'os.remove', 'os.rename',
        'pathlib.Path.exists', 'Path.unlink'
    }

    def __init__(self):
        """Initialize the race condition detector."""
        self.findings: List[RaceConditionFinding] = []
        self.current_function: Optional[str] = None

    def detect(
        self,
        source_code: str,
        file_path: str
    ) -> List[RaceConditionFinding]:
        """
        Detect race condition vulnerabilities in source code.

        Args:
            source_code: Python source code to analyze
            file_path: Path to the file being analyzed

        Returns:
            List of race condition findings
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
        Analyze the AST for race condition patterns.

        Args:
            tree: AST of the source code
            source_code: Original source code for context
        """
        # Analyze each function for race conditions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self.current_function = node.name
                self._analyze_function(node, source_code)

    def _analyze_function(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Analyze a function for race condition patterns.

        Args:
            func_node: Function definition AST node
            source_code: Source code for context
        """
        # Pattern 1: TOCTOU - Check then Create
        self._detect_toctou_pattern(func_node, source_code)

        # Pattern 2: Missing select_for_update()
        self._detect_missing_select_for_update(func_node, source_code)

        # Pattern 3: Missing transaction.atomic()
        self._detect_missing_transaction(func_node, source_code)

        # Pattern 4: Counter increment without atomicity
        self._detect_unsafe_counter_increment(func_node, source_code)

        # Pattern 5: File system TOCTOU
        self._detect_file_system_races(func_node, source_code)

    def _detect_toctou_pattern(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Detect TOCTOU (Time-of-Check Time-of-Use) pattern.

        Pattern:
            if not Model.objects.filter(...).exists():
                Model.objects.create(...)

        Race: Two threads both check, both see "doesn't exist", both create.
        """
        # Find if statements
        for node in ast.walk(func_node):
            if not isinstance(node, ast.If):
                continue

            # Check if condition uses .exists() or .count()
            if self._is_existence_check(node.test):
                # Check if body contains create operation
                if self._contains_create_operation(node.body):
                    code_snippet = ast.get_source_segment(source_code, node)

                    finding = RaceConditionFinding(
                        pattern_id="RACE_CONDITION_001",
                        line=node.lineno,
                        column=node.col_offset,
                        code_snippet=code_snippet or "Unable to extract snippet",
                        severity="HIGH",
                        confidence=85,
                        description="TOCTOU race condition: check-then-create pattern",
                        race_scenario=(
                            "Thread A: checks, doesn't exist\n"
                            "Thread B: checks, doesn't exist\n"
                            "Thread A: creates record\n"
                            "Thread B: creates duplicate!"
                        ),
                        fix_suggestion=(
                            "Use get_or_create() or wrap in transaction.atomic() "
                            "with select_for_update()"
                        )
                    )

                    self.findings.append(finding)

    def _detect_missing_select_for_update(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Detect queries followed by updates without locking.

        Pattern:
            obj = Model.objects.get(id=id)  # No lock!
            obj.counter += 1
            obj.save()

        Race: Two threads can read same value, both increment, one update lost.
        """
        # Find query operations followed by mutations
        statements = func_node.body
        for i in range(len(statements) - 1):
            current = statements[i]
            next_stmt = statements[i + 1]

            # Check if current is a query without select_for_update
            if self._is_query_without_lock(current):
                # Check if next statements modify the object
                if self._modifies_queried_object(current, next_stmt):
                    code_snippet = ast.get_source_segment(source_code, current)

                    finding = RaceConditionFinding(
                        pattern_id="RACE_CONDITION_002",
                        line=current.lineno,
                        column=current.col_offset,
                        code_snippet=code_snippet or "Unable to extract snippet",
                        severity="HIGH",
                        confidence=80,
                        description="Missing select_for_update() before modification",
                        race_scenario=(
                            "Thread A: reads counter = 10\n"
                            "Thread B: reads counter = 10\n"
                            "Thread A: writes counter = 11\n"
                            "Thread B: writes counter = 11 (lost update!)"
                        ),
                        fix_suggestion=(
                            "Use .select_for_update() to lock the row:\n"
                            "obj = Model.objects.select_for_update().get(id=id)"
                        )
                    )

                    self.findings.append(finding)

    def _detect_missing_transaction(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Detect multiple database operations without transaction.

        Pattern:
            user.balance -= amount
            user.save()
            recipient.balance += amount
            recipient.save()

        Race: Crash between operations = inconsistent state.
        """
        # Check if function has multiple save() calls
        save_calls = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if self._is_save_call(node):
                    save_calls.append(node)

        # If 2+ saves without transaction.atomic, flag it
        if len(save_calls) >= 2:
            # Check if wrapped in transaction.atomic()
            if not self._is_in_transaction(func_node):
                first_save = save_calls[0]
                code_snippet = ast.get_source_segment(source_code, func_node)

                finding = RaceConditionFinding(
                    pattern_id="RACE_CONDITION_003",
                    line=first_save.lineno,
                    column=first_save.col_offset,
                    code_snippet=code_snippet[:200] if code_snippet else "...",
                    severity="MEDIUM",
                    confidence=75,
                    description="Multiple database operations without transaction",
                    race_scenario=(
                        "Operation 1 succeeds, crash before operation 2.\n"
                        "Result: Inconsistent database state."
                    ),
                    fix_suggestion=(
                        "Wrap in transaction.atomic():\n"
                        "with transaction.atomic():\n"
                        "    # All database operations here"
                    )
                )

                self.findings.append(finding)

    def _detect_unsafe_counter_increment(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Detect counter increments without atomic operations.

        Pattern:
            obj.counter += 1  # Read-modify-write race
            obj.save()

        Race: Lost updates if concurrent increments.
        """
        for node in ast.walk(func_node):
            if isinstance(node, ast.AugAssign):
                # Check if it's += or -=
                if isinstance(node.op, (ast.Add, ast.Sub)):
                    # Check if target is an object attribute
                    if isinstance(node.target, ast.Attribute):
                        code_snippet = ast.get_source_segment(source_code, node)

                        finding = RaceConditionFinding(
                            pattern_id="RACE_CONDITION_004",
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=code_snippet or "Unable to extract snippet",
                            severity="MEDIUM",
                            confidence=70,
                            description="Counter increment without atomic operation",
                            race_scenario=(
                                "Thread A: reads counter = 10\n"
                                "Thread B: reads counter = 10\n"
                                "Thread A: writes 11\n"
                                "Thread B: writes 11 (should be 12!)"
                            ),
                            fix_suggestion=(
                                "Use F() expressions for atomic updates:\n"
                                "from django.db.models import F\n"
                                "obj.counter = F('counter') + 1\n"
                                "obj.save()"
                            )
                        )

                        self.findings.append(finding)

    def _detect_file_system_races(
        self,
        func_node: ast.FunctionDef,
        source_code: str
    ) -> None:
        """
        Detect file system TOCTOU vulnerabilities.

        Pattern:
            if os.path.exists(file):
                os.remove(file)

        Race: File could be deleted between check and remove.
        """
        for node in ast.walk(func_node):
            if not isinstance(node, ast.If):
                continue

            # Check if condition checks file existence
            if self._is_file_existence_check(node.test):
                # Check if body operates on file
                if self._contains_file_operation(node.body):
                    code_snippet = ast.get_source_segment(source_code, node)

                    finding = RaceConditionFinding(
                        pattern_id="RACE_CONDITION_005",
                        line=node.lineno,
                        column=node.col_offset,
                        code_snippet=code_snippet or "Unable to extract snippet",
                        severity="MEDIUM",
                        confidence=75,
                        description="File system TOCTOU vulnerability",
                        race_scenario=(
                            "Thread A: checks file exists = True\n"
                            "Thread B: deletes file\n"
                            "Thread A: tries to open file -> FileNotFoundError"
                        ),
                        fix_suggestion=(
                            "Use try/except instead of checking:\n"
                            "try:\n"
                            "    with open(file) as f:\n"
                            "        ...\n"
                            "except FileNotFoundError:\n"
                            "    ..."
                        )
                    )

                    self.findings.append(finding)

    def _is_existence_check(self, node: ast.AST) -> bool:
        """Check if node is an existence check (.exists(), .count())."""
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            node = node.operand

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return node.func.attr in ('exists', 'count')

        return False

    def _contains_create_operation(self, body: List[ast.stmt]) -> bool:
        """Check if body contains create operation."""
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'create':
                            return True
        return False

    def _is_query_without_lock(self, node: ast.stmt) -> bool:
        """Check if statement is a query without select_for_update."""
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Call):
                if isinstance(sub_node.func, ast.Attribute):
                    if sub_node.func.attr in self.QUERY_METHODS:
                        # Check if select_for_update is in the chain
                        if not self._has_select_for_update(sub_node):
                            return True
        return False

    def _has_select_for_update(self, node: ast.Call) -> bool:
        """Check if query chain includes select_for_update()."""
        # Walk up the chain looking for select_for_update
        current = node
        while current:
            if isinstance(current, ast.Call):
                if isinstance(current.func, ast.Attribute):
                    if current.func.attr == 'select_for_update':
                        return True
                    current = current.func.value
                else:
                    break
            else:
                break
        return False

    def _modifies_queried_object(
        self,
        query_stmt: ast.stmt,
        next_stmt: ast.stmt
    ) -> bool:
        """Check if next statement modifies the queried object."""
        # Simplified check: look for .save() or attribute assignment
        for node in ast.walk(next_stmt):
            if isinstance(node, ast.Call):
                if self._is_save_call(node):
                    return True
            if isinstance(node, ast.AugAssign):
                return True
        return False

    def _is_save_call(self, node: ast.Call) -> bool:
        """Check if node is a .save() call."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr == 'save'
        return False

    def _is_in_transaction(self, func_node: ast.FunctionDef) -> bool:
        """Check if function is wrapped in transaction.atomic()."""
        # Look for @transaction.atomic decorator
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Attribute):
                if decorator.attr == 'atomic':
                    return True
            elif isinstance(decorator, ast.Name):
                if decorator.id == 'atomic':
                    return True

        # Look for with transaction.atomic() context manager
        for node in ast.walk(func_node):
            if isinstance(node, ast.With):
                for item in node.items:
                    if isinstance(item.context_expr, ast.Call):
                        if isinstance(item.context_expr.func, ast.Attribute):
                            if item.context_expr.func.attr == 'atomic':
                                return True

        return False

    def _is_file_existence_check(self, node: ast.AST) -> bool:
        """Check if node checks file existence."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                name = f"{self._get_full_name(node.func.value)}.{node.func.attr}"
                return 'exists' in name.lower()
        return False

    def _contains_file_operation(self, body: List[ast.stmt]) -> bool:
        """Check if body contains file operations."""
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ('open', 'remove', 'rename'):
                            return True
        return False

    def _get_full_name(self, node: ast.AST) -> str:
        """Get full dotted name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_full_name(node.value)}.{node.attr}"
        return ""
