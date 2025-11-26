"""
Module: vibe_debt_analyzer.py
Author: Claude AI + Human Reviewer (Bogdan)
Purpose: Detect "vibe debt" - code that works but isn't production-ready
This is the unique feature that identifies AI-generated code patterns
"""

import os
import re
import ast
from typing import List, Dict
from pathlib import Path

# Import the specialized vibe patterns detector (based on real audit findings)
import sys
detector_path = Path(__file__).parent.parent.parent / 'detectors'
sys.path.insert(0, str(detector_path))
from vibe_patterns import VibePatternsDetector, VibeIssue


class VibeDebtAnalyzer:
    """
    Detects vibe coding patterns - code that "feels right" and works
    but has production issues common in AI-generated code.
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.issues = []
        self.vibe_patterns_detector = VibePatternsDetector()

    def analyze(self) -> List[Dict]:
        """
        Run all vibe debt analyses.
        """
        print(f"Running vibe debt analysis on {self.repo_path}")

        # First run the audit-based pattern detector (more specific)
        self._run_audit_pattern_detection()

        # Then run the additional heuristic checks
        self._check_missing_error_handling()
        self._check_overly_generic_names()
        self._check_missing_logging()
        self._check_hardcoded_values()
        self._check_race_conditions()
        self._check_missing_input_validation()
        self._check_god_objects()
        self._check_missing_docstrings()

        return self.issues

    def _run_audit_pattern_detection(self):
        """
        Run the specialized vibe patterns detector based on real audit findings.
        This detector finds specific patterns from production audits:
        - 846 dict.get() without defaults
        - 62 array access without bounds checking
        - 160 functions without error handling
        - 749 type conversions without try/except
        - 126 debug print statements
        - 19 bare except:pass blocks
        - 795 regex operations (ReDoS risk)
        - 31 timezone-naive datetime usage
        """
        print("  Running audit-based pattern detection...")

        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    source_code = f.read()

                # Run the specialized detector
                vibe_issues = self.vibe_patterns_detector.detect(str(file_path), source_code)

                # Convert VibeIssue objects to the format used by vibe_debt_analyzer
                for vibe_issue in vibe_issues:
                    self.issues.append({
                        "id": f"vibe-audit-{len(self.issues)}",
                        "type": "vibe_debt",
                        "severity": vibe_issue.severity.lower(),
                        "title": f"[AUDIT] {vibe_issue.description}",
                        "description": f"{vibe_issue.description} (CWE: {vibe_issue.cwe})",
                        "location": {
                            "file": str(file_path),
                            "line": vibe_issue.line,
                            "column": vibe_issue.column
                        },
                        "code_snippet": vibe_issue.code_snippet,
                        "auto_fix_available": True,
                        "fix_suggestion": vibe_issue.fix_suggestion,
                        "pattern_type": vibe_issue.pattern_type,
                        "cwe": vibe_issue.cwe,
                        "why_ai_did_this": f"Pattern from audit: {vibe_issue.pattern_type}",
                        "why_its_wrong": vibe_issue.description,
                        "how_to_prevent": vibe_issue.fix_suggestion
                    })

            except Exception as e:
                # Skip files that can't be read or parsed
                pass

        # Print statistics from the audit pattern detector
        stats = self.vibe_patterns_detector.get_statistics()
        print(f"  Audit patterns found: {stats['total_issues']} issues")
        print(f"    - dict.get() without defaults: {stats['patterns']['dict_get_no_default']}")
        print(f"    - Array access without bounds: {stats['patterns']['array_access_no_bounds']}")
        print(f"    - Functions without error handling: {stats['patterns']['function_no_error_handling']}")
        print(f"    - Unsafe type conversions: {stats['patterns']['unsafe_type_conversion']}")
        print(f"    - Debug print statements: {stats['patterns']['debug_prints']}")
        print(f"    - Bare except:pass blocks: {stats['patterns']['bare_except_pass']}")
        print(f"    - Unsafe regex (ReDoS): {stats['patterns']['unsafe_regex']}")
        print(f"    - Naive datetime usage: {stats['patterns']['naive_datetime']}")

    def _check_missing_error_handling(self):
        """
        Detect functions without try-catch or error handling.
        AI often generates "happy path" code without error cases.
        """
        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)

                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef):
                            # Check if function has try-except
                            has_try_except = any(
                                isinstance(child, ast.Try)
                                for child in ast.walk(node)
                            )

                            # Check if function does I/O operations
                            has_io = self._has_io_operations(node)

                            if has_io and not has_try_except:
                                self.issues.append({
                                    "id": f"vibe-{len(self.issues)}",
                                    "type": "vibe_debt",
                                    "severity": "medium",
                                    "title": f"Missing error handling in {node.name}()",
                                    "description": "Function performs I/O but has no try-except block.",
                                    "location": {
                                        "file": str(file_path),
                                        "line": node.lineno,
                                        "column": node.col_offset
                                    },
                                    "auto_fix_available": True,
                                    "why_ai_did_this": "AI generates the happy path first. Error handling is seen as boilerplate.",
                                    "why_its_wrong": "Production code must handle failures gracefully. No error handling = crashes.",
                                    "how_to_prevent": "Prompt: 'Add comprehensive error handling for all I/O operations.'"
                                })

                except SyntaxError:
                    pass

            except Exception as e:
                pass

    def _check_overly_generic_names(self):
        """
        Detect generic variable names like 'data', 'result', 'temp', 'obj'.
        AI often uses these placeholder names.
        """
        generic_names = ['data', 'result', 'temp', 'obj', 'item', 'value', 'x', 'y']

        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)

                    for node in ast.walk(tree):
                        if isinstance(node, (ast.Name, ast.arg)):
                            name = node.id if isinstance(node, ast.Name) else node.arg

                            if name in generic_names:
                                self.issues.append({
                                    "id": f"vibe-{len(self.issues)}",
                                    "type": "vibe_debt",
                                    "severity": "low",
                                    "title": f"Generic variable name: '{name}'",
                                    "description": "Use descriptive variable names for better code clarity.",
                                    "location": {
                                        "file": str(file_path),
                                        "line": getattr(node, 'lineno', 0),
                                        "column": getattr(node, 'col_offset', 0)
                                    },
                                    "auto_fix_available": False,
                                    "why_ai_did_this": "AI uses generic names as placeholders for quick prototyping.",
                                    "why_its_wrong": "Generic names reduce code readability and maintainability.",
                                    "how_to_prevent": "Prompt: 'Use descriptive, domain-specific variable names.'"
                                })
                                break  # Only report once per file to avoid spam

                except SyntaxError:
                    pass

            except Exception as e:
                pass

    def _check_missing_logging(self):
        """
        Check for missing logging in critical operations.
        """
        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Check if file has logging import
                has_logging_import = re.search(r'import logging|from logging', content)

                # Check if file has API routes or database operations
                has_critical_ops = re.search(
                    r'@app\.route|@api\.|\.filter\(|\.create\(|\.update\(',
                    content
                )

                if has_critical_ops and not has_logging_import:
                    self.issues.append({
                        "id": f"vibe-{len(self.issues)}",
                        "type": "vibe_debt",
                        "severity": "medium",
                        "title": "Missing logging in critical module",
                        "description": "Module performs critical operations but has no logging.",
                        "location": {
                            "file": str(file_path),
                            "line": 1,
                            "column": 0
                        },
                        "auto_fix_available": True,
                        "why_ai_did_this": "Logging is seen as non-functional code. AI focuses on features.",
                        "why_its_wrong": "Without logs, debugging production issues is impossible.",
                        "how_to_prevent": "Prompt: 'Add comprehensive logging for all operations.'"
                    })

            except Exception as e:
                pass

    def _check_hardcoded_values(self):
        """
        Detect hardcoded configuration values (URLs, ports, etc.)
        """
        hardcode_patterns = [
            (r'http://localhost:\d+', "Hardcoded localhost URL"),
            (r'https?://[a-zA-Z0-9.-]+\.[a-z]{2,}', "Hardcoded external URL"),
            (r'port\s*=\s*\d{4,5}', "Hardcoded port number"),
        ]

        for file_path in Path(self.repo_path).rglob("*"):
            if file_path.suffix in ['.py', '.js', '.ts', '.tsx', '.jsx']:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line_num, line in enumerate(f, 1):
                            for pattern, description in hardcode_patterns:
                                if re.search(pattern, line):
                                    self.issues.append({
                                        "id": f"vibe-{len(self.issues)}",
                                        "type": "vibe_debt",
                                        "severity": "medium",
                                        "title": description,
                                        "description": "Configuration should be in environment variables.",
                                        "location": {
                                            "file": str(file_path),
                                            "line": line_num,
                                            "column": 0
                                        },
                                        "auto_fix_available": True,
                                        "why_ai_did_this": "AI generates working examples with concrete values.",
                                        "why_its_wrong": "Hardcoded values prevent deployment to different environments.",
                                        "how_to_prevent": "Use .env files and environment variables for all config."
                                    })
                except Exception as e:
                    pass

    def _check_race_conditions(self):
        """
        Detect potential race conditions in async code or shared state.
        """
        race_patterns = [
            (r'global\s+\w+', "Global variable modification"),
            (r'async\s+def.*\n.*(?!await)', "Async function without await"),
        ]

        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                    for pattern, description in race_patterns:
                        if re.search(pattern, content, re.MULTILINE):
                            self.issues.append({
                                "id": f"vibe-{len(self.issues)}",
                                "type": "vibe_debt",
                                "severity": "high",
                                "title": "Potential race condition",
                                "description": description,
                                "location": {
                                    "file": str(file_path),
                                    "line": 1,
                                    "column": 0
                                },
                                "auto_fix_available": True,
                                "why_ai_did_this": "AI doesn't consider concurrent execution scenarios.",
                                "why_its_wrong": "Race conditions cause unpredictable behavior in production.",
                                "how_to_prevent": "Use locks, queues, or atomic operations for shared state."
                            })
                            break

            except Exception as e:
                pass

    def _check_missing_input_validation(self):
        """
        Check for missing input validation in API routes.
        """
        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        # Check for API routes
                        if re.search(r'@app\.route|@api\.get|@api\.post', line):
                            # Check next 10 lines for validation
                            has_validation = False
                            for next_line in lines[line_num:line_num+10]:
                                if re.search(r'if.*not|validate|schema|pydantic', next_line, re.IGNORECASE):
                                    has_validation = True
                                    break

                            if not has_validation:
                                self.issues.append({
                                    "id": f"vibe-{len(self.issues)}",
                                    "type": "vibe_debt",
                                    "severity": "high",
                                    "title": "Missing input validation",
                                    "description": "API endpoint without input validation.",
                                    "location": {
                                        "file": str(file_path),
                                        "line": line_num,
                                        "column": 0
                                    },
                                    "auto_fix_available": True,
                                    "why_ai_did_this": "AI generates functional endpoints without defensive programming.",
                                    "why_its_wrong": "Invalid input causes crashes and security issues.",
                                    "how_to_prevent": "Use Pydantic models or explicit validation for all inputs."
                                })

            except Exception as e:
                pass

    def _check_god_objects(self):
        """
        Detect "god objects" - classes with too many responsibilities.
        """
        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)

                    for node in ast.walk(tree):
                        if isinstance(node, ast.ClassDef):
                            # Count methods
                            method_count = sum(
                                1 for child in node.body
                                if isinstance(child, ast.FunctionDef)
                            )

                            if method_count > 15:
                                self.issues.append({
                                    "id": f"vibe-{len(self.issues)}",
                                    "type": "vibe_debt",
                                    "severity": "medium",
                                    "title": f"God object: {node.name} has {method_count} methods",
                                    "description": "Class has too many responsibilities. Consider splitting.",
                                    "location": {
                                        "file": str(file_path),
                                        "line": node.lineno,
                                        "column": node.col_offset
                                    },
                                    "auto_fix_available": False,
                                    "why_ai_did_this": "AI tends to put related functionality in one class.",
                                    "why_its_wrong": "Large classes are hard to test, maintain, and reuse.",
                                    "how_to_prevent": "Follow Single Responsibility Principle. One class, one purpose."
                                })

                except SyntaxError:
                    pass

            except Exception as e:
                pass

    def _check_missing_docstrings(self):
        """
        Check for missing docstrings in public functions.
        """
        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)

                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef):
                            # Skip private functions
                            if node.name.startswith('_'):
                                continue

                            # Check for docstring
                            has_docstring = (
                                ast.get_docstring(node) is not None
                            )

                            if not has_docstring:
                                self.issues.append({
                                    "id": f"vibe-{len(self.issues)}",
                                    "type": "vibe_debt",
                                    "severity": "low",
                                    "title": f"Missing docstring: {node.name}()",
                                    "description": "Public function without documentation.",
                                    "location": {
                                        "file": str(file_path),
                                        "line": node.lineno,
                                        "column": node.col_offset
                                    },
                                    "auto_fix_available": True,
                                    "why_ai_did_this": "AI focuses on implementation, not documentation.",
                                    "why_its_wrong": "Undocumented code is hard for teams to understand and maintain.",
                                    "how_to_prevent": "Prompt: 'Add comprehensive docstrings with parameters and return values.'"
                                })

                except SyntaxError:
                    pass

            except Exception as e:
                pass

    def _has_io_operations(self, node) -> bool:
        """
        Check if AST node contains I/O operations.
        """
        io_patterns = ['open', 'read', 'write', 'request', 'fetch', 'query']

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in io_patterns:
                        return True
                elif isinstance(child.func, ast.Attribute):
                    if child.func.attr in io_patterns:
                        return True

        return False
