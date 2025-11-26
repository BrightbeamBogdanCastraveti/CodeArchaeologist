"""
Module: test_analyzer.py
Author: Claude AI + Human Reviewer (Bogdan)
Purpose: Analyze test coverage and quality
"""

import os
import ast
from typing import List, Dict
from pathlib import Path


class TestAnalyzer:
    """
    Analyzes test coverage and identifies untested code.
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.issues = []
        self.test_files = []
        self.source_files = []

    def analyze(self) -> List[Dict]:
        """
        Run test analysis.
        """
        print(f"Running test analysis on {self.repo_path}")

        self._identify_files()
        self._check_test_coverage()
        self._check_assertion_quality()

        return self.issues

    def _identify_files(self):
        """
        Identify test files vs source files.
        """
        for file_path in Path(self.repo_path).rglob("*.py"):
            file_str = str(file_path)

            if 'test' in file_str or file_str.endswith('_test.py'):
                self.test_files.append(file_path)
            elif '__pycache__' not in file_str and 'venv' not in file_str:
                self.source_files.append(file_path)

    def _check_test_coverage(self):
        """
        Check for untested source files.
        """
        # Simple heuristic: check if source file has corresponding test file
        for source_file in self.source_files:
            source_name = source_file.stem
            has_test = any(
                source_name in test_file.stem
                for test_file in self.test_files
            )

            if not has_test and not source_name.startswith('__'):
                self.issues.append({
                    "id": f"test-{len(self.issues)}",
                    "type": "testing",
                    "severity": "medium",
                    "title": f"Missing tests: {source_name}.py",
                    "description": "Source file without corresponding test file.",
                    "location": {
                        "file": str(source_file),
                        "line": 1,
                        "column": 0
                    },
                    "auto_fix_available": True,
                    "why_ai_did_this": "AI generates functional code first. Tests are seen as optional.",
                    "why_its_wrong": "Untested code breaks easily and is hard to refactor safely.",
                    "how_to_prevent": "Prompt: 'Generate comprehensive tests for all functions.'"
                })

    def _check_assertion_quality(self):
        """
        Check quality of test assertions.
        """
        for test_file in self.test_files:
            try:
                with open(test_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)

                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
                            # Count assertions
                            assertion_count = sum(
                                1 for child in ast.walk(node)
                                if isinstance(child, ast.Assert)
                            )

                            if assertion_count == 0:
                                self.issues.append({
                                    "id": f"test-{len(self.issues)}",
                                    "type": "testing",
                                    "severity": "high",
                                    "title": f"Test without assertions: {node.name}",
                                    "description": "Test function has no assert statements.",
                                    "location": {
                                        "file": str(test_file),
                                        "line": node.lineno,
                                        "column": node.col_offset
                                    },
                                    "auto_fix_available": True,
                                    "why_ai_did_this": "AI generates test structure without proper validation.",
                                    "why_its_wrong": "Tests without assertions don't actually test anything.",
                                    "how_to_prevent": "Prompt: 'Include multiple assertions to verify expected behavior.'"
                                })

                except SyntaxError:
                    pass

            except Exception as e:
                pass
