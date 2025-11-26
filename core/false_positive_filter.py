"""
False Positive Filter

Reduces false positives by filtering out:
1. Code in docstrings and comments (examples)
2. Test files (intentionally vulnerable)
3. Detector files (pattern definitions)
4. Configuration examples
5. Dead code / commented-out code

Research: False positives kill tool adoption
Target: <5% false positive rate
"""

import ast
import re
from typing import Dict, List, Set
from pathlib import Path


class FalsePositiveFilter:
    """Filter out false positive findings."""

    # Files that should be ignored
    IGNORE_PATTERNS = {
        'test_*.py',
        '*_test.py',
        'tests/',
        'test/',
        'examples/',
        'docs/',
        '.venv/',
        'venv/',
        'node_modules/',
    }

    # Directories that contain detector definitions
    DETECTOR_PATHS = {
        'analysis_engine/detectors/',
        'detectors/',
    }

    def __init__(self):
        self.filters_applied = {
            'docstring': 0,
            'comment': 0,
            'test_file': 0,
            'detector_file': 0,
            'low_confidence': 0,
            'example_code': 0,
        }

    def filter_findings(self, findings: List[Dict], file_content: str = None,
                       file_path: str = None) -> List[Dict]:
        """
        Filter out false positives from findings.

        Args:
            findings: List of findings from detectors
            file_content: Optional file content for context-aware filtering
            file_path: Optional file path for path-based filtering

        Returns:
            Filtered list of findings
        """
        filtered = []

        for finding in findings:
            # Filter 1: Test files
            if self._is_test_file(finding.get('file', file_path or '')):
                self.filters_applied['test_file'] += 1
                continue

            # Filter 2: Detector definition files
            if self._is_detector_file(finding.get('file', file_path or '')):
                self.filters_applied['detector_file'] += 1
                continue

            # Filter 3: Low confidence findings
            if finding.get('confidence', 100) < 40:
                self.filters_applied['low_confidence'] += 1
                continue

            # Filter 4: Check if finding is in docstring/comment
            if file_content and self._is_in_docstring_or_comment(
                finding, file_content
            ):
                self.filters_applied['docstring'] += 1
                continue

            # Filter 5: Example/demonstration code
            if self._is_example_code(finding, file_content):
                self.filters_applied['example_code'] += 1
                continue

            # Passed all filters
            filtered.append(finding)

        return filtered

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file."""
        path = Path(file_path)

        # Check filename patterns
        if path.name.startswith('test_') or path.name.endswith('_test.py'):
            return True

        # Check if in test directory
        parts = path.parts
        return any(part in ['test', 'tests', 'testing'] for part in parts)

    def _is_detector_file(self, file_path: str) -> bool:
        """Check if file is a detector definition."""
        path = Path(file_path)

        # Check if in detector directory
        for detector_path in self.DETECTOR_PATHS:
            if detector_path in str(path):
                return True

        return False

    def _is_in_docstring_or_comment(self, finding: Dict, content: str) -> bool:
        """
        Check if finding is in a docstring or comment.

        This is crucial for avoiding false positives from example code.
        """
        line = finding.get('line', 0)
        if line <= 0:
            return False

        lines = content.split('\n')
        if line > len(lines):
            return False

        # Check if the specific line is a comment
        actual_line = lines[line - 1].strip()
        if actual_line.startswith('#'):
            return True

        # Check if line is inside docstring
        try:
            tree = ast.parse(content)
            return self._is_line_in_docstring(line, tree)
        except:
            return False

    def _is_line_in_docstring(self, line: int, tree: ast.AST) -> bool:
        """Check if line number is inside any docstring."""
        for node in ast.walk(tree):
            # Check module docstring
            if isinstance(node, ast.Module):
                if (node.body and
                    isinstance(node.body[0], ast.Expr) and
                    isinstance(node.body[0].value, ast.Constant)):
                    docstring_node = node.body[0]
                    if docstring_node.lineno <= line <= docstring_node.end_lineno:
                        return True

            # Check function/class docstrings
            if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                if (node.body and
                    isinstance(node.body[0], ast.Expr) and
                    isinstance(node.body[0].value, ast.Constant)):
                    docstring_node = node.body[0]
                    if docstring_node.lineno <= line <= docstring_node.end_lineno:
                        return True

        return False

    def _is_example_code(self, finding: Dict, content: str) -> bool:
        """
        Check if finding is in example/demonstration code.

        Patterns:
        - Lines near "Example:", "Bad:", "Wrong:", "Don't:"
        - Lines in triple-quoted blocks after example markers
        """
        if not content:
            return False

        line = finding.get('line', 0)
        if line <= 0:
            return False

        lines = content.split('\n')
        if line > len(lines):
            return False

        # Check surrounding lines for example markers
        start = max(0, line - 10)
        end = min(len(lines), line + 5)
        context = '\n'.join(lines[start:end]).lower()

        example_markers = [
            'example:', 'bad:', 'wrong:', "don't:", 'avoid:',
            'incorrect:', 'vulnerable:', 'attack vector:',
            'ai training paradox:', 'training era:'
        ]

        for marker in example_markers:
            if marker in context:
                return True

        return False

    def get_filter_stats(self) -> Dict[str, int]:
        """Get statistics on filters applied."""
        return self.filters_applied.copy()


def apply_false_positive_filters(findings: List[Dict],
                                 file_content: str = None,
                                 file_path: str = None) -> List[Dict]:
    """
    Convenience function to apply false positive filtering.

    Usage:
        findings = detector.detect(content, path)
        filtered = apply_false_positive_filters(findings, content, path)
    """
    filter = FalsePositiveFilter()
    return filter.filter_findings(findings, file_content, file_path)
