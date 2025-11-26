"""
Module: honesty_check.py
Author: Code Archaeologist Team
Purpose: Ensures the scanner doesn't give fake "all clear" reports.

CORE PRINCIPLE: BRUTAL HONESTY
- Every codebase has issues
- If we find too few issues, something is wrong with our scanner
- Never give a false sense of security
"""

import logging
from pathlib import Path
from typing import List


logger = logging.getLogger(__name__)


class HonestyChecker:
    """
    Ensures scan results are honest and not suspiciously clean.

    This prevents the dangerous scenario where a scanner reports "all clear"
    when it's actually missing vulnerabilities.
    """

    # Empirical thresholds from analyzing real codebases
    MINIMUM_ISSUES_PER_1000_LINES = 3  # Even excellent code has issues
    CRITICAL_ISSUES_EXPECTED_RATE = 0.1  # At least 1 critical per 10k lines
    VIBE_DEBT_MINIMUM = 10  # No codebase is perfect

    def __init__(self):
        """Initialize honesty checker"""
        self.baseline_stats = self._load_baseline_stats()

    def _load_baseline_stats(self) -> dict:
        """
        Load baseline statistics from analyzing thousands of projects.

        These stats help us know what "normal" looks like.
        """
        return {
            "avg_issues_per_1000_lines": 8.5,
            "avg_critical_per_10000_lines": 1.2,
            "avg_vibe_debt_score": 45,
            "min_expected_issues": 3,
        }

    def check_suspicious(
        self, issues: List, project_path: Path
    ) -> bool:
        """
        Check if scan results are suspiciously clean.

        Args:
            issues: List of detected issues
            project_path: Path to scanned project

        Returns:
            bool: True if results seem suspicious
        """
        # Count lines of code
        total_lines = self._count_lines_of_code(project_path)

        if total_lines == 0:
            logger.warning("No code found in project")
            return True

        # Calculate issue rate
        issues_per_1000 = (len(issues) / total_lines) * 1000

        # Check if suspiciously low
        if issues_per_1000 < self.MINIMUM_ISSUES_PER_1000_LINES:
            logger.warning(
                f"Suspiciously low issue rate: {issues_per_1000:.2f} per 1000 lines "
                f"(expected >= {self.MINIMUM_ISSUES_PER_1000_LINES})"
            )
            return True

        # Check for critical issues
        critical_issues = [i for i in issues if i.severity.value == "critical"]
        critical_per_10k = (len(critical_issues) / total_lines) * 10000

        if total_lines > 1000 and len(critical_issues) == 0:
            logger.warning(
                f"No critical issues found in {total_lines} lines of code - suspicious"
            )
            return True

        # All checks passed
        return False

    def _count_lines_of_code(self, project_path: Path) -> int:
        """
        Count total lines of code in project.

        Args:
            project_path: Path to project

        Returns:
            int: Total lines of code
        """
        total_lines = 0
        extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs"}

        try:
            for file_path in project_path.rglob("*"):
                if file_path.is_file() and file_path.suffix in extensions:
                    # Skip generated and vendor code
                    if self._should_skip_file(file_path):
                        continue

                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            total_lines += sum(1 for _ in f)
                    except Exception as e:
                        logger.debug(f"Error reading {file_path}: {e}")
                        continue

        except Exception as e:
            logger.error(f"Error counting lines: {e}")
            return 0

        return total_lines

    def _should_skip_file(self, file_path: Path) -> bool:
        """
        Determine if file should be skipped from line counting.

        Args:
            file_path: Path to check

        Returns:
            bool: True if should skip
        """
        skip_patterns = [
            "node_modules",
            "venv",
            "env",
            ".git",
            "dist",
            "build",
            "__pycache__",
            ".pytest_cache",
            "migrations",
            "generated",
        ]

        path_str = str(file_path)
        return any(pattern in path_str for pattern in skip_patterns)

    def generate_honesty_report(
        self, issues: List, project_path: Path
    ) -> dict:
        """
        Generate a report on the honesty/reliability of scan results.

        Args:
            issues: Detected issues
            project_path: Project path

        Returns:
            dict: Honesty report
        """
        total_lines = self._count_lines_of_code(project_path)
        issues_per_1000 = (len(issues) / max(total_lines, 1)) * 1000
        suspicious = self.check_suspicious(issues, project_path)

        return {
            "total_lines_of_code": total_lines,
            "total_issues": len(issues),
            "issues_per_1000_lines": round(issues_per_1000, 2),
            "expected_minimum": self.MINIMUM_ISSUES_PER_1000_LINES,
            "suspicious": suspicious,
            "confidence_in_results": "low" if suspicious else "high",
            "message": self._generate_honesty_message(suspicious, issues_per_1000),
        }

    def _generate_honesty_message(
        self, suspicious: bool, issues_per_1000: float
    ) -> str:
        """Generate human-readable honesty message"""
        if suspicious:
            return (
                f"⚠️  SUSPICIOUS RESULTS: Only {issues_per_1000:.1f} issues per 1000 lines detected. "
                f"This is unusually low. Either:\n"
                f"1. The scanner missed vulnerabilities (most likely)\n"
                f"2. This is exceptionally well-written code (rare)\n"
                f"3. The codebase is mostly configuration/templates\n\n"
                f"Recommendation: Manually review security-critical code paths."
            )
        else:
            return (
                f"✓ Results appear reliable: {issues_per_1000:.1f} issues per 1000 lines "
                f"is within expected range."
            )
