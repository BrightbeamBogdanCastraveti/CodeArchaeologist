"""
Vibe Debt Calculator

Calculates a 0-100 "vibe debt" score for codebases.
Vibe debt = technical debt from rapid AI-assisted development

Score Components:
- Security vulnerabilities (40 points)
- Missing tests (20 points)
- Code quality issues (20 points)
- Architecture violations (10 points)
- AI signature smells (10 points)

Lower score = more vibe debt = less production ready
Higher score = less vibe debt = more production ready
"""

from typing import Dict, List
from dataclasses import dataclass
from pathlib import Path
import json


@dataclass
class VibeDebtScore:
    """Vibe debt score breakdown."""
    total_score: int  # 0-100
    security_score: int  # 0-40
    testing_score: int  # 0-20
    quality_score: int  # 0-20
    architecture_score: int  # 0-10
    ai_signature_score: int  # 0-10

    # Detailed breakdown
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int

    # Production readiness
    production_ready: bool
    blockers: List[str]
    days_to_production: int

    # Category breakdown
    category_scores: Dict[str, int]


class VibeDebtCalculator:
    """
    Calculate vibe debt score for a codebase.

    The vibe debt score represents how much "cleanup" is needed
    to make AI-generated or rapidly-developed code production-ready.
    """

    def __init__(self):
        """Initialize the calculator with scoring weights."""
        self.weights = {
            "security": 40,
            "testing": 20,
            "quality": 20,
            "architecture": 10,
            "ai_signature": 10
        }

        # Issue severity weights
        self.severity_weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1
        }

        # Production readiness thresholds
        self.production_threshold = 85
        self.blocker_threshold = 90

    def calculate(self, scan_results: Dict) -> VibeDebtScore:
        """
        Calculate vibe debt score from scan results.

        Args:
            scan_results: Dictionary containing:
                - security_issues: List of security vulnerabilities
                - test_coverage: Test coverage percentage
                - quality_issues: List of code quality issues
                - architecture_issues: List of architecture violations
                - ai_signatures: List of AI-generated code smells

        Returns:
            VibeDebtScore with complete breakdown
        """
        # Calculate component scores
        security_score = self._calculate_security_score(
            scan_results.get("security_issues", [])
        )

        testing_score = self._calculate_testing_score(
            scan_results.get("test_coverage", 0),
            scan_results.get("test_issues", [])
        )

        quality_score = self._calculate_quality_score(
            scan_results.get("quality_issues", [])
        )

        architecture_score = self._calculate_architecture_score(
            scan_results.get("architecture_issues", [])
        )

        ai_signature_score = self._calculate_ai_signature_score(
            scan_results.get("ai_signatures", [])
        )

        # Total score
        total_score = (
            security_score +
            testing_score +
            quality_score +
            architecture_score +
            ai_signature_score
        )

        # Count issues by severity
        all_issues = (
            scan_results.get("security_issues", []) +
            scan_results.get("quality_issues", []) +
            scan_results.get("architecture_issues", [])
        )

        critical_count = len([i for i in all_issues if i.get("severity") == "critical"])
        high_count = len([i for i in all_issues if i.get("severity") == "high"])
        medium_count = len([i for i in all_issues if i.get("severity") == "medium"])
        low_count = len([i for i in all_issues if i.get("severity") == "low"])

        # Determine production readiness
        production_ready = total_score >= self.production_threshold and critical_count == 0

        # Identify blockers
        blockers = self._identify_blockers(scan_results, critical_count)

        # Estimate days to production
        days_to_production = self._estimate_days_to_production(
            total_score, critical_count, high_count, medium_count
        )

        # Category breakdown
        category_scores = {
            "security": security_score,
            "testing": testing_score,
            "quality": quality_score,
            "architecture": architecture_score,
            "ai_signature": ai_signature_score
        }

        return VibeDebtScore(
            total_score=total_score,
            security_score=security_score,
            testing_score=testing_score,
            quality_score=quality_score,
            architecture_score=architecture_score,
            ai_signature_score=ai_signature_score,
            critical_issues=critical_count,
            high_issues=high_count,
            medium_issues=medium_count,
            low_issues=low_count,
            production_ready=production_ready,
            blockers=blockers,
            days_to_production=days_to_production,
            category_scores=category_scores
        )

    def _calculate_security_score(self, issues: List[Dict]) -> int:
        """
        Calculate security component score (0-40 points).

        Deductions:
        - Critical: -10 points each
        - High: -5 points each
        - Medium: -2 points each
        - Low: -1 point each
        """
        max_score = self.weights["security"]
        deductions = 0

        for issue in issues:
            severity = issue.get("severity", "low")
            deductions += self.severity_weights.get(severity, 1)

        score = max(0, max_score - deductions)
        return score

    def _calculate_testing_score(self, coverage: float, test_issues: List[Dict]) -> int:
        """
        Calculate testing component score (0-20 points).

        Score based on:
        - Test coverage percentage (0-15 points)
        - Test quality issues (-1 to -3 points each)
        """
        max_score = self.weights["testing"]

        # Coverage score (0-15 points)
        coverage_score = min(15, int(coverage * 15 / 100))

        # Test quality deductions (0-5 points)
        quality_deductions = min(5, len(test_issues))

        score = coverage_score + (5 - quality_deductions)
        return min(max_score, score)

    def _calculate_quality_score(self, issues: List[Dict]) -> int:
        """
        Calculate code quality component score (0-20 points).

        Deductions for:
        - Magic numbers
        - Bare exceptions
        - Long functions
        - Code duplication
        - Missing docstrings
        """
        max_score = self.weights["quality"]
        deductions = len(issues)  # 1 point per quality issue

        score = max(0, max_score - deductions)
        return score

    def _calculate_architecture_score(self, issues: List[Dict]) -> int:
        """
        Calculate architecture component score (0-10 points).

        Deductions for:
        - Circular dependencies
        - Layer violations
        - Missing patterns
        """
        max_score = self.weights["architecture"]
        deductions = len(issues) * 2  # 2 points per architecture issue

        score = max(0, max_score - deductions)
        return score

    def _calculate_ai_signature_score(self, signatures: List[Dict]) -> int:
        """
        Calculate AI signature component score (0-10 points).

        Deductions for:
        - Verbose comments
        - Generic variable names
        - Unnecessary complexity
        """
        max_score = self.weights["ai_signature"]
        deductions = len(signatures)  # 1 point per AI smell

        score = max(0, max_score - deductions)
        return score

    def _identify_blockers(self, scan_results: Dict, critical_count: int) -> List[str]:
        """Identify critical blockers preventing production deployment."""
        blockers = []

        if critical_count > 0:
            blockers.append(f"{critical_count} critical security vulnerabilities")

        test_coverage = scan_results.get("test_coverage", 0)
        if test_coverage < 50:
            blockers.append(f"Test coverage too low ({test_coverage}%)")

        security_issues = scan_results.get("security_issues", [])
        sql_injection = [i for i in security_issues if i.get("type") == "sql_injection"]
        if sql_injection:
            blockers.append(f"{len(sql_injection)} SQL injection vulnerabilities")

        return blockers

    def _estimate_days_to_production(
        self, score: int, critical: int, high: int, medium: int
    ) -> int:
        """
        Estimate days needed to reach production readiness.

        Estimation:
        - Each critical issue: 0.5 days
        - Each high issue: 0.25 days
        - Each medium issue: 0.1 days
        - Gap to 85 score: (85-score) * 0.1 days
        """
        if score >= self.production_threshold and critical == 0:
            return 0

        issue_days = (critical * 0.5) + (high * 0.25) + (medium * 0.1)
        score_gap_days = max(0, self.production_threshold - score) * 0.1

        total_days = int(issue_days + score_gap_days)
        return total_days

    def generate_report(self, score: VibeDebtScore) -> str:
        """Generate human-readable vibe debt report."""
        report = []
        report.append("=" * 70)
        report.append("VIBE DEBT REPORT")
        report.append("=" * 70)
        report.append("")

        # Overall score
        report.append(f"Production Readiness Score: {score.total_score}/100")

        # Visual score bar
        filled = int(score.total_score / 10)
        empty = 10 - filled
        bar = "█" * filled + "░" * empty
        report.append(f"[{bar}] {score.total_score}%")
        report.append("")

        # Production ready status
        if score.production_ready:
            report.append("✅ PRODUCTION READY")
        else:
            report.append("❌ NOT PRODUCTION READY")
            report.append(f"   Estimated time to production: {score.days_to_production} days")
        report.append("")

        # Blockers
        if score.blockers:
            report.append("🚫 BLOCKERS:")
            for blocker in score.blockers:
                report.append(f"   • {blocker}")
            report.append("")

        # Component scores
        report.append("SCORE BREAKDOWN:")
        report.append(f"  Security:      {score.security_score:2d}/40  " + self._score_indicator(score.security_score, 40))
        report.append(f"  Testing:       {score.testing_score:2d}/20  " + self._score_indicator(score.testing_score, 20))
        report.append(f"  Code Quality:  {score.quality_score:2d}/20  " + self._score_indicator(score.quality_score, 20))
        report.append(f"  Architecture:  {score.architecture_score:2d}/10  " + self._score_indicator(score.architecture_score, 10))
        report.append(f"  AI Signatures: {score.ai_signature_score:2d}/10  " + self._score_indicator(score.ai_signature_score, 10))
        report.append("")

        # Issue counts
        report.append("ISSUES BY SEVERITY:")
        report.append(f"  🔴 Critical: {score.critical_issues}")
        report.append(f"  🟡 High:     {score.high_issues}")
        report.append(f"  🟠 Medium:   {score.medium_issues}")
        report.append(f"  🔵 Low:      {score.low_issues}")
        report.append("")

        report.append("=" * 70)

        return "\n".join(report)

    def _score_indicator(self, score: int, max_score: int) -> str:
        """Generate visual indicator for component score."""
        percentage = (score / max_score) * 100

        if percentage >= 90:
            return "✅ Excellent"
        elif percentage >= 75:
            return "🟢 Good"
        elif percentage >= 50:
            return "🟡 Needs Work"
        else:
            return "🔴 Critical"


# Example usage
if __name__ == "__main__":
    calculator = VibeDebtCalculator()

    # Example scan results
    scan_results = {
        "security_issues": [
            {"type": "sql_injection", "severity": "critical"},
            {"type": "xss", "severity": "high"},
            {"type": "xss", "severity": "medium"}
        ],
        "test_coverage": 67,
        "quality_issues": [
            {"type": "magic_number"},
            {"type": "bare_exception"},
            {"type": "long_function"}
        ],
        "architecture_issues": [
            {"type": "circular_dependency"}
        ],
        "ai_signatures": [
            {"type": "verbose_comments"},
            {"type": "generic_names"}
        ]
    }

    score = calculator.calculate(scan_results)
    print(calculator.generate_report(score))
