"""
Production Readiness Report

Calculates production readiness and vibe debt scores from scan findings.
"""

from typing import List, Dict


class ProductionReadinessReport:
    """Calculate production readiness metrics from scan findings."""

    def __init__(self, findings: List[Dict]):
        """
        Initialize with scan findings.

        Args:
            findings: List of issue dictionaries from scanner
        """
        self.findings = findings
        self.total_issues = len(findings)

        # Count by severity
        self.blocker_count = sum(1 for f in findings if f.get('severity') == 'BLOCKER')
        self.critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        self.high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')
        self.medium_count = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        self.low_count = sum(1 for f in findings if f.get('severity') == 'LOW')

    def calculate_vibe_debt_score(self) -> float:
        """
        Calculate vibe debt score (0-100, higher = more debt).

        Vibe debt is technical debt from AI-generated "vibe coding" -
        code that works but lacks production readiness (error handling,
        validation, security, tests, etc.)

        Returns:
            Float from 0-100 (0 = no debt, 100 = maximum debt)
        """
        if self.total_issues == 0:
            return 0.0

        # Weight severities
        weighted_score = (
            self.blocker_count * 20 +
            self.critical_count * 10 +
            self.high_count * 5 +
            self.medium_count * 2 +
            self.low_count * 1
        )

        # Normalize to 0-100 scale
        # Assume 50 weighted issues = 100 score
        max_weighted = 50
        score = min(100.0, (weighted_score / max_weighted) * 100)

        return round(score, 1)

    def calculate_production_readiness_score(self) -> float:
        """
        Calculate production readiness score (0-100, higher = more ready).

        This is the inverse of vibe debt - measures how close the code
        is to being production-ready.

        Returns:
            Float from 0-100 (0 = not ready, 100 = production ready)
        """
        vibe_debt = self.calculate_vibe_debt_score()

        # Production readiness is inverse of vibe debt
        readiness = 100.0 - vibe_debt

        # Blockers are an absolute requirement - each blocker reduces score
        blocker_penalty = self.blocker_count * 10
        readiness = max(0.0, readiness - blocker_penalty)

        return round(readiness, 1)

    def get_status_label(self, score: float, score_type: str = 'readiness') -> str:
        """
        Get human-readable status label for score.

        Args:
            score: The score value
            score_type: Either 'readiness' or 'debt'

        Returns:
            Status label string
        """
        if score_type == 'readiness':
            if score >= 85:
                return "Production Ready"
            elif score >= 70:
                return "Almost Ready"
            elif score >= 50:
                return "Needs Work"
            elif score >= 30:
                return "Not Ready"
            else:
                return "Critical Issues"
        else:  # debt
            if score >= 80:
                return "Critical Vibe Debt"
            elif score >= 60:
                return "High Vibe Debt"
            elif score >= 40:
                return "Moderate Vibe Debt"
            elif score >= 20:
                return "Low Vibe Debt"
            else:
                return "Minimal Vibe Debt"

    def get_metrics_summary(self) -> Dict:
        """
        Get comprehensive metrics summary.

        Returns:
            Dictionary with all metrics
        """
        vibe_debt = self.calculate_vibe_debt_score()
        readiness = self.calculate_production_readiness_score()

        return {
            'vibe_debt_score': vibe_debt,
            'vibe_debt_status': self.get_status_label(vibe_debt, 'debt'),
            'production_readiness_score': readiness,
            'production_readiness_status': self.get_status_label(readiness, 'readiness'),
            'total_issues': self.total_issues,
            'blockers': self.blocker_count,
            'critical': self.critical_count,
            'high': self.high_count,
            'medium': self.medium_count,
            'low': self.low_count,
            'can_deploy': self.blocker_count == 0 and readiness >= 70
        }
