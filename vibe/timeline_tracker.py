"""
Timeline Tracker - Track Vibe Debt Over Time

The "Archaeological Journey" - showing progress from vibe code to production-ready.

Tracks:
- Scan results over time
- Vibe debt score progression
- Issue count reductions
- Milestones achieved
- Days to production estimate

Stores history in: .code-archaeologist/history.json
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class ScanSnapshot:
    """A single scan result snapshot."""
    timestamp: str
    vibe_debt_score: int  # 0-100
    production_ready_score: int  # 0-100
    total_issues: int
    blockers: int
    critical: int
    high: int
    medium: int
    low: int
    files_scanned: int

    # Breakdown by category
    security_issues: int
    architecture_issues: int
    testing_issues: int
    quality_issues: int

    # Progress metrics
    days_to_production: int

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class JourneyStats:
    """Statistics about the archaeological journey."""
    start_date: str
    current_date: str
    days_active: int
    total_scans: int

    # Score progression
    start_vibe_debt: int
    current_vibe_debt: int
    improvement: int
    improvement_percentage: float

    # Issue reduction
    issues_fixed: int
    blockers_fixed: int
    critical_fixed: int

    # Production readiness
    start_production_score: int
    current_production_score: int
    production_improvement: int

    # Timeline
    timeline: List[ScanSnapshot]
    milestones: List[str]


class TimelineTracker:
    """
    Track vibe debt over time - the "archaeological journey".

    Shows progression from messy AI-generated code to production-ready.
    """

    def __init__(self, project_path: str):
        """Initialize timeline tracker for a project."""
        self.project_path = Path(project_path)
        self.history_dir = self.project_path / ".code-archaeologist"
        self.history_file = self.history_dir / "history.json"

        # Create directory if needed
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def record_scan(self, scan_results: Dict) -> ScanSnapshot:
        """
        Save scan results with timestamp.

        Args:
            scan_results: Dictionary containing scan results

        Returns:
            ScanSnapshot of recorded data
        """
        snapshot = ScanSnapshot(
            timestamp=datetime.now().isoformat(),
            vibe_debt_score=scan_results.get('vibe_debt_score', 0),
            production_ready_score=scan_results.get('production_ready_score', 0),
            total_issues=scan_results.get('total_issues', 0),
            blockers=scan_results.get('blockers', 0),
            critical=scan_results.get('critical', 0),
            high=scan_results.get('high', 0),
            medium=scan_results.get('medium', 0),
            low=scan_results.get('low', 0),
            files_scanned=scan_results.get('files_scanned', 0),
            security_issues=scan_results.get('security_issues', 0),
            architecture_issues=scan_results.get('architecture_issues', 0),
            testing_issues=scan_results.get('testing_issues', 0),
            quality_issues=scan_results.get('quality_issues', 0),
            days_to_production=scan_results.get('days_to_production', 0)
        )

        self._append_to_history(snapshot)
        return snapshot

    def get_journey(self) -> Optional[JourneyStats]:
        """
        Get the complete archaeological journey.

        Returns:
            JourneyStats with full history, or None if no scans yet
        """
        history = self._load_history()

        if not history:
            return None

        # Parse timestamps
        start = datetime.fromisoformat(history[0].timestamp)
        current = datetime.fromisoformat(history[-1].timestamp)
        days_active = (current - start).days

        # Calculate improvements
        start_vibe = history[0].vibe_debt_score
        current_vibe = history[-1].vibe_debt_score
        improvement = start_vibe - current_vibe
        improvement_pct = (improvement / start_vibe * 100) if start_vibe > 0 else 0

        # Issue reductions
        issues_fixed = history[0].total_issues - history[-1].total_issues
        blockers_fixed = history[0].blockers - history[-1].blockers
        critical_fixed = history[0].critical - history[-1].critical

        # Production readiness
        start_prod = history[0].production_ready_score
        current_prod = history[-1].production_ready_score
        prod_improvement = current_prod - start_prod

        # Get milestones
        milestones = self.celebrate_milestones(history)

        return JourneyStats(
            start_date=history[0].timestamp,
            current_date=history[-1].timestamp,
            days_active=max(1, days_active),  # At least 1 day
            total_scans=len(history),
            start_vibe_debt=start_vibe,
            current_vibe_debt=current_vibe,
            improvement=improvement,
            improvement_percentage=improvement_pct,
            issues_fixed=issues_fixed,
            blockers_fixed=blockers_fixed,
            critical_fixed=critical_fixed,
            start_production_score=start_prod,
            current_production_score=current_prod,
            production_improvement=prod_improvement,
            timeline=history,
            milestones=milestones
        )

    def celebrate_milestones(self, history: List[ScanSnapshot]) -> List[str]:
        """
        Check for achievements and milestones.

        Args:
            history: List of scan snapshots

        Returns:
            List of milestone messages
        """
        if not history:
            return []

        current = history[-1]
        milestones = []

        # Vibe debt milestones
        if current.vibe_debt_score < 50 and history[0].vibe_debt_score >= 50:
            milestones.append("🎉 Vibe debt under 50%!")

        if current.vibe_debt_score < 25 and history[0].vibe_debt_score >= 25:
            milestones.append("🌟 Vibe debt under 25%!")

        if current.vibe_debt_score < 10:
            milestones.append("🏆 Nearly vibe-debt free!")

        # Production readiness milestones
        if current.production_ready_score >= 85:
            milestones.append("✅ Production ready!")

        if current.production_ready_score >= 95:
            milestones.append("💎 Excellent code quality!")

        # Issue milestones
        if current.blockers == 0 and history[0].blockers > 0:
            milestones.append("🚀 Zero blockers - ready to deploy!")

        if current.critical == 0 and history[0].critical > 0:
            milestones.append("🔒 All critical security issues fixed!")

        if current.total_issues == 0:
            milestones.append("🎊 Perfect score - no issues found!")

        # Progress milestones
        if len(history) >= 10:
            milestones.append("📈 10+ scans completed - consistent improvement!")

        if len(history) >= 30:
            milestones.append("🔥 30+ scans - dedicated to quality!")

        # Speed milestones
        if len(history) >= 2:
            start = datetime.fromisoformat(history[0].timestamp)
            current_time = datetime.fromisoformat(current.timestamp)
            days = (current_time - start).days

            if days <= 7 and current.production_ready_score >= 85:
                milestones.append("⚡ Production-ready in under a week!")

            if days <= 30 and current.production_ready_score >= 95:
                milestones.append("🚄 Excellent quality in under a month!")

        return milestones

    def generate_progress_chart(self, width: int = 60) -> str:
        """
        Generate ASCII progress chart showing vibe debt over time.

        Args:
            width: Character width of the chart

        Returns:
            ASCII chart as string
        """
        history = self._load_history()

        if not history:
            return "No scan history yet. Run your first scan!"

        # Build chart
        chart = []
        chart.append("=" * width)
        chart.append("VIBE DEBT PROGRESS")
        chart.append("=" * width)
        chart.append("")

        # Show each scan as a bar
        max_score = max(s.vibe_debt_score for s in history)

        for i, snapshot in enumerate(history[-10:]):  # Last 10 scans
            # Date
            dt = datetime.fromisoformat(snapshot.timestamp)
            date_str = dt.strftime("%b %d")

            # Score bar
            bar_length = int((snapshot.vibe_debt_score / 100) * (width - 20))
            bar = "█" * bar_length + "░" * (width - 20 - bar_length)

            # Status indicator
            if snapshot.vibe_debt_score < 25:
                status = "✅"
            elif snapshot.vibe_debt_score < 50:
                status = "🟢"
            elif snapshot.vibe_debt_score < 75:
                status = "🟡"
            else:
                status = "🔴"

            chart.append(f"{date_str:8s} [{bar}] {snapshot.vibe_debt_score:3d}% {status}")

        chart.append("")
        chart.append("=" * width)

        # Summary stats
        journey = self.get_journey()
        if journey:
            chart.append(f"Journey: Day 1 ({journey.start_vibe_debt}%) → Day {journey.days_active} ({journey.current_vibe_debt}%)")
            chart.append(f"Improvement: {journey.improvement}% ({journey.improvement_percentage:.1f}%)")
            chart.append(f"Issues Fixed: {journey.issues_fixed}")
            chart.append("=" * width)

        return "\n".join(chart)

    def generate_report(self) -> str:
        """Generate detailed timeline report."""
        journey = self.get_journey()

        if not journey:
            return "No scan history yet. Run your first scan to start tracking!"

        report = []
        report.append("=" * 70)
        report.append("ARCHAEOLOGICAL JOURNEY REPORT")
        report.append("=" * 70)
        report.append("")

        # Journey overview
        report.append("🗺️  YOUR JOURNEY")
        report.append(f"   Started: {journey.start_date[:10]}")
        report.append(f"   Latest:  {journey.current_date[:10]}")
        report.append(f"   Days Active: {journey.days_active}")
        report.append(f"   Total Scans: {journey.total_scans}")
        report.append("")

        # Score progression
        report.append("📊 VIBE DEBT PROGRESSION")
        report.append(f"   Day 1:  {journey.start_vibe_debt}% vibe debt")
        report.append(f"   Now:    {journey.current_vibe_debt}% vibe debt")

        if journey.improvement > 0:
            report.append(f"   ✅ Improvement: -{journey.improvement}% ({journey.improvement_percentage:.1f}%)")
        elif journey.improvement < 0:
            report.append(f"   ⚠️  Regression: +{abs(journey.improvement)}%")
        else:
            report.append(f"   ➡️  No change")
        report.append("")

        # Production readiness
        report.append("🚀 PRODUCTION READINESS")
        report.append(f"   Day 1:  {journey.start_production_score}%")
        report.append(f"   Now:    {journey.current_production_score}%")

        if journey.production_improvement > 0:
            report.append(f"   ✅ Improvement: +{journey.production_improvement}%")
        report.append("")

        # Issues fixed
        report.append("🔧 ISSUES RESOLVED")
        report.append(f"   Total Fixed: {journey.issues_fixed}")
        report.append(f"   🔴 Blockers: {journey.blockers_fixed}")
        report.append(f"   🟡 Critical: {journey.critical_fixed}")
        report.append("")

        # Milestones
        if journey.milestones:
            report.append("🏆 MILESTONES ACHIEVED")
            for milestone in journey.milestones:
                report.append(f"   {milestone}")
            report.append("")

        # Progress chart
        report.append(self.generate_progress_chart())
        report.append("")

        # Next steps
        current = journey.timeline[-1]
        if current.production_ready_score >= 85:
            report.append("🎉 CONGRATULATIONS! You're production ready!")
        else:
            report.append("⏭️  NEXT STEPS")
            if current.blockers > 0:
                report.append(f"   • Fix {current.blockers} blocker issues")
            if current.critical > 0:
                report.append(f"   • Address {current.critical} critical issues")
            if current.days_to_production > 0:
                report.append(f"   • Estimated time to production: {current.days_to_production} days")

        report.append("")
        report.append("=" * 70)

        return "\n".join(report)

    def _load_history(self) -> List[ScanSnapshot]:
        """Load scan history from file."""
        if not self.history_file.exists():
            return []

        try:
            with open(self.history_file, 'r') as f:
                data = json.load(f)
                return [ScanSnapshot(**entry) for entry in data]
        except (json.JSONDecodeError, TypeError, KeyError):
            # Corrupted history file
            return []

    def _append_to_history(self, snapshot: ScanSnapshot):
        """Append a new snapshot to history."""
        history = self._load_history()
        history.append(snapshot)

        # Save back
        with open(self.history_file, 'w') as f:
            json.dump([s.to_dict() for s in history], f, indent=2)

    def clear_history(self):
        """Clear all scan history (use with caution!)."""
        if self.history_file.exists():
            self.history_file.unlink()


# Example usage
if __name__ == "__main__":
    tracker = TimelineTracker("/path/to/project")

    # Simulate first scan
    scan_1 = {
        'vibe_debt_score': 68,
        'production_ready_score': 32,
        'total_issues': 47,
        'blockers': 3,
        'critical': 12,
        'high': 18,
        'medium': 10,
        'low': 4,
        'files_scanned': 50,
        'security_issues': 15,
        'architecture_issues': 10,
        'testing_issues': 12,
        'quality_issues': 10,
        'days_to_production': 18
    }

    tracker.record_scan(scan_1)

    # Simulate second scan after fixes
    scan_2 = {
        'vibe_debt_score': 34,
        'production_ready_score': 66,
        'total_issues': 23,
        'blockers': 0,
        'critical': 3,
        'high': 8,
        'medium': 8,
        'low': 4,
        'files_scanned': 50,
        'security_issues': 3,
        'architecture_issues': 5,
        'testing_issues': 8,
        'quality_issues': 7,
        'days_to_production': 5
    }

    tracker.record_scan(scan_2)

    # Generate report
    print(tracker.generate_report())
