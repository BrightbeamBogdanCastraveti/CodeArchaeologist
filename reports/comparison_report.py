"""
Comparison Report Generator

Compares two scan results to track progress over time.

Shows:
- Issues fixed/added between scans
- Progress by category
- Improvement trends
- Regression warnings

Format: Markdown
"""

from typing import Dict, List, Tuple
from collections import defaultdict
from datetime import datetime
import json


class ComparisonReport:
    """Generate comparison report between two scans."""

    def __init__(self, old_results, new_results):
        """
        Initialize with two scan results.

        Args:
            old_results: Previous ScanResults object
            new_results: Current ScanResults object
        """
        self.old = old_results
        self.new = new_results

        # Build lookup structures
        self._build_issue_maps()

    def _build_issue_maps(self):
        """Build maps for comparing issues."""
        # Create signature for each issue (file:line:detector)
        self.old_issues = {}
        for issue in self.old.findings:
            sig = self._issue_signature(issue)
            self.old_issues[sig] = issue

        self.new_issues = {}
        for issue in self.new.findings:
            sig = self._issue_signature(issue)
            self.new_issues[sig] = issue

        # Find fixed and new issues
        old_sigs = set(self.old_issues.keys())
        new_sigs = set(self.new_issues.keys())

        self.fixed_sigs = old_sigs - new_sigs
        self.new_sigs = new_sigs - old_sigs
        self.unchanged_sigs = old_sigs & new_sigs

    def _issue_signature(self, issue: Dict) -> str:
        """Create unique signature for issue."""
        file = issue.get('file', '')
        line = issue.get('line', 0)
        detector = issue.get('detector', '')
        return f"{file}:{line}:{detector}"

    def generate(self) -> str:
        """Generate complete comparison report."""
        sections = [
            self._header(),
            self._summary(),
            self._by_category(),
            self._top_improvements(),
            self._regressions(),
            self._trend_analysis(),
            self._footer()
        ]

        return '\n\n'.join(sections)

    def _header(self) -> str:
        """Generate report header."""
        # Calculate time difference
        # (Note: ScanResults doesn't have timestamp, using current time)
        return f"""# Progress Comparison Report

**Comparison Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

**Previous Scan:**
- Total Issues: {self.old.total_issues}
- Vibe Debt Score: {self.old.vibe_debt_score}/100

**Current Scan:**
- Total Issues: {self.new.total_issues}
- Vibe Debt Score: {self.new.vibe_debt_score}/100

---
"""

    def _summary(self) -> str:
        """Generate summary of changes."""
        fixed_count = len(self.fixed_sigs)
        new_count = len(self.new_sigs)
        net_change = new_count - fixed_count

        # Calculate percentage change
        if self.old.total_issues > 0:
            pct_change = (net_change / self.old.total_issues) * 100
        else:
            pct_change = 0

        # Vibe debt change
        vibe_change = self.new.vibe_debt_score - self.old.vibe_debt_score

        output = "## Overall Progress\n\n"

        if net_change < 0:
            output += f"### ✅ IMPROVEMENT - {abs(net_change)} Net Issues Fixed\n\n"
        elif net_change > 0:
            output += f"### ⚠️ REGRESSION - {net_change} Net New Issues\n\n"
        else:
            output += f"### ➡️ NO CHANGE - Same Issue Count\n\n"

        output += f"| Metric | Previous | Current | Change |\n"
        output += f"|--------|----------|---------|--------|\n"
        output += f"| Total Issues | {self.old.total_issues} | {self.new.total_issues} | {net_change:+d} ({pct_change:+.1f}%) |\n"
        output += f"| Issues Fixed | - | - | {fixed_count} |\n"
        output += f"| New Issues | - | - | {new_count} |\n"
        output += f"| Vibe Debt Score | {self.old.vibe_debt_score} | {self.new.vibe_debt_score} | {vibe_change:+d} |\n"
        output += f"| BLOCKER | {self.old.blocker_count} | {self.new.blocker_count} | {self.new.blocker_count - self.old.blocker_count:+d} |\n"
        output += f"| CRITICAL | {self.old.critical_count} | {self.new.critical_count} | {self.new.critical_count - self.old.critical_count:+d} |\n"
        output += f"| HIGH | {self.old.high_count} | {self.new.high_count} | {self.new.high_count - self.old.high_count:+d} |\n"
        output += f"| MEDIUM | {self.old.medium_count} | {self.new.medium_count} | {self.new.medium_count - self.old.medium_count:+d} |\n"
        output += f"| LOW | {self.old.low_count} | {self.new.low_count} | {self.new.low_count - self.old.low_count:+d} |\n"

        return output

    def _by_category(self) -> str:
        """Show progress by category."""
        # Group old and new by detector
        old_by_detector = defaultdict(int)
        for sig in self.old_issues:
            detector = self.old_issues[sig].get('detector', 'unknown')
            old_by_detector[detector] += 1

        new_by_detector = defaultdict(int)
        for sig in self.new_issues:
            detector = self.new_issues[sig].get('detector', 'unknown')
            new_by_detector[detector] += 1

        # Calculate changes
        all_detectors = set(old_by_detector.keys()) | set(new_by_detector.keys())
        changes = []

        for detector in all_detectors:
            old_count = old_by_detector.get(detector, 0)
            new_count = new_by_detector.get(detector, 0)
            change = new_count - old_count

            if change != 0:
                changes.append((detector, old_count, new_count, change))

        # Sort by absolute change
        changes.sort(key=lambda x: abs(x[3]), reverse=True)

        output = "## Progress by Category\n\n"
        output += "| Category | Previous | Current | Change | Status |\n"
        output += "|----------|----------|---------|--------|--------|\n"

        for detector, old_count, new_count, change in changes[:15]:
            if change < 0:
                status = f"✅ {abs(change)} fixed"
            else:
                status = f"⚠️ {change} new"

            pct = (change / max(old_count, 1)) * 100
            output += f"| {detector.replace('_', ' ').title()} | {old_count} | {new_count} | {change:+d} ({pct:+.0f}%) | {status} |\n"

        if len(changes) > 15:
            output += f"\n*...and {len(changes) - 15} more categories*\n"

        return output

    def _top_improvements(self) -> str:
        """Show top improvements."""
        # Group fixed issues by detector
        fixed_by_detector = defaultdict(list)
        for sig in self.fixed_sigs:
            issue = self.old_issues[sig]
            detector = issue.get('detector', 'unknown')
            fixed_by_detector[detector].append(issue)

        if not fixed_by_detector:
            return "## Top Improvements\n\n*No issues fixed in this period.*\n"

        # Sort by count
        sorted_detectors = sorted(fixed_by_detector.items(),
                                 key=lambda x: len(x[1]),
                                 reverse=True)

        output = "## Top Improvements ✅\n\n"
        output += "### Categories with Most Fixes\n\n"

        for i, (detector, issues) in enumerate(sorted_detectors[:5], 1):
            count = len(issues)
            output += f"### {i}. {detector.replace('_', ' ').title()} ({count} fixed)\n\n"

            # Show sample fixed issues
            for j, issue in enumerate(issues[:3], 1):
                from pathlib import Path
                file_path = Path(issue.get('file', '')).name
                line = issue.get('line', 0)
                message = issue.get('message', '')[:60]
                output += f"   - `{file_path}:{line}` - {message}\n"

            if len(issues) > 3:
                output += f"   - *...and {len(issues)-3} more*\n"

            output += "\n"

        return output

    def _regressions(self) -> str:
        """Show regressions (new issues)."""
        # Group new issues by detector
        new_by_detector = defaultdict(list)
        for sig in self.new_sigs:
            issue = self.new_issues[sig]
            detector = issue.get('detector', 'unknown')
            new_by_detector[detector].append(issue)

        if not new_by_detector:
            return "## Regressions\n\n✅ **No new issues introduced!**\n"

        # Sort by count
        sorted_detectors = sorted(new_by_detector.items(),
                                 key=lambda x: len(x[1]),
                                 reverse=True)

        output = "## Regressions ⚠️\n\n"
        output += "### New Issues Introduced\n\n"

        for i, (detector, issues) in enumerate(sorted_detectors[:5], 1):
            count = len(issues)

            # Check severity
            critical = sum(1 for issue in issues if issue.get('severity') in ['BLOCKER', 'CRITICAL'])

            if critical > 0:
                output += f"### {i}. {detector.replace('_', ' ').title()} ({count} new) 🔴 {critical} CRITICAL\n\n"
            else:
                output += f"### {i}. {detector.replace('_', ' ').title()} ({count} new)\n\n"

            # Show sample new issues
            for j, issue in enumerate(issues[:3], 1):
                from pathlib import Path
                file_path = Path(issue.get('file', '')).name
                line = issue.get('line', 0)
                severity = issue.get('severity', 'UNKNOWN')
                message = issue.get('message', '')[:60]
                output += f"   - [{severity}] `{file_path}:{line}` - {message}\n"

            if len(issues) > 3:
                output += f"   - *...and {len(issues)-3} more*\n"

            output += "\n"

        return output

    def _trend_analysis(self) -> str:
        """Analyze trends."""
        fixed_count = len(self.fixed_sigs)
        new_count = len(self.new_sigs)
        net_change = new_count - fixed_count

        output = "## Trend Analysis\n\n"

        # Overall trend
        if net_change < -50:
            output += "### 🚀 Excellent Progress\n\n"
            output += f"You've fixed {fixed_count} issues and only introduced {new_count} new ones.\n"
            output += "At this rate, your codebase will be production-ready soon!\n\n"
        elif net_change < 0:
            output += "### ✅ Good Progress\n\n"
            output += f"You're moving in the right direction with a net reduction of {abs(net_change)} issues.\n"
            output += "Keep up the momentum!\n\n"
        elif net_change == 0:
            output += "### ➡️ Maintaining Status\n\n"
            output += f"You fixed {fixed_count} issues but introduced {new_count} new ones.\n"
            output += "Focus on preventing new issues while fixing existing ones.\n\n"
        else:
            output += "### ⚠️ Needs Attention\n\n"
            output += f"You introduced {new_count} new issues while fixing {fixed_count}.\n"
            output += "Review your development process to prevent regressions.\n\n"

        # Vibe debt trend
        vibe_change = self.new.vibe_debt_score - self.old.vibe_debt_score
        if vibe_change < 0:
            output += f"**Vibe Debt:** Improved by {abs(vibe_change)} points ✅\n"
        elif vibe_change > 0:
            output += f"**Vibe Debt:** Increased by {vibe_change} points ⚠️\n"
        else:
            output += f"**Vibe Debt:** Unchanged at {self.new.vibe_debt_score}/100\n"

        return output

    def _footer(self) -> str:
        """Generate report footer."""
        return """---

## Recommendations

1. **Celebrate Wins:** Acknowledge progress with the team
2. **Address Regressions:** Review why new issues were introduced
3. **Maintain Momentum:** Keep fixing issues at current pace
4. **Re-scan Regularly:** Weekly scans track progress effectively

**Next Steps:**
- Focus on high-severity issues
- Review code review process for regressions
- Share this report with the team

*Generated by Code Archaeologist - Progress Tracker*
"""

    def save_to_file(self, output_path: str):
        """Save report to file."""
        report = self.generate()
        with open(output_path, 'w') as f:
            f.write(report)


def generate_comparison_report(old_results, new_results,
                               output_path: str = None) -> str:
    """
    Generate comparison report between two scans.

    Args:
        old_results: Previous ScanResults object
        new_results: Current ScanResults object
        output_path: Optional path to save report

    Returns:
        Markdown report as string
    """
    reporter = ComparisonReport(old_results, new_results)
    report = reporter.generate()

    if output_path:
        reporter.save_to_file(output_path)

    return report
