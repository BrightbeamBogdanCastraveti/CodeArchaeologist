"""
Critical Path Report Generator

Shows the MINIMUM fixes needed to make code production-ready.

Unlike other reports that show all issues, this focuses on:
- What MUST be fixed (blockers)
- What SHOULD be fixed this sprint (critical)
- Time estimates for each fix
- Fastest path to deployment

Format: Markdown with actionable steps
"""

from typing import Dict, List, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


class CriticalPathReport:
    """Generate critical path to production report."""

    def __init__(self, scan_results):
        """Initialize with scan results."""
        self.results = scan_results
        self.findings = scan_results.findings

    def generate(self) -> str:
        """Generate complete critical path report."""
        sections = [
            self._header(),
            self._blockers(),
            self._critical_issues(),
            self._high_priority(),
            self._timeline(),
            self._quick_wins(),
            self._footer()
        ]

        return '\n\n'.join(sections)

    def _header(self) -> str:
        """Generate report header."""
        project_name = Path(self.results.project_path).name

        return f"""# Critical Path to Production

**Project:** {project_name}
**Current Status:** Not Production Ready
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

This report shows the **fastest path** to make your code production-ready.
Focus on these issues FIRST, in the order listed.
"""

    def _blockers(self) -> str:
        """Show blocker issues that prevent deployment."""
        blockers = [f for f in self.findings if f.get('severity') == 'BLOCKER']

        output = "## 🚨 BLOCKERS (Must Fix Before Any Deployment)\n\n"

        if not blockers:
            output += "✅ **No blockers detected!**\n\n"
            output += "You can proceed to fixing critical issues.\n"
            return output

        output += f"**Count:** {len(blockers)} issues\n"
        output += f"**Estimated Time:** {len(blockers) * 30} minutes\n\n"
        output += "**You cannot deploy until these are fixed:**\n\n"

        # Group by type
        by_type = defaultdict(list)
        for blocker in blockers:
            detector = blocker.get('detector', 'unknown')
            by_type[detector].append(blocker)

        for i, (detector, issues) in enumerate(sorted(by_type.items()), 1):
            first_issue = issues[0]
            file_path = Path(first_issue.get('file', '')).name
            line = first_issue.get('line', 0)
            message = first_issue.get('message', '')

            output += f"### {i}. {message}\n\n"
            output += f"- **Location:** `{file_path}:{line}`\n"
            output += f"- **Impact:** {self._get_impact(detector)}\n"
            output += f"- **Fix:** {first_issue.get('fix', 'See documentation')}\n"
            output += f"- **Time:** ~30 minutes\n\n"

            if len(issues) > 1:
                output += f"*{len(issues)-1} more similar issues in this file*\n\n"

        return output

    def _critical_issues(self) -> str:
        """Show critical issues to fix this sprint."""
        critical = [f for f in self.findings if f.get('severity') == 'CRITICAL']

        output = "## 🔴 CRITICAL (Fix This Sprint)\n\n"

        if not critical:
            output += "✅ **No critical issues!**\n\n"
            return output

        output += f"**Count:** {len(critical)} issues\n"
        output += f"**Estimated Time:** {len(critical) * 15 // 60} hours\n\n"

        # Group by detector and show top 5
        by_detector = defaultdict(list)
        for issue in critical:
            detector = issue.get('detector', 'unknown')
            by_detector[detector].append(issue)

        # Sort by count
        sorted_detectors = sorted(by_detector.items(), key=lambda x: len(x[1]), reverse=True)

        output += "**Top Critical Categories:**\n\n"

        for i, (detector, issues) in enumerate(sorted_detectors[:5], 1):
            count = len(issues)
            time_estimate = count * 15  # minutes

            output += f"### {i}. {detector.replace('_', ' ').title()}\n\n"
            output += f"- **Issues:** {count}\n"
            output += f"- **Impact:** {self._get_impact(detector)}\n"
            output += f"- **Time Estimate:** ~{time_estimate} minutes ({time_estimate // 60}h {time_estimate % 60}m)\n"
            output += f"- **Fix Strategy:** {self._get_fix_strategy(detector)}\n\n"

            # Show first 3 specific issues
            for j, issue in enumerate(issues[:3], 1):
                file_path = Path(issue.get('file', '')).name
                line = issue.get('line', 0)
                output += f"   {j}. `{file_path}:{line}` - {issue.get('message', '')[:60]}\n"

            if len(issues) > 3:
                output += f"   *...and {len(issues)-3} more*\n"

            output += "\n"

        if len(sorted_detectors) > 5:
            remaining = sum(len(issues) for _, issues in sorted_detectors[5:])
            output += f"*...and {len(sorted_detectors)-5} more categories ({remaining} issues)*\n\n"

        return output

    def _high_priority(self) -> str:
        """Show high priority issues."""
        high = [f for f in self.findings if f.get('severity') == 'HIGH']

        output = "## 🟡 HIGH PRIORITY (Recommended Before Production)\n\n"

        if not high:
            output += "✅ **No high priority issues!**\n\n"
            return output

        output += f"**Count:** {len(high)} issues\n"
        output += f"**Estimated Time:** {len(high) * 10 // 60} hours\n"
        output += f"**Recommendation:** Fix before going live, but not blockers.\n\n"

        # Just show summary by category
        by_detector = defaultdict(int)
        for issue in high:
            detector = issue.get('detector', 'unknown')
            by_detector[detector] += 1

        output += "**Summary by Category:**\n\n"
        for detector, count in sorted(by_detector.items(), key=lambda x: x[1], reverse=True)[:5]:
            output += f"- {detector.replace('_', ' ').title()}: {count} issues\n"

        output += "\n"
        return output

    def _timeline(self) -> str:
        """Generate timeline to production."""
        blockers = [f for f in self.findings if f.get('severity') == 'BLOCKER']
        critical = [f for f in self.findings if f.get('severity') == 'CRITICAL']
        high = [f for f in self.findings if f.get('severity') == 'HIGH']

        # Calculate time estimates
        blocker_hours = len(blockers) * 0.5  # 30 min each
        critical_hours = len(critical) * 0.25  # 15 min each
        high_hours = len(high) * 0.16  # 10 min each

        total_hours = blocker_hours + critical_hours + high_hours
        work_days = total_hours / 8  # Assuming 8-hour workdays

        output = "## 📅 Timeline to Production\n\n"

        today = datetime.now()

        if blockers:
            day1_end = today + timedelta(hours=blocker_hours)
            output += f"### Day 1: Fix Blockers\n"
            output += f"- **Tasks:** Fix {len(blockers)} blocker issues\n"
            output += f"- **Time:** ~{blocker_hours:.1f} hours\n"
            output += f"- **Completion:** {day1_end.strftime('%Y-%m-%d %H:%M')}\n"
            output += "- **Deploy:** Staging environment\n\n"
            start_day = 2
        else:
            output += "### ✅ No Blockers - Start with Critical\n\n"
            start_day = 1

        if critical:
            critical_days = max(1, int(critical_hours / 8))
            critical_end = today + timedelta(days=critical_days)
            output += f"### Day {start_day}-{start_day+critical_days-1}: Fix Critical Issues\n"
            output += f"- **Tasks:** Fix {len(critical)} critical issues\n"
            output += f"- **Time:** ~{critical_hours:.1f} hours\n"
            output += f"- **Completion:** {critical_end.strftime('%Y-%m-%d')}\n"
            output += "- **Deploy:** Production (with monitoring)\n\n"
            start_day += critical_days

        if high:
            high_days = max(1, int(high_hours / 8))
            high_end = today + timedelta(days=start_day + high_days - 1)
            output += f"### Day {start_day}+: High Priority (Post-Launch)\n"
            output += f"- **Tasks:** Fix {len(high)} high priority issues\n"
            output += f"- **Time:** ~{high_hours:.1f} hours\n"
            output += "- **Status:** Can deploy before these are fixed\n\n"

        output += f"### 🎯 Target Production Date\n\n"
        if work_days <= 1:
            output += f"**You can go live:** Today (after {total_hours:.1f}h of fixes)\n"
        elif work_days <= 5:
            target_date = today + timedelta(days=int(work_days))
            output += f"**You can go live:** {target_date.strftime('%Y-%m-%d')} ({work_days:.1f} work days)\n"
        else:
            target_date = today + timedelta(days=int(work_days))
            output += f"**You can go live:** {target_date.strftime('%Y-%m-%d')} (~{work_days:.0f} work days)\n"

        output += f"\n*This assumes {total_hours:.1f} hours of focused effort.*\n"

        return output

    def _quick_wins(self) -> str:
        """Show quick wins - easy fixes with high impact."""
        output = "## ⚡ Quick Wins (High Impact, Low Effort)\n\n"
        output += "These issues are easy to fix and have high security impact:\n\n"

        # Find specific quick win patterns
        quick_wins = []

        # Pattern 1: Hardcoded secrets
        for finding in self.findings:
            if finding.get('detector') == 'secrets':
                quick_wins.append({
                    'title': 'Move secrets to environment variables',
                    'impact': 'Prevents credential leaks',
                    'effort': '5 minutes',
                    'finding': finding
                })
                if len(quick_wins) >= 5:
                    break

        # Pattern 2: Missing @login_required
        if len(quick_wins) < 5:
            for finding in self.findings:
                if finding.get('detector') == 'auth_bypass' and 'missing auth' in finding.get('message', '').lower():
                    quick_wins.append({
                        'title': 'Add @login_required decorator',
                        'impact': 'Prevents unauthorized access',
                        'effort': '2 minutes',
                        'finding': finding
                    })
                    if len(quick_wins) >= 5:
                        break

        if quick_wins:
            for i, win in enumerate(quick_wins[:5], 1):
                file_path = Path(win['finding'].get('file', '')).name
                line = win['finding'].get('line', 0)

                output += f"### {i}. {win['title']}\n"
                output += f"- **Location:** `{file_path}:{line}`\n"
                output += f"- **Impact:** {win['impact']}\n"
                output += f"- **Effort:** {win['effort']}\n"
                output += f"- **Fix:** {win['finding'].get('fix', 'See docs')}\n\n"
        else:
            output += "*No obvious quick wins found. Focus on critical path.*\n"

        return output

    def _footer(self) -> str:
        """Generate report footer."""
        return """---

## Summary: Your Action Plan

1. **TODAY:** Fix all blockers (if any)
2. **THIS SPRINT:** Fix critical issues
3. **DEPLOY:** To production with monitoring
4. **POST-LAUNCH:** Address high priority issues
5. **RE-SCAN:** Weekly to track progress

**Remember:** Perfect is the enemy of done. Fix blockers and critical issues, then deploy.

*Generated by Code Archaeologist - Critical Path Analyzer*
"""

    def _get_impact(self, detector: str) -> str:
        """Get business impact description for detector."""
        impact_map = {
            'sql_injection': 'Database compromise, data theft',
            'xss': 'User account takeover, phishing',
            'secrets': 'Credential theft, API abuse',
            'auth_bypass': 'Unauthorized data access',
            'ssrf': 'Internal network access, cloud metadata theft',
            'command_injection': 'Server takeover',
            'prompt_injection': 'LLM jailbreak, data exfiltration',
        }
        return impact_map.get(detector, 'Security/reliability risk')

    def _get_fix_strategy(self, detector: str) -> str:
        """Get fix strategy for detector category."""
        strategy_map = {
            'sql_injection': 'Use ORM or parameterized queries',
            'auth_bypass': 'Add @login_required to all endpoints',
            'missing_error_handling': 'Add try/except blocks',
            'missing_validation': 'Validate all inputs at API boundary',
            'secrets': 'Move to environment variables',
        }
        return strategy_map.get(detector, 'See detector documentation')

    def save_to_file(self, output_path: str):
        """Save report to file."""
        report = self.generate()
        with open(output_path, 'w') as f:
            f.write(report)


def generate_critical_path_report(scan_results, output_path: str = None) -> str:
    """
    Generate critical path to production report.

    Args:
        scan_results: ScanResults object from scanner
        output_path: Optional path to save report

    Returns:
        Markdown report as string
    """
    reporter = CriticalPathReport(scan_results)
    report = reporter.generate()

    if output_path:
        reporter.save_to_file(output_path)

    return report
