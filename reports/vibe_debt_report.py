"""
Vibe Debt Report Generator

Creates comprehensive markdown report analyzing vibe debt in codebase.

Output includes:
- Executive summary with vibe debt score
- Issue breakdown by category
- Top offending files
- Critical path to production
- Actionable recommendations
- Progress tracking (if multiple scans)

Format: Markdown
"""

from typing import Dict, List, Tuple
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class VibeDebtReport:
    """Generate comprehensive vibe debt analysis report."""

    def __init__(self, scan_results):
        """
        Initialize report generator.

        Args:
            scan_results: ScanResults object from scanner
        """
        self.results = scan_results
        self.findings = scan_results.findings

    def generate(self) -> str:
        """Generate complete markdown report."""
        report_sections = [
            self._header(),
            self._executive_summary(),
            self._issue_breakdown(),
            self._top_files(),
            self._critical_path(),
            self._recommendations(),
            self._footer()
        ]

        return '\n\n'.join(report_sections)

    def _header(self) -> str:
        """Generate report header."""
        project_name = Path(self.results.project_path).name
        return f"""# Vibe Debt Analysis Report

**Project:** {project_name}
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Generator:** Code Archaeologist v1.0
"""

    def _executive_summary(self) -> str:
        """Generate executive summary."""
        vibe_score = self.results.vibe_debt_score
        status = self._get_vibe_status(vibe_score)

        # Calculate vibe vs traditional split
        vibe_detectors = {'missing_error_handling', 'ai_signature', 'missing_validation',
                         'generic_patterns', 'copy_paste'}
        vibe_count = sum(1 for f in self.findings if f.get('detector') in vibe_detectors)
        traditional_count = len(self.findings) - vibe_count

        return f"""## Executive Summary

- **Files Scanned:** {self.results.files_scanned}
- **Lines Analyzed:** {self.results.lines_scanned:,}
- **Scan Duration:** {self.results.scan_duration:.2f}s
- **Total Issues:** {self.results.total_issues:,}
- **Vibe Debt Score:** {vibe_score}/100 ({status})

### Issue Distribution

- **Vibe Debt Issues:** {vibe_count} ({vibe_count/self.results.total_issues*100:.1f}%)
  - Missing Error Handling
  - Missing Validation
  - AI Signatures
  - Copy-Paste Patterns
  - Generic Code Patterns

- **Traditional OWASP Issues:** {traditional_count} ({traditional_count/self.results.total_issues*100:.1f}%)
  - SQL Injection, XSS, CSRF, etc.
  - Cryptographic Failures
  - Security Misconfigurations

### Severity Summary

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 BLOCKER | {self.results.blocker_count} | {self.results.blocker_count/max(self.results.total_issues,1)*100:.1f}% |
| 🔴 CRITICAL | {self.results.critical_count} | {self.results.critical_count/max(self.results.total_issues,1)*100:.1f}% |
| 🟡 HIGH | {self.results.high_count} | {self.results.high_count/max(self.results.total_issues,1)*100:.1f}% |
| 🟡 MEDIUM | {self.results.medium_count} | {self.results.medium_count/max(self.results.total_issues,1)*100:.1f}% |
| 🔵 LOW | {self.results.low_count} | {self.results.low_count/max(self.results.total_issues,1)*100:.1f}% |

**Average Confidence:** {self.results.average_confidence:.1f}%
"""

    def _issue_breakdown(self) -> str:
        """Break down issues by category."""
        # Group by detector
        by_detector = defaultdict(list)
        for finding in self.findings:
            detector = finding.get('detector', 'unknown')
            by_detector[detector].append(finding)

        # Sort by count
        sorted_detectors = sorted(by_detector.items(), key=lambda x: len(x[1]), reverse=True)

        # Generate breakdown
        breakdown = "## Issue Breakdown by Category\n\n"

        for i, (detector, findings) in enumerate(sorted_detectors[:10], 1):
            count = len(findings)
            pct = count / self.results.total_issues * 100

            # Get severity breakdown
            severities = defaultdict(int)
            for f in findings:
                severities[f.get('severity', 'UNKNOWN')] += 1

            breakdown += f"### {i}. {detector.replace('_', ' ').title()} ({count} issues, {pct:.1f}%)\n\n"
            breakdown += f"**Severity:** "
            breakdown += ', '.join(f"{sev}: {cnt}" for sev, cnt in sorted(severities.items()))
            breakdown += "\n\n"

            # Show sample issues
            breakdown += "**Sample Issues:**\n\n"
            for finding in findings[:3]:
                file_path = Path(finding.get('file', '')).name
                line = finding.get('line', 0)
                message = finding.get('message', 'No description')[:80]
                breakdown += f"- `{file_path}:{line}` - {message}\n"

            breakdown += "\n"

        if len(sorted_detectors) > 10:
            breakdown += f"\n*...and {len(sorted_detectors) - 10} more categories*\n"

        return breakdown

    def _top_files(self) -> str:
        """Show files with most issues."""
        # Group by file
        by_file = defaultdict(list)
        for finding in self.findings:
            file_path = finding.get('file', 'unknown')
            by_file[file_path].append(finding)

        # Sort by count
        sorted_files = sorted(by_file.items(), key=lambda x: len(x[1]), reverse=True)

        output = "## Top 10 Files by Issue Count\n\n"
        output += "| Rank | File | Issues | Critical | High | Medium | Low |\n"
        output += "|------|------|--------|----------|------|--------|-----|\n"

        for i, (file_path, findings) in enumerate(sorted_files[:10], 1):
            file_name = Path(file_path).name
            total = len(findings)

            # Count by severity
            critical = sum(1 for f in findings if f.get('severity') in ['BLOCKER', 'CRITICAL'])
            high = sum(1 for f in findings if f.get('severity') == 'HIGH')
            medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
            low = sum(1 for f in findings if f.get('severity') == 'LOW')

            output += f"| {i} | `{file_name}` | {total} | {critical} | {high} | {medium} | {low} |\n"

        return output

    def _critical_path(self) -> str:
        """Generate critical path to production."""
        # Get blockers and critical issues
        blockers = [f for f in self.findings if f.get('severity') == 'BLOCKER']
        critical = [f for f in self.findings if f.get('severity') == 'CRITICAL']
        high = [f for f in self.findings if f.get('severity') == 'HIGH']

        output = "## Critical Path to Production\n\n"
        output += "This is the **minimum** set of issues you must fix before deploying to production.\n\n"

        # Blockers
        if blockers:
            output += f"### 🚨 Blockers (MUST FIX - {len(blockers)} issues)\n\n"
            output += "**Cannot deploy until these are fixed:**\n\n"

            for i, finding in enumerate(blockers[:5], 1):
                file_path = Path(finding.get('file', '')).name
                line = finding.get('line', 0)
                message = finding.get('message', '')
                output += f"{i}. **{message}**\n"
                output += f"   - Location: `{file_path}:{line}`\n"
                output += f"   - Impact: Production security/reliability risk\n"
                output += f"   - Fix: {finding.get('fix', 'See documentation')}\n\n"
        else:
            output += "### ✅ No Blockers\n\n"
            output += "No critical blockers detected.\n\n"

        # Critical issues
        if critical:
            output += f"### 🔴 Critical (FIX THIS SPRINT - {len(critical)} issues)\n\n"
            output += "**Should fix before production:**\n\n"

            # Group critical by detector
            by_detector = defaultdict(list)
            for f in critical:
                by_detector[f.get('detector', 'unknown')].append(f)

            for detector, findings in list(by_detector.items())[:5]:
                count = len(findings)
                output += f"- **{detector.replace('_', ' ').title()}**: {count} issue(s)\n"

            if len(critical) > 20:
                output += f"\n*Total: {len(critical)} critical issues. Showing summary.*\n"
        else:
            output += "### ✅ No Critical Issues\n\n"

        # High priority
        if high:
            output += f"\n### 🟡 High Priority ({len(high)} issues)\n\n"
            output += "Recommended to fix before production.\n\n"
        else:
            output += "\n### ✅ No High Priority Issues\n\n"

        # Time estimate
        total_critical_issues = len(blockers) + len(critical)
        if total_critical_issues > 0:
            # Rough estimate: 30 min per blocker, 15 min per critical
            hours = (len(blockers) * 0.5) + (len(critical) * 0.25)
            days = hours / 8

            output += f"\n**Estimated Effort:**\n"
            output += f"- Blockers: ~{len(blockers) * 30} minutes\n"
            output += f"- Critical: ~{len(critical) * 15} minutes\n"
            output += f"- **Total: ~{hours:.1f} hours ({days:.1f} days)**\n"

        return output

    def _recommendations(self) -> str:
        """Generate actionable recommendations."""
        # Analyze top issues
        vibe_issues = sum(1 for f in self.findings if f.get('detector') in
                         {'missing_error_handling', 'missing_validation'})

        output = "## Recommendations\n\n"

        if vibe_issues > self.results.total_issues * 0.3:
            output += "### 1. Implement Error Handling Framework\n\n"
            output += "**Problem:** 30%+ of issues are missing error handling.\n\n"
            output += "**Solution:**\n"
            output += "```python\n"
            output += "# Create error handling decorator\n"
            output += "@handle_errors(log=True, reraise=False)\n"
            output += "def risky_operation():\n"
            output += "    # Your code here\n"
            output += "    pass\n"
            output += "```\n\n"

            output += "### 2. Add Input Validation Decorator\n\n"
            output += "**Problem:** Missing validation on API inputs.\n\n"
            output += "**Solution:**\n"
            output += "```python\n"
            output += "from pydantic import BaseModel\n\n"
            output += "class UserInput(BaseModel):\n"
            output += "    user_id: int\n"
            output += "    email: str\n\n"
            output += "@validate_input(UserInput)\n"
            output += "def process_user(data):\n"
            output += "    # data is validated\n"
            output += "    pass\n"
            output += "```\n\n"

        output += "### 3. Enable Pre-Commit Hooks\n\n"
        output += "**Install Code Archaeologist in CI/CD:**\n"
        output += "```yaml\n"
        output += "# .github/workflows/code-quality.yml\n"
        output += "- name: Scan for vibe debt\n"
        output += "  run: code-archaeologist scan . --fail-on-critical\n"
        output += "```\n\n"

        output += "### 4. Track Progress\n\n"
        output += "**Re-scan weekly to measure improvement:**\n"
        output += "```bash\n"
        output += "code-archaeologist scan . --output report.json\n"
        output += "code-archaeologist compare last-week.json report.json\n"
        output += "```\n"

        return output

    def _footer(self) -> str:
        """Generate report footer."""
        return f"""---

**Report Statistics:**
- False Positives Filtered: {self.results.false_positives_filtered}
- Confidence Level: {self.results.average_confidence:.1f}%
- Scan Performance: {int(self.results.lines_scanned / max(self.results.scan_duration, 0.1)):,} lines/sec

**Next Steps:**
1. Fix all BLOCKER issues (if any)
2. Address CRITICAL issues this sprint
3. Schedule HIGH priority fixes
4. Re-scan to verify improvements

*Generated by Code Archaeologist - Making AI-generated code production-ready*
"""

    def _get_vibe_status(self, score: int) -> str:
        """Get human-readable vibe debt status."""
        if score >= 80:
            return "🔴 Critical Vibe Debt"
        elif score >= 60:
            return "🟡 High Vibe Debt"
        elif score >= 40:
            return "🟢 Moderate Vibe Debt"
        elif score >= 20:
            return "🟢 Low Vibe Debt"
        else:
            return "✅ Minimal Vibe Debt"

    def save_to_file(self, output_path: str):
        """Save report to markdown file."""
        report = self.generate()
        with open(output_path, 'w') as f:
            f.write(report)


def generate_vibe_debt_report(scan_results, output_path: str = None) -> str:
    """
    Generate vibe debt report from scan results.

    Args:
        scan_results: ScanResults object from scanner
        output_path: Optional path to save report (default: vibe_debt_report.md)

    Returns:
        Markdown report as string
    """
    reporter = VibeDebtReport(scan_results)
    report = reporter.generate()

    if output_path:
        reporter.save_to_file(output_path)

    return report
