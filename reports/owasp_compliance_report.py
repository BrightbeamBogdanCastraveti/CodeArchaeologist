"""
OWASP Compliance Report Generator

Checks compliance against:
- OWASP Top 10 2021
- OWASP LLM Top 10 2023

Output format: Markdown with compliance matrix
"""

from typing import Dict, List, Tuple
from collections import defaultdict
from datetime import datetime


# OWASP Top 10 2021 Mapping
OWASP_2021_CATEGORIES = {
    'A01:2021': {
        'name': 'Broken Access Control',
        'detectors': ['auth_bypass', 'csrf'],
        'severity_threshold': 'CRITICAL'
    },
    'A02:2021': {
        'name': 'Cryptographic Failures',
        'detectors': ['crypto_failures', 'secrets'],
        'severity_threshold': 'HIGH'
    },
    'A03:2021': {
        'name': 'Injection',
        'detectors': ['sql_injection', 'command_injection', 'email_injection', 'xss'],
        'severity_threshold': 'CRITICAL'
    },
    'A04:2021': {
        'name': 'Insecure Design',
        'detectors': ['race_conditions'],
        'severity_threshold': 'HIGH'
    },
    'A05:2021': {
        'name': 'Security Misconfiguration',
        'detectors': ['security_misconfiguration'],
        'severity_threshold': 'HIGH'
    },
    'A06:2021': {
        'name': 'Vulnerable Components',
        'detectors': ['supply_chain'],
        'severity_threshold': 'MEDIUM'
    },
    'A07:2021': {
        'name': 'Authentication Failures',
        'detectors': ['auth_bypass', 'secrets'],
        'severity_threshold': 'CRITICAL'
    },
    'A08:2021': {
        'name': 'Data Integrity Failures',
        'detectors': ['deserialization'],
        'severity_threshold': 'HIGH'
    },
    'A09:2021': {
        'name': 'Logging Failures',
        'detectors': ['info_exposure'],
        'severity_threshold': 'MEDIUM'
    },
    'A10:2021': {
        'name': 'Server-Side Request Forgery',
        'detectors': ['ssrf'],
        'severity_threshold': 'HIGH'
    },
}

# OWASP LLM Top 10 Mapping
OWASP_LLM_CATEGORIES = {
    'LLM01': {
        'name': 'Prompt Injection',
        'detectors': ['prompt_injection'],
        'severity_threshold': 'HIGH'
    },
    'LLM02': {
        'name': 'Insecure Output Handling',
        'detectors': ['insecure_output'],
        'severity_threshold': 'CRITICAL'
    },
    'LLM03': {
        'name': 'Training Data Poisoning',
        'detectors': ['training_poisoning'],
        'severity_threshold': 'MEDIUM'
    },
    'LLM04': {
        'name': 'Model Denial of Service',
        'detectors': ['model_dos', 'unbounded_consumption'],
        'severity_threshold': 'MEDIUM'
    },
    'LLM05': {
        'name': 'Supply Chain Vulnerabilities',
        'detectors': ['supply_chain'],
        'severity_threshold': 'MEDIUM'
    },
    'LLM06': {
        'name': 'Excessive Agency',
        'detectors': ['excessive_agency'],
        'severity_threshold': 'HIGH'
    },
    'LLM07': {
        'name': 'Sensitive Information Disclosure',
        'detectors': ['data_leakage'],
        'severity_threshold': 'MEDIUM'
    },
    'LLM08': {
        'name': 'Overreliance',
        'detectors': ['overreliance'],
        'severity_threshold': 'LOW'
    },
    'LLM09': {
        'name': 'Model Theft',
        'detectors': ['model_theft'],
        'severity_threshold': 'LOW'
    },
    'LLM10': {
        'name': 'Model Denial of Service',
        'detectors': ['unbounded_consumption'],
        'severity_threshold': 'MEDIUM'
    },
}


class OWASPComplianceReport:
    """Generate OWASP compliance assessment report."""

    def __init__(self, scan_results):
        """Initialize with scan results."""
        self.results = scan_results
        self.findings = scan_results.findings

        # Group findings by detector
        self.by_detector = defaultdict(list)
        for finding in self.findings:
            detector = finding.get('detector', 'unknown')
            self.by_detector[detector].append(finding)

    def generate(self) -> str:
        """Generate complete compliance report."""
        sections = [
            self._header(),
            self._owasp_2021_compliance(),
            self._owasp_llm_compliance(),
            self._overall_verdict(),
            self._recommendations(),
            self._footer()
        ]

        return '\n\n'.join(sections)

    def _header(self) -> str:
        """Generate report header."""
        from pathlib import Path
        project_name = Path(self.results.project_path).name

        return f"""# OWASP Compliance Report

**Project:** {project_name}
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Standards Checked:**
- OWASP Top 10 2021
- OWASP LLM Top 10 2023

---
"""

    def _owasp_2021_compliance(self) -> str:
        """Check OWASP Top 10 2021 compliance."""
        output = "## OWASP Top 10 2021 Compliance\n\n"
        output += "| Category | Name | Status | Issues | Risk Level |\n"
        output += "|----------|------|--------|--------|------------|\n"

        pass_count = 0
        warn_count = 0
        fail_count = 0

        for category_id, category_info in sorted(OWASP_2021_CATEGORIES.items()):
            name = category_info['name']
            detectors = category_info['detectors']
            threshold = category_info['severity_threshold']

            # Count issues from relevant detectors
            issues = []
            for detector in detectors:
                issues.extend(self.by_detector.get(detector, []))

            # Count critical/high issues
            critical_issues = [f for f in issues if f.get('severity') in ['BLOCKER', 'CRITICAL']]
            high_issues = [f for f in issues if f.get('severity') == 'HIGH']

            # Determine status
            if len(critical_issues) > 0:
                status = "❌ FAIL"
                risk = "CRITICAL"
                fail_count += 1
            elif len(high_issues) > 0 or len(issues) > 0:
                status = "⚠️ WARN"
                risk = "MEDIUM"
                warn_count += 1
            else:
                status = "✅ PASS"
                risk = "LOW"
                pass_count += 1

            output += f"| {category_id} | {name} | {status} | {len(issues)} | {risk} |\n"

        output += f"\n**Summary:** {pass_count}/10 PASS | {warn_count}/10 WARN | {fail_count}/10 FAIL\n"

        if fail_count > 0:
            output += "\n**Verdict:** ❌ NOT PRODUCTION READY\n"
        elif warn_count > 5:
            output += "\n**Verdict:** ⚠️ NEEDS IMPROVEMENT\n"
        else:
            output += "\n**Verdict:** ✅ ACCEPTABLE\n"

        return output

    def _owasp_llm_compliance(self) -> str:
        """Check OWASP LLM Top 10 compliance."""
        output = "## OWASP LLM Top 10 2023 Compliance\n\n"
        output += "| Category | Name | Status | Issues | Risk Level |\n"
        output += "|----------|------|--------|--------|------------|\n"

        pass_count = 0
        warn_count = 0
        fail_count = 0

        for category_id, category_info in sorted(OWASP_LLM_CATEGORIES.items()):
            name = category_info['name']
            detectors = category_info['detectors']

            # Count issues from relevant detectors
            issues = []
            for detector in detectors:
                issues.extend(self.by_detector.get(detector, []))

            # Count critical/high issues
            critical_issues = [f for f in issues if f.get('severity') in ['BLOCKER', 'CRITICAL']]
            high_issues = [f for f in issues if f.get('severity') == 'HIGH']

            # Determine status
            if len(critical_issues) > 0:
                status = "❌ FAIL"
                risk = "HIGH"
                fail_count += 1
            elif len(high_issues) > 0:
                status = "⚠️ WARN"
                risk = "MEDIUM"
                warn_count += 1
            elif len(issues) > 0:
                status = "⚠️ WARN"
                risk = "LOW"
                warn_count += 1
            else:
                status = "✅ PASS"
                risk = "MINIMAL"
                pass_count += 1

            output += f"| {category_id} | {name} | {status} | {len(issues)} | {risk} |\n"

        output += f"\n**Summary:** {pass_count}/10 PASS | {warn_count}/10 WARN | {fail_count}/10 FAIL\n"

        if fail_count > 0:
            output += "\n**LLM Security Status:** ❌ HIGH RISK\n"
        elif warn_count > 5:
            output += "\n**LLM Security Status:** ⚠️ MEDIUM RISK\n"
        else:
            output += "\n**LLM Security Status:** ✅ LOW RISK\n"

        return output

    def _overall_verdict(self) -> str:
        """Generate overall compliance verdict."""
        # Count critical issues
        critical = self.results.critical_count + self.results.blocker_count
        high = self.results.high_count

        output = "## Overall Security Posture\n\n"

        if critical > 50 or self.results.blocker_count > 0:
            output += "### 🔴 CRITICAL - Not Production Ready\n\n"
            output += f"- **Critical Issues:** {critical}\n"
            output += f"- **Blocker Issues:** {self.results.blocker_count}\n"
            output += "\n**Action Required:** Fix all critical and blocker issues before deployment.\n"

        elif critical > 20 or high > 50:
            output += "### 🟡 WARNING - Significant Risk\n\n"
            output += f"- **Critical Issues:** {critical}\n"
            output += f"- **High Issues:** {high}\n"
            output += "\n**Action Required:** Address critical issues this sprint.\n"

        elif critical > 0 or high > 20:
            output += "### 🟡 CAUTION - Moderate Risk\n\n"
            output += f"- **Critical Issues:** {critical}\n"
            output += f"- **High Issues:** {high}\n"
            output += "\n**Action Required:** Plan fixes within next 2 sprints.\n"

        else:
            output += "### ✅ ACCEPTABLE - Low Risk\n\n"
            output += f"- **Critical Issues:** {critical}\n"
            output += f"- **High Issues:** {high}\n"
            output += "\n**Status:** Code meets minimum security standards.\n"

        return output

    def _recommendations(self) -> str:
        """Generate compliance recommendations."""
        output = "## Compliance Recommendations\n\n"

        # Check specific categories
        sql_issues = len(self.by_detector.get('sql_injection', []))
        auth_issues = len(self.by_detector.get('auth_bypass', []))
        prompt_issues = len(self.by_detector.get('prompt_injection', []))

        if sql_issues > 0:
            output += "### 1. Fix Injection Vulnerabilities (A03:2021)\n\n"
            output += f"**Issues Found:** {sql_issues} SQL injection vulnerabilities\n\n"
            output += "**Action:** Use parameterized queries:\n"
            output += "```python\n"
            output += "# BAD\n"
            output += "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n\n"
            output += "# GOOD\n"
            output += "cursor.execute(\"SELECT * FROM users WHERE id=?\", (user_id,))\n"
            output += "```\n\n"

        if auth_issues > 0:
            output += "### 2. Implement Access Control (A01:2021)\n\n"
            output += f"**Issues Found:** {auth_issues} access control issues\n\n"
            output += "**Action:** Add authentication to all endpoints:\n"
            output += "```python\n"
            output += "@login_required\n"
            output += "@require_permission('can_edit')\n"
            output += "def edit_resource(resource_id):\n"
            output += "    # Check ownership\n"
            output += "    if resource.owner != current_user:\n"
            output += "        raise PermissionDenied()\n"
            output += "```\n\n"

        if prompt_issues > 0:
            output += "### 3. Secure LLM Prompts (LLM01)\n\n"
            output += f"**Issues Found:** {prompt_issues} prompt injection risks\n\n"
            output += "**Action:** Use message roles:\n"
            output += "```python\n"
            output += "# BAD\n"
            output += "prompt = f\"User: {user_input}\"\n\n"
            output += "# GOOD\n"
            output += "messages = [\n"
            output += "    {'role': 'system', 'content': 'You are a helpful assistant.'},\n"
            output += "    {'role': 'user', 'content': user_input}\n"
            output += "]\n"
            output += "```\n\n"

        output += "### General Recommendations\n\n"
        output += "1. Enable security scanning in CI/CD\n"
        output += "2. Implement security headers (HSTS, CSP, etc.)\n"
        output += "3. Regular dependency updates\n"
        output += "4. Security training for development team\n"
        output += "5. Quarterly penetration testing\n"

        return output

    def _footer(self) -> str:
        """Generate report footer."""
        return f"""---

**Compliance Standards:**
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP LLM Top 10 2023: https://owasp.org/www-project-top-10-for-large-language-model-applications/

**Next Steps:**
1. Review failed compliance categories
2. Prioritize fixes by severity
3. Re-scan after fixes applied
4. Maintain compliance with regular scans

*Generated by Code Archaeologist - OWASP Compliance Checker*
"""

    def save_to_file(self, output_path: str):
        """Save report to file."""
        report = self.generate()
        with open(output_path, 'w') as f:
            f.write(report)


def generate_owasp_compliance_report(scan_results, output_path: str = None) -> str:
    """
    Generate OWASP compliance report.

    Args:
        scan_results: ScanResults object from scanner
        output_path: Optional path to save report

    Returns:
        Markdown report as string
    """
    reporter = OWASPComplianceReport(scan_results)
    report = reporter.generate()

    if output_path:
        reporter.save_to_file(output_path)

    return report
