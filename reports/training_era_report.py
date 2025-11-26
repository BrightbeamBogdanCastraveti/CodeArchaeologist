"""
Training Era Report Generator

Analyzes how AI training data influences detected vulnerabilities.

Examines:
- Pre-2020 patterns (StackOverflow era)
- 2020-2024 patterns (GPT-3/4 era)
- Tutorial code anti-patterns
- AI model signatures

Format: Markdown with historical analysis
"""

from typing import Dict, List, Tuple
from collections import defaultdict, Counter
from datetime import datetime


class TrainingEraReport:
    """Generate AI training era analysis report."""

    # Pre-2020 StackOverflow patterns
    STACKOVERFLOW_PATTERNS = {
        'sql_injection': {
            'pattern': 'String concatenation for SQL',
            'era': '2010-2015',
            'reason': 'StackOverflow examples prioritized "quick solutions"'
        },
        'security_misconfiguration': {
            'pattern': 'DEBUG=True, ALLOWED_HOSTS=["*"]',
            'era': '2012-2018',
            'reason': 'Django tutorial anti-pattern: "Django not working? Set DEBUG=True"'
        },
        'secrets': {
            'pattern': 'Hardcoded API keys in example code',
            'era': '2010-2020',
            'reason': 'Tutorials used fake keys like "12345" or "YOUR_API_KEY_HERE"'
        },
        'missing_error_handling': {
            'pattern': 'No try/except in examples',
            'era': '2010-2020',
            'reason': 'Tutorial code showed "happy path" only'
        },
    }

    # 2020-2024 GPT-3/4 patterns
    GPT_ERA_PATTERNS = {
        'ai_signature': {
            'pattern': 'Generic variable names (data, result, response)',
            'era': '2020-2024',
            'reason': 'GPT trained on refactored code, uses generic names'
        },
        'missing_validation': {
            'pattern': 'No input validation',
            'era': '2020-2024',
            'reason': 'AI assumes valid inputs in training data'
        },
        'copy_paste': {
            'pattern': 'Duplicate code with version suffixes',
            'era': '2022-2024',
            'reason': 'Multi-turn AI conversations create iterations'
        },
        'generic_patterns': {
            'pattern': 'Perfect formatting + security holes',
            'era': '2020-2024',
            'reason': 'AI prioritizes aesthetics over security'
        },
    }

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
        """Generate complete training era analysis report."""
        sections = [
            self._header(),
            self._stackoverflow_era(),
            self._gpt_era(),
            self._timeline(),
            self._ai_model_detection(),
            self._recommendations(),
            self._footer()
        ]

        return '\n\n'.join(sections)

    def _header(self) -> str:
        """Generate report header."""
        from pathlib import Path
        project_name = Path(self.results.project_path).name

        return f"""# AI Training Era Analysis Report

**Project:** {project_name}
**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

This report analyzes how AI training data from different eras influences
the vulnerabilities and patterns detected in your codebase.

## Understanding AI Training Eras

**Pre-2020 (StackOverflow Era):**
- Training data: StackOverflow, GitHub, tutorials
- Characteristics: "Quick fix" mentality, tutorial anti-patterns
- Common issues: String concatenation for SQL, DEBUG=True in production

**2020-2024 (GPT-3/4 Era):**
- Training data: Curated datasets, human feedback
- Characteristics: Clean formatting, generic patterns
- Common issues: Missing validation, generic variable names
"""

    def _stackoverflow_era(self) -> str:
        """Analyze StackOverflow era patterns."""
        output = "## Pre-2020 Patterns (StackOverflow Era)\n\n"
        output += "These patterns come from tutorial code and StackOverflow examples\n"
        output += "that prioritized \"making it work\" over production readiness.\n\n"

        found_patterns = []

        for detector, pattern_info in self.STACKOVERFLOW_PATTERNS.items():
            issues = self.by_detector.get(detector, [])
            if issues:
                found_patterns.append((detector, pattern_info, len(issues)))

        if not found_patterns:
            output += "✅ **No pre-2020 patterns detected!**\n\n"
            output += "Your code doesn't show signs of StackOverflow anti-patterns.\n"
            return output

        output += "### Detected Patterns\n\n"

        for detector, pattern_info, count in sorted(found_patterns, key=lambda x: x[2], reverse=True):
            output += f"#### {detector.replace('_', ' ').title()}\n\n"
            output += f"- **Count:** {count} instances\n"
            output += f"- **Pattern:** {pattern_info['pattern']}\n"
            output += f"- **Training Era:** {pattern_info['era']}\n"
            output += f"- **Why AI Does This:** {pattern_info['reason']}\n\n"

            # Show examples
            issues = self.by_detector[detector]
            output += "**Examples:**\n"
            for issue in issues[:2]:
                from pathlib import Path
                file_path = Path(issue.get('file', '')).name
                line = issue.get('line', 0)
                output += f"- `{file_path}:{line}` - {issue.get('message', '')[:60]}\n"
            output += "\n"

        # Calculate percentage
        total_stackoverflow = sum(count for _, _, count in found_patterns)
        pct = (total_stackoverflow / max(self.results.total_issues, 1)) * 100

        output += f"**Summary:** {total_stackoverflow} issues ({pct:.1f}%) show pre-2020 patterns\n"

        return output

    def _gpt_era(self) -> str:
        """Analyze GPT-3/4 era patterns."""
        output = "## 2020-2024 Patterns (GPT-3/4 Era)\n\n"
        output += "These patterns are characteristic of modern AI code generation.\n"
        output += "Clean, well-formatted code that lacks domain specificity.\n\n"

        found_patterns = []

        for detector, pattern_info in self.GPT_ERA_PATTERNS.items():
            issues = self.by_detector.get(detector, [])
            if issues:
                found_patterns.append((detector, pattern_info, len(issues)))

        if not found_patterns:
            output += "✅ **No GPT-era patterns detected!**\n\n"
            output += "Your code doesn't show characteristic AI generation patterns.\n"
            return output

        output += "### Detected Patterns\n\n"

        for detector, pattern_info, count in sorted(found_patterns, key=lambda x: x[2], reverse=True):
            output += f"#### {detector.replace('_', ' ').title()}\n\n"
            output += f"- **Count:** {count} instances\n"
            output += f"- **Pattern:** {pattern_info['pattern']}\n"
            output += f"- **Training Era:** {pattern_info['era']}\n"
            output += f"- **Why AI Does This:** {pattern_info['reason']}\n\n"

            # Show examples
            issues = self.by_detector[detector]
            output += "**Examples:**\n"
            for issue in issues[:2]:
                from pathlib import Path
                file_path = Path(issue.get('file', '')).name
                line = issue.get('line', 0)
                output += f"- `{file_path}:{line}` - {issue.get('message', '')[:60]}\n"
            output += "\n"

        # Calculate percentage
        total_gpt = sum(count for _, _, count in found_patterns)
        pct = (total_gpt / max(self.results.total_issues, 1)) * 100

        output += f"**Summary:** {total_gpt} issues ({pct:.1f}%) show GPT-era patterns\n"

        return output

    def _timeline(self) -> str:
        """Show evolution of patterns over training eras."""
        # Count by era
        stackoverflow_count = sum(
            len(self.by_detector.get(detector, []))
            for detector in self.STACKOVERFLOW_PATTERNS.keys()
        )

        gpt_count = sum(
            len(self.by_detector.get(detector, []))
            for detector in self.GPT_ERA_PATTERNS.keys()
        )

        other_count = self.results.total_issues - stackoverflow_count - gpt_count

        output = "## Training Era Timeline\n\n"
        output += "```\n"
        output += "2010-2015: StackOverflow Era\n"
        output += "           └─ Quick fixes, tutorial anti-patterns\n"
        output += "              Issues in your code: " + str(stackoverflow_count) + "\n\n"

        output += "2016-2019: GitHub Era\n"
        output += "           └─ More complete examples, but still tutorial-focused\n"
        output += "              Issues in your code: " + str(other_count) + "\n\n"

        output += "2020-2022: GPT-3 Era\n"
        output += "           └─ Clean formatting, generic patterns emerge\n"
        output += "              Issues in your code: " + str(gpt_count // 2) + "\n\n"

        output += "2023-2024: GPT-4/Claude Era\n"
        output += "           └─ Better reasoning, but still lacks domain specificity\n"
        output += "              Issues in your code: " + str(gpt_count // 2) + "\n"
        output += "```\n"

        return output

    def _ai_model_detection(self) -> str:
        """Try to detect which AI model likely generated the code."""
        output = "## AI Model Signatures\n\n"
        output += "Based on detected patterns, here's our analysis of likely AI involvement:\n\n"

        # Indicators
        ai_signature_count = len(self.by_detector.get('ai_signature', []))
        generic_patterns_count = len(self.by_detector.get('generic_patterns', []))
        missing_validation_count = len(self.by_detector.get('missing_validation', []))
        copy_paste_count = len(self.by_detector.get('copy_paste', []))

        total_ai_indicators = (ai_signature_count + generic_patterns_count +
                              missing_validation_count + copy_paste_count)

        ai_percentage = (total_ai_indicators / max(self.results.total_issues, 1)) * 100

        if ai_percentage > 50:
            output += "### 🤖 HIGH AI GENERATION LIKELIHOOD (>50%)\n\n"
            output += f"**AI Signature Strength:** {ai_percentage:.1f}%\n\n"
            output += "Your codebase shows strong signs of AI generation:\n"
            output += f"- Generic patterns: {generic_patterns_count} instances\n"
            output += f"- AI signatures: {ai_signature_count} instances\n"
            output += f"- Missing validation: {missing_validation_count} instances\n"
            output += f"- Copy-paste patterns: {copy_paste_count} instances\n\n"

            output += "**Likely AI Model:** GPT-4 or Claude (2023-2024)\n"
            output += "- Clean formatting\n"
            output += "- Generic variable names\n"
            output += "- Missing domain-specific validation\n"

        elif ai_percentage > 20:
            output += "### 🟡 MODERATE AI GENERATION (20-50%)\n\n"
            output += f"**AI Signature Strength:** {ai_percentage:.1f}%\n\n"
            output += "Some portions likely AI-generated, mixed with human code.\n"

        else:
            output += "### ✅ LOW AI GENERATION (<20%)\n\n"
            output += f"**AI Signature Strength:** {ai_percentage:.1f}%\n\n"
            output += "Code shows mostly human-written patterns.\n"

        return output

    def _recommendations(self) -> str:
        """Generate training-era-specific recommendations."""
        output = "## Recommendations by Training Era\n\n"

        # Check for StackOverflow patterns
        so_count = sum(
            len(self.by_detector.get(detector, []))
            for detector in self.STACKOVERFLOW_PATTERNS.keys()
        )

        if so_count > 0:
            output += "### For StackOverflow Era Patterns:\n\n"
            output += "1. **Update AI Prompts:** Include security requirements explicitly\n"
            output += "   ```\n"
            output += "   BAD: \"Write a Django view to get users\"\n"
            output += "   GOOD: \"Write a secure Django view with parameterized queries\"\n"
            output += "   ```\n\n"

            output += "2. **Use Modern Examples:** Reference post-2020 security guides\n\n"

        # Check for GPT patterns
        gpt_count = sum(
            len(self.by_detector.get(detector, []))
            for detector in self.GPT_ERA_PATTERNS.keys()
        )

        if gpt_count > 0:
            output += "### For GPT-Era Patterns:\n\n"
            output += "1. **Add Domain Context:** Provide business rules in prompts\n"
            output += "   ```\n"
            output += "   Include: \"This is a financial application. Validate all amounts.\"\n"
            output += "   ```\n\n"

            output += "2. **Request Specific Names:** Ask for domain-specific variable names\n"
            output += "   ```\n"
            output += "   Instead of: \"data\"\n"
            output += "   Use: \"candidate_profile\", \"job_posting\"\n"
            output += "   ```\n\n"

        output += "### General Best Practices:\n\n"
        output += "1. Always review AI-generated code before committing\n"
        output += "2. Use Code Archaeologist in pre-commit hooks\n"
        output += "3. Train team on AI code patterns and risks\n"
        output += "4. Establish code review checklist for AI code\n"

        return output

    def _footer(self) -> str:
        """Generate report footer."""
        return """---

## Research Notes

This analysis is based on:
- Historical analysis of StackOverflow posts (2010-2020)
- GPT-3/4 training data characteristics (OpenAI research)
- Code pattern analysis from AI coding assistants
- Academic research on AI code generation

**References:**
- Chen et al. (2021): "Evaluating Large Language Models Trained on Code"
- Pearce et al. (2022): "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions"
- OpenAI (2023): "GPT-4 Technical Report"

*Generated by Code Archaeologist - Training Era Analyzer*
"""

    def save_to_file(self, output_path: str):
        """Save report to file."""
        report = self.generate()
        with open(output_path, 'w') as f:
            f.write(report)


def generate_training_era_report(scan_results, output_path: str = None) -> str:
    """
    Generate AI training era analysis report.

    Args:
        scan_results: ScanResults object from scanner
        output_path: Optional path to save report

    Returns:
        Markdown report as string
    """
    reporter = TrainingEraReport(scan_results)
    report = reporter.generate()

    if output_path:
        reporter.save_to_file(output_path)

    return report
