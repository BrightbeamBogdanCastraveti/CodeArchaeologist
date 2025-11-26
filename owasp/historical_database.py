"""
OWASP Historical Database - Master Interface

Provides unified access to all OWASP Top 10 versions (2013, 2017, 2021, 2024)
and training era analysis.

This is the core of Code Archaeologist's unique "archaeological" analysis:
- Track how vulnerabilities evolved over 10+ years
- Map vulnerabilities to AI training eras
- Explain why AI models generate specific vulnerable patterns
- Show historical persistence of vulnerabilities

Example Usage:
    db = OWASPHistoricalDatabase()
    evolution = db.trace_vulnerability_evolution('sql_injection')
    # Shows: A1 (2013) -> A1 (2017) -> A03 (2021)

    eras = db.map_to_training_eras('sql_injection')
    # Shows: Present in GPT-2, Codex, GPT-4 training data
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime

# Import all OWASP versions
from . import owasp_2013
from . import owasp_2017
from . import owasp_2021
from . import owasp_2024
from .training_era_mapper import TrainingEraMapper


@dataclass
class VulnerabilityEvolution:
    """Tracks how a vulnerability evolved across OWASP versions."""
    vulnerability_type: str
    rank_2013: Optional[str]
    rank_2017: Optional[str]
    rank_2021: Optional[str]
    rank_2024: Optional[str]
    trend: str  # 'rising', 'falling', 'stable', 'new', 'removed'
    persistence_years: int  # How many years in Top 10
    training_eras: List[str]
    why_ai_generates: str


class OWASPHistoricalDatabase:
    """
    Master database for OWASP Top 10 historical analysis.

    Provides:
    - Evolution tracking across versions
    - Training era mapping
    - AI generation explanations
    - Vulnerability persistence analysis
    """

    def __init__(self):
        """Initialize the historical database."""
        self.owasp_2013 = owasp_2013
        self.owasp_2017 = owasp_2017
        self.owasp_2021 = owasp_2021
        self.owasp_2024 = owasp_2024
        self.era_mapper = TrainingEraMapper()

    def get_all_versions(self) -> Dict[str, Dict]:
        """Get all OWASP Top 10 versions."""
        return {
            '2013': self.owasp_2013.get_all_categories(),
            '2017': self.owasp_2017.get_all_categories(),
            '2021': self.owasp_2021.get_all_categories(),
            '2024': self.owasp_2024.get_all_categories()
        }

    def trace_vulnerability_evolution(self, vuln_type: str) -> VulnerabilityEvolution:
        """
        Trace how a vulnerability evolved across OWASP versions.

        Example:
            evolution = db.trace_vulnerability_evolution('sql_injection')
            # Returns: A1 (2013) -> A1 (2017) -> A03 (2021) -> A03 (2024)
        """
        # Map vulnerability types to OWASP categories
        vuln_mappings = {
            'sql_injection': {
                '2013': 'A1', '2017': 'A1', '2021': 'A03', '2024': 'A03'
            },
            'xss': {
                '2013': 'A3', '2017': 'A7', '2021': 'A03', '2024': 'A03'
            },
            'broken_access_control': {
                '2013': 'A4', '2017': 'A5', '2021': 'A01', '2024': 'A01'
            },
            'broken_authentication': {
                '2013': 'A2', '2017': 'A2', '2021': 'A07', '2024': 'A07'
            },
            'sensitive_data_exposure': {
                '2013': 'A6', '2017': 'A3', '2021': 'A02', '2024': 'A02'
            },
            'xxe': {
                '2013': None, '2017': 'A4', '2021': 'A05', '2024': 'A05'
            },
            'security_misconfiguration': {
                '2013': 'A5', '2017': 'A6', '2021': 'A05', '2024': 'A05'
            },
            'insecure_deserialization': {
                '2013': None, '2017': 'A8', '2021': 'A08', '2024': 'A08'
            },
            'vulnerable_components': {
                '2013': 'A9', '2017': 'A9', '2021': 'A06', '2024': 'A06'
            },
            'insufficient_logging': {
                '2013': None, '2017': 'A10', '2021': 'A09', '2024': 'A09'
            },
            'ssrf': {
                '2013': None, '2017': None, '2021': 'A10', '2024': 'A10'
            },
            'csrf': {
                '2013': 'A8', '2017': None, '2021': None, '2024': None
            },
            'unvalidated_redirects': {
                '2013': 'A10', '2017': None, '2021': None, '2024': None
            },
            'prompt_injection': {
                '2013': None, '2017': None, '2021': None, '2024': 'A08*'
            }
        }

        mapping = vuln_mappings.get(vuln_type, {})

        # Calculate trend
        ranks = [mapping.get(y) for y in ['2013', '2017', '2021', '2024']]
        ranks_numeric = []
        for r in ranks:
            if r and r != 'A08*':  # Handle predicted entries
                try:
                    ranks_numeric.append(int(r.replace('A', '').replace('0', '')))
                except:
                    pass

        if not any(ranks):
            trend = 'not_tracked'
        elif ranks[0] is None and ranks[-1] is not None:
            trend = 'new'
        elif ranks[0] is not None and ranks[-1] is None:
            trend = 'removed'
        elif len(ranks_numeric) >= 2:
            if ranks_numeric[-1] < ranks_numeric[0]:
                trend = 'rising'
            elif ranks_numeric[-1] > ranks_numeric[0]:
                trend = 'falling'
            else:
                trend = 'stable'
        else:
            trend = 'variable'

        # Calculate persistence
        persistence_years = sum(1 for r in ranks if r is not None)

        # Get training eras
        training_eras = self.era_mapper.map_vulnerability_to_eras(vuln_type)

        # Get explanation
        why_ai_generates = self.era_mapper.explain_why_ai_generated(vuln_type)

        return VulnerabilityEvolution(
            vulnerability_type=vuln_type,
            rank_2013=mapping.get('2013'),
            rank_2017=mapping.get('2017'),
            rank_2021=mapping.get('2021'),
            rank_2024=mapping.get('2024'),
            trend=trend,
            persistence_years=persistence_years * 3,  # Approximate years (3-4 year cycles)
            training_eras=[era['era'] for era in training_eras],
            why_ai_generates=why_ai_generates
        )

    def find_vulnerabilities_by_era(self, era: str) -> List[str]:
        """
        Find which vulnerabilities were in OWASP Top 10 during a specific training era.

        Example:
            vulns = db.find_vulnerabilities_by_era('codex')
            # Returns: All OWASP 2017/2021 vulnerabilities (Codex training period)
        """
        era_to_owasp = {
            'pre_ai': ['2013'],
            'early_ai': ['2013', '2017'],
            'transformer': ['2017'],
            'codex': ['2017', '2021'],
            'gpt4': ['2021'],
            'current': ['2021', '2024']
        }

        owasp_versions = era_to_owasp.get(era, [])
        vulnerabilities = set()

        for version in owasp_versions:
            if version == '2013':
                categories = self.owasp_2013.get_all_categories()
            elif version == '2017':
                categories = self.owasp_2017.get_all_categories()
            elif version == '2021':
                categories = self.owasp_2021.get_all_categories()
            elif version == '2024':
                categories = self.owasp_2024.get_all_categories()
            else:
                continue

            for rank, category in categories.items():
                vulnerabilities.add(category.name)

        return sorted(list(vulnerabilities))

    def analyze_codebase_archaeology(self, detected_vulnerabilities: List[Dict]) -> Dict:
        """
        Perform archaeological analysis of a codebase.

        Shows:
        - Which OWASP eras are represented
        - Which AI training periods contributed
        - Historical persistence of issues
        - Unique insights about code generation

        Args:
            detected_vulnerabilities: List of detected vulnerabilities with types

        Returns:
            Comprehensive archaeological analysis
        """
        # Map vulnerabilities to eras
        era_analysis = self.era_mapper.analyze_codebase_training_eras(detected_vulnerabilities)

        # Track OWASP version representation
        owasp_version_representation = {
            '2013': 0,
            '2017': 0,
            '2021': 0,
            '2024': 0
        }

        # Track persistence
        persistent_vulns = []  # Vulnerabilities in multiple OWASP versions

        for vuln in detected_vulnerabilities:
            vuln_type = vuln.get('type', '')
            evolution = self.trace_vulnerability_evolution(vuln_type)

            # Count OWASP version representation
            if evolution.rank_2013:
                owasp_version_representation['2013'] += 1
            if evolution.rank_2017:
                owasp_version_representation['2017'] += 1
            if evolution.rank_2021:
                owasp_version_representation['2021'] += 1
            if evolution.rank_2024:
                owasp_version_representation['2024'] += 1

            # Track persistent vulnerabilities
            if evolution.persistence_years >= 8:  # In Top 10 for 8+ years
                persistent_vulns.append({
                    'type': vuln_type,
                    'years': evolution.persistence_years,
                    'ranks': f"{evolution.rank_2013 or '-'} → {evolution.rank_2017 or '-'} → {evolution.rank_2021 or '-'} → {evolution.rank_2024 or '-'}"
                })

        return {
            'summary': {
                'total_vulnerabilities': len(detected_vulnerabilities),
                'owasp_eras_represented': sum(1 for v in owasp_version_representation.values() if v > 0),
                'training_eras_represented': era_analysis['era_span'],
                'dominant_era': era_analysis['dominant_era']
            },
            'owasp_version_breakdown': owasp_version_representation,
            'training_era_breakdown': era_analysis['era_breakdown'],
            'persistent_vulnerabilities': persistent_vulns,
            'archaeological_insight': era_analysis['archaeological_insight'],
            'key_findings': self._generate_key_findings(
                owasp_version_representation,
                era_analysis,
                persistent_vulns
            )
        }

    def _generate_key_findings(self, owasp_rep: Dict, era_analysis: Dict, persistent: List) -> List[str]:
        """Generate key archaeological findings."""
        findings = []

        # Check for ancient vulnerabilities
        if owasp_rep['2013'] > 0:
            findings.append(
                f"⚠️  Contains {owasp_rep['2013']} vulnerabilities from OWASP 2013 (10+ years old). "
                f"These are ANCIENT patterns that should have been fixed long ago."
            )

        # Check for persistent vulnerabilities
        if persistent:
            findings.append(
                f"🔴 Found {len(persistent)} vulnerabilities that have persisted in OWASP Top 10 "
                f"for 8+ years. These are the MOST COMMON and WELL-KNOWN vulnerabilities, yet "
                f"still appear in your code."
            )

        # Check dominant era
        dominant = era_analysis.get('dominant_era', '')
        if 'Codex' in dominant or 'Copilot' in dominant:
            findings.append(
                f"🤖 Most vulnerabilities match the Codex/Copilot Era (2021-2023). Strong evidence "
                f"of AI-generated code using models trained on 2017-2020 GitHub repositories."
            )

        # Check for new AI vulnerabilities
        if owasp_rep.get('2024', 0) > owasp_rep.get('2021', 0):
            findings.append(
                f"⚡ Contains vulnerabilities from OWASP 2024 draft (AI/ML security). These are NEW "
                f"attack surfaces that did not exist in AI training data."
            )

        # Check for span
        if era_analysis.get('era_span', 0) >= 4:
            findings.append(
                f"📚 Vulnerabilities span {era_analysis['era_span']} different AI training eras. "
                f"This codebase has 'archaeological layers' suggesting multiple generations of development."
            )

        return findings

    def get_vulnerability_timeline(self, vuln_type: str) -> str:
        """
        Generate a visual timeline showing vulnerability evolution.

        Returns ASCII timeline suitable for terminal display.
        """
        evolution = self.trace_vulnerability_evolution(vuln_type)

        timeline = f"""
VULNERABILITY EVOLUTION: {vuln_type.upper().replace('_', ' ')}
{'=' * 70}

2013: {evolution.rank_2013 or 'Not in Top 10'}  │ OWASP 2013
      {self._get_rank_bar(evolution.rank_2013)}
                                                  │
2017: {evolution.rank_2017 or 'Not in Top 10'}  │ OWASP 2017
      {self._get_rank_bar(evolution.rank_2017)}  │ ▼ GPT-2, early transformers trained
                                                  │
2021: {evolution.rank_2021 or 'Not in Top 10'}  │ OWASP 2021
      {self._get_rank_bar(evolution.rank_2021)}  │ ▼ Codex, Copilot trained (2017-2020 data)
                                                  │
2024: {evolution.rank_2024 or 'Not in Top 10'}  │ OWASP 2024 (draft)
      {self._get_rank_bar(evolution.rank_2024)}  │ ▼ GPT-4, Claude trained (2021 cutoff)

{'=' * 70}
Trend: {evolution.trend.upper()}
Persistence: {evolution.persistence_years} years in Top 10
Training Eras: {', '.join(evolution.training_eras)}

WHY AI GENERATES THIS:
{evolution.why_ai_generates}
"""
        return timeline

    def _get_rank_bar(self, rank: Optional[str]) -> str:
        """Generate a visual bar for rank."""
        if not rank:
            return '░░░░░░░░░░ (not ranked)'

        try:
            rank_num = int(rank.replace('A', '').replace('0', ''))
            bar_length = 11 - rank_num
            return '█' * bar_length + '░' * (10 - bar_length) + f' (#{rank_num})'
        except:
            return '░░░░░░░░░░ (predicted)'

    def generate_report(self, detected_vulnerabilities: List[Dict]) -> str:
        """
        Generate a comprehensive archaeological report for a codebase.

        This is the main report that shows the unique "archaeological" analysis.
        """
        analysis = self.analyze_codebase_archaeology(detected_vulnerabilities)

        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║          CODE ARCHAEOLOGY REPORT                                 ║
║          OWASP Historical Analysis                                ║
╚══════════════════════════════════════════════════════════════════╝

SUMMARY
{'=' * 70}
Total Vulnerabilities Analyzed: {analysis['summary']['total_vulnerabilities']}
OWASP Eras Represented: {analysis['summary']['owasp_eras_represented']}/4
AI Training Eras Represented: {analysis['summary']['training_eras_represented']}
Dominant Training Era: {analysis['summary']['dominant_era']}

OWASP VERSION BREAKDOWN
{'=' * 70}
"""

        for version, count in analysis['owasp_version_breakdown'].items():
            if count > 0:
                bar = '█' * min(count, 50)
                report += f"OWASP {version}: {bar} ({count} vulnerabilities)\n"

        report += f"""

TRAINING ERA BREAKDOWN
{'=' * 70}
"""

        for era, count in analysis['training_era_breakdown'].items():
            bar = '█' * min(count, 50)
            report += f"{era}: {bar} ({count} vulnerabilities)\n"

        if analysis['persistent_vulnerabilities']:
            report += f"""

PERSISTENT VULNERABILITIES (8+ years in OWASP Top 10)
{'=' * 70}
"""
            for vuln in analysis['persistent_vulnerabilities']:
                report += f"• {vuln['type']}: {vuln['years']} years - Evolution: {vuln['ranks']}\n"

        report += f"""

ARCHAEOLOGICAL INSIGHTS
{'=' * 70}
{analysis['archaeological_insight']}

KEY FINDINGS
{'=' * 70}
"""

        for finding in analysis['key_findings']:
            report += f"{finding}\n\n"

        report += """
╚══════════════════════════════════════════════════════════════════╝
"""

        return report


# Convenience functions
def get_historical_database() -> OWASPHistoricalDatabase:
    """Get an instance of the historical database."""
    return OWASPHistoricalDatabase()


def trace_vulnerability(vuln_type: str) -> VulnerabilityEvolution:
    """Quick function to trace a vulnerability's evolution."""
    db = OWASPHistoricalDatabase()
    return db.trace_vulnerability_evolution(vuln_type)


def generate_archaeology_report(vulnerabilities: List[Dict]) -> str:
    """Quick function to generate archaeological report."""
    db = OWASPHistoricalDatabase()
    return db.generate_report(vulnerabilities)
