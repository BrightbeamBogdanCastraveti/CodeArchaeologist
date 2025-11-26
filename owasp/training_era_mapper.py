"""
Training Era Mapper

Maps vulnerabilities to AI training eras and explains why AI models
generate specific vulnerable patterns.

This is THE KEY DIFFERENTIATOR for Code Archaeologist:
- Shows which vulnerabilities come from which training era
- Explains which AI models learned which patterns
- Provides "archaeological" analysis of code generation
"""

from typing import List, Dict, Tuple
from datetime import datetime


class TrainingEraMapper:
    """Maps vulnerabilities to AI model training eras."""

    # AI Training Eras
    ERAS = {
        'pre_ai': {
            'name': 'Pre-AI Era',
            'years': (2000, 2012),
            'description': 'Before deep learning for code',
            'models': ['Static analysis tools', 'Simple pattern matching'],
            'owasp_versions': ['2004', '2007', '2010', '2013'],
            'note': 'Vulnerabilities from this era in modern AI code suggest training on very old examples'
        },
        'early_ai': {
            'name': 'Early AI Era',
            'years': (2013, 2017),
            'description': 'Early neural networks for code',
            'models': ['Word2Vec for code', 'Code2Vec', 'Early RNNs'],
            'owasp_versions': ['2013', '2017'],
            'github_data': 'GitHub data from 2013-2017',
            'stackoverflow_data': 'Stack Overflow from 2013-2017',
            'note': 'Limited AI code generation. Mostly research prototypes.'
        },
        'transformer': {
            'name': 'Transformer Era',
            'years': (2018, 2020),
            'description': 'Transformers applied to code',
            'models': ['GPT-2', 'BERT for code', 'CodeBERT', 'Early Codex prototypes'],
            'owasp_versions': ['2017'],
            'github_data': 'GitHub data from 2018-2020 (billions of lines)',
            'stackoverflow_data': 'Stack Overflow 2018-2020',
            'note': 'First practical AI code generation. Models trained on 2017-2019 code.'
        },
        'codex': {
            'name': 'Codex/Copilot Era',
            'years': (2021, 2023),
            'description': 'Production AI code assistants',
            'models': ['GPT-3', 'Codex', 'GitHub Copilot', 'CodeBERT', 'AlphaCode'],
            'owasp_versions': ['2021'],
            'github_data': 'GitHub data from 2017-2020 (training cutoff)',
            'stackoverflow_data': 'Stack Overflow through 2020',
            'note': 'MOST COMMON TRAINING ERA for current models. GPT-3 cutoff Sept 2021, Copilot trained on pre-2020 code.'
        },
        'gpt4': {
            'name': 'GPT-4/Claude Era',
            'years': (2023, 2024),
            'description': 'Advanced multimodal AI',
            'models': ['GPT-4', 'Claude 3', 'Gemini', 'Copilot X', 'CodeWhisperer'],
            'owasp_versions': ['2021', '2024 draft'],
            'github_data': 'GitHub through 2021-2023',
            'stackoverflow_data': 'Stack Overflow through 2023',
            'note': 'CURRENT ERA. Models trained on OWASP 2021-era code. New vulnerability: AI security flaws.'
        },
        'current': {
            'name': 'Current/Future Era',
            'years': (2024, 2025),
            'description': 'Emerging AI capabilities',
            'models': ['Claude 3.5', 'GPT-4o', 'o1', 'Gemini Pro', 'Claude Code'],
            'owasp_versions': ['2024 expected'],
            'note': 'Models being trained NOW. Will learn from 2021-2024 code including OWASP LLM Top 10.'
        }
    }

    @staticmethod
    def map_vulnerability_to_eras(vuln_type: str, owasp_category: str = None) -> List[Dict]:
        """
        Map a vulnerability type to the AI training eras that learned it.

        Args:
            vuln_type: Vulnerability type (e.g., 'sql_injection', 'xss')
            owasp_category: OWASP category code (e.g., 'A1', 'A03')

        Returns:
            List of eras where this vulnerability was present in training data
        """
        # Map common vulnerability types to OWASP categories and eras
        vuln_to_owasp = {
            'sql_injection': {
                'owasp_2013': 'A1',
                'owasp_2017': 'A1',
                'owasp_2021': 'A03',
                'first_documented': 1998,
                'eras': ['pre_ai', 'early_ai', 'transformer', 'codex', 'gpt4'],
                'prevalence': 'Very High in training data'
            },
            'xss': {
                'owasp_2013': 'A3',
                'owasp_2017': 'A7',
                'owasp_2021': 'A03 (merged)',
                'first_documented': 2000,
                'eras': ['pre_ai', 'early_ai', 'transformer', 'codex', 'gpt4'],
                'prevalence': 'Extremely High in training data'
            },
            'command_injection': {
                'owasp_2013': 'A1',
                'owasp_2017': 'A1',
                'owasp_2021': 'A03',
                'first_documented': 1995,
                'eras': ['pre_ai', 'early_ai', 'transformer', 'codex', 'gpt4'],
                'prevalence': 'High in training data'
            },
            'broken_access_control': {
                'owasp_2013': 'A4 (IDOR) + A7',
                'owasp_2017': 'A5',
                'owasp_2021': 'A01',
                'first_documented': 2002,
                'eras': ['pre_ai', 'early_ai', 'transformer', 'codex', 'gpt4'],
                'prevalence': 'HIGHEST in training data (most common vulnerability)'
            },
            'csrf': {
                'owasp_2013': 'A8',
                'owasp_2017': 'Removed from top 10',
                'owasp_2021': 'Not in top 10',
                'first_documented': 2001,
                'eras': ['pre_ai', 'early_ai', 'transformer'],
                'prevalence': 'Medium (declining in newer code)'
            },
            'ssrf': {
                'owasp_2013': 'Not in top 10',
                'owasp_2017': 'Not in top 10',
                'owasp_2021': 'A10 (NEW)',
                'first_documented': 2006,
                'eras': ['early_ai', 'transformer', 'codex', 'gpt4'],
                'prevalence': 'Medium but growing (cloud era)'
            },
            'xxe': {
                'owasp_2013': 'Not in top 10',
                'owasp_2017': 'A4 (NEW)',
                'owasp_2021': 'Merged into A05',
                'first_documented': 2002,
                'eras': ['pre_ai', 'early_ai', 'transformer', 'codex'],
                'prevalence': 'Medium (declining with modern parsers)'
            },
            'deserialization': {
                'owasp_2013': 'Not in top 10',
                'owasp_2017': 'A8 (NEW)',
                'owasp_2021': 'A08 (expanded)',
                'first_documented': 2003,
                'eras': ['pre_ai', 'early_ai', 'transformer', 'codex', 'gpt4'],
                'prevalence': 'Low but severe'
            },
            'prompt_injection': {
                'owasp_2013': 'Did not exist',
                'owasp_2017': 'Did not exist',
                'owasp_2021': 'Did not exist',
                'owasp_llm_2025': 'LLM01',
                'first_documented': 2022,
                'eras': ['gpt4', 'current'],
                'prevalence': 'NEW - Not in AI training data (targets AI itself)'
            },
            'insecure_output_handling': {
                'owasp_2013': 'Did not exist',
                'owasp_2017': 'Did not exist',
                'owasp_2021': 'Did not exist',
                'owasp_llm_2025': 'LLM02',
                'first_documented': 2023,
                'eras': ['gpt4', 'current'],
                'prevalence': 'NEW - Not in AI training data'
            },
        }

        vuln_info = vuln_to_owasp.get(vuln_type, {
            'eras': ['unknown'],
            'prevalence': 'Unknown'
        })

        result = []
        for era_key in vuln_info.get('eras', []):
            era_data = TrainingEraMapper.ERAS.get(era_key, {})
            result.append({
                'era': era_data.get('name', era_key),
                'years': era_data.get('years', (0, 0)),
                'models': era_data.get('models', []),
                'prevalence': vuln_info.get('prevalence'),
                'owasp_mapping': {
                    '2013': vuln_info.get('owasp_2013'),
                    '2017': vuln_info.get('owasp_2017'),
                    '2021': vuln_info.get('owasp_2021')
                }
            })

        return result

    @staticmethod
    def explain_why_ai_generated(vuln_type: str) -> str:
        """
        Explain WHY an AI model generated code with this vulnerability.

        This is the "archaeological" insight that makes Code Archaeologist unique.
        """
        explanations = {
            'sql_injection': (
                "SQL Injection has been in EVERY OWASP Top 10 since 2003 (#1 in 2013 and 2017). "
                "When GPT-3, Codex, and Copilot were trained (2018-2020), GitHub and Stack Overflow "
                "were FULL of vulnerable SQL concatenation examples. The AI learned that "
                "f\"SELECT * FROM users WHERE name = '{name}'\" is a COMMON pattern, even though "
                "it's vulnerable. The model optimized for 'code that looks like training data' not "
                "'secure code'. This pattern appears in ~8% of the training data (estimated)."
            ),
            'xss': (
                "XSS was #3 in OWASP 2013 and #7 in 2017. Training data from 2017-2020 contained "
                "millions of code examples where user input was directly embedded in HTML without "
                "escaping. Stack Overflow answers, GitHub repositories, and tutorials commonly showed "
                "document.write(userInput) or innerHTML = data. The AI learned this as a valid pattern "
                "for displaying dynamic content."
            ),
            'broken_access_control': (
                "Broken Access Control is the #1 vulnerability in OWASP 2021 and was common in 2017. "
                "Training data contained MASSIVE amounts of code like: "
                "'doc = Document.objects.get(id=doc_id)' without checking if the user owns the document. "
                "This is EASIER to write than proper access control, so it appeared more frequently in "
                "training data. The AI learned the COMMON pattern, not the SECURE pattern."
            ),
            'prompt_injection': (
                "CRITICAL: Prompt injection is a NEW vulnerability (2022+) that did not exist in AI "
                "training data. GPT-4 and Copilot were trained on code from before LLMs were common. "
                "The training data has NO examples of secure LLM integration because LLM apps didn't "
                "exist yet. This is why AI-generated AI applications are ESPECIALLY vulnerable - "
                "the AI has no training data on securing AI systems."
            ),
            'insecure_output_handling': (
                "LLM-specific vulnerability (OWASP LLM02). Did not exist before 2023. AI models trained "
                "on pre-2023 code have ZERO examples of securely handling LLM outputs. The AI generates "
                "code that directly uses LLM responses without validation because there's no training "
                "data showing the secure pattern."
            ),
        }

        return explanations.get(
            vuln_type,
            f"This vulnerability appears in AI-generated code because it was common in the model's "
            f"training data (2017-2020 GitHub repositories). The AI learned vulnerable patterns that "
            f"were FREQUENT, not patterns that were SECURE."
        )

    @staticmethod
    def get_training_data_timeline(vuln_type: str) -> List[Tuple[int, str, str]]:
        """
        Get a timeline showing when this vulnerability appeared in training data.

        Returns: List of (year, event, description) tuples
        """
        # Example timeline for SQL Injection
        if vuln_type == 'sql_injection':
            return [
                (1998, 'First documented', 'SQL injection attacks first documented'),
                (2003, 'OWASP Top 10', 'Included in first OWASP Top 10'),
                (2013, 'OWASP #1', 'Ranked #1 vulnerability'),
                (2017, 'OWASP #1', 'Still ranked #1'),
                (2018, 'Training data', 'GPT-2 trained on code with SQL injection patterns'),
                (2020, 'Codex training', 'Codex trained on GitHub (includes SQL injection examples)'),
                (2021, 'OWASP #3', 'Moved to #3 but still common'),
                (2023, 'AI generation', 'GPT-4/Copilot generate code with SQL injection from training data')
            ]

        # Example timeline for Prompt Injection
        elif vuln_type == 'prompt_injection':
            return [
                (2022, 'First attacks', 'Prompt injection attacks discovered'),
                (2023, 'Widespread', 'Prompt injection recognized as serious threat'),
                (2024, 'OWASP LLM01', 'Included in OWASP LLM Top 10'),
                (2024, 'AI blind spot', 'AI models have NO training data on this (targets AI itself)')
            ]

        return []

    @staticmethod
    def get_era_by_year(year: int) -> Dict:
        """Get the training era for a specific year."""
        for era_key, era_data in TrainingEraMapper.ERAS.items():
            years = era_data.get('years', (0, 0))
            if years[0] <= year <= years[1]:
                return {
                    'key': era_key,
                    **era_data
                }
        return {'key': 'unknown', 'name': 'Unknown Era'}

    @staticmethod
    def analyze_codebase_training_eras(vulnerabilities: List[Dict]) -> Dict:
        """
        Analyze which training eras contributed vulnerabilities to a codebase.

        Args:
            vulnerabilities: List of detected vulnerabilities with types

        Returns:
            Analysis showing which training eras are represented
        """
        era_counts = {}

        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            eras = TrainingEraMapper.map_vulnerability_to_eras(vuln_type)

            for era_info in eras:
                era_name = era_info['era']
                era_counts[era_name] = era_counts.get(era_name, 0) + 1

        return {
            'era_breakdown': era_counts,
            'dominant_era': max(era_counts.items(), key=lambda x: x[1])[0] if era_counts else 'Unknown',
            'era_span': len(era_counts),
            'archaeological_insight': TrainingEraMapper._generate_insight(era_counts)
        }

    @staticmethod
    def _generate_insight(era_counts: Dict) -> str:
        """Generate archaeological insight about the codebase."""
        if not era_counts:
            return "No vulnerabilities detected or unable to map to training eras."

        dominant_era = max(era_counts.items(), key=lambda x: x[1])[0]
        total_vulns = sum(era_counts.values())
        era_span = len(era_counts)

        if era_span >= 4:
            return (
                f"This codebase shows vulnerabilities from {era_span} different AI training eras "
                f"spanning 15+ years. The code has archaeological layers, suggesting multiple "
                f"generations of AI-assisted development or learning from very old examples. "
                f"Most vulnerabilities ({era_counts[dominant_era]}/{total_vulns}) come from the "
                f"{dominant_era}, indicating which AI model or training period had the most influence."
            )
        elif dominant_era == 'Codex/Copilot Era':
            return (
                f"Most vulnerabilities come from the Codex/Copilot Era (2021-2023). "
                f"This strongly suggests code generated by GPT-3, GitHub Copilot, or similar "
                f"models trained on 2017-2020 GitHub repositories. These models learned vulnerable "
                f"patterns that were COMMON in training data, not patterns that were SECURE."
            )
        else:
            return (
                f"Vulnerabilities primarily from {dominant_era}. This provides insight into "
                f"which AI training period or manual coding practices influenced this codebase."
            )
