"""
Pattern Explainer
Explains WHY AI models generate specific code patterns by analyzing training data origins
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path
import json


@dataclass
class PatternExplanation:
    """Detailed explanation of why AI learned a specific pattern"""
    pattern_id: str
    category: str
    vulnerable_code: str
    why_vulnerable: str
    why_ai_learned_this: str
    training_era: str
    ai_models_affected: List[str]
    stackoverflow_metadata: Dict
    historical_context: str
    modern_fix: str
    source_url: str


class PatternExplainer:
    """
    Explains code patterns by referencing their training data origins

    This tool helps developers understand WHY their AI coding assistant
    suggests certain patterns by tracing them back to StackOverflow posts
    and other training data sources.
    """

    def __init__(self, patterns_dir: str = "training_data_archive/stackoverflow"):
        self.patterns_dir = Path(patterns_dir)
        self.patterns = self._load_patterns()
        self._build_index()

    def _load_patterns(self) -> List[Dict]:
        """Load all archaeological patterns"""
        patterns = []

        if not self.patterns_dir.exists():
            return patterns

        for pattern_file in self.patterns_dir.glob("*_arch_*.json"):
            try:
                with open(pattern_file, 'r') as f:
                    pattern = json.load(f)
                    patterns.append(pattern)
            except Exception as e:
                print(f"Warning: Failed to load {pattern_file}: {e}")

        return patterns

    def _build_index(self):
        """Build searchable index of patterns"""
        self.by_category = {}
        self.by_era = {}
        self.by_model = {}

        for pattern in self.patterns:
            # Index by category
            cat = pattern.get('category', 'unknown')
            if cat not in self.by_category:
                self.by_category[cat] = []
            self.by_category[cat].append(pattern)

            # Index by training era
            era = pattern.get('training_era', 'unknown')
            if era not in self.by_era:
                self.by_era[era] = []
            self.by_era[era].append(pattern)

            # Index by AI model
            for model in pattern.get('ai_models_affected', []):
                if model not in self.by_model:
                    self.by_model[model] = []
                self.by_model[model].append(pattern)

    def explain_pattern(self, pattern_id: str) -> Optional[PatternExplanation]:
        """Get detailed explanation for a specific pattern"""
        for pattern in self.patterns:
            if pattern.get('id') == pattern_id:
                return self._create_explanation(pattern)
        return None

    def explain_category(self, category: str) -> List[PatternExplanation]:
        """Get explanations for all patterns in a category"""
        patterns = self.by_category.get(category, [])
        return [self._create_explanation(p) for p in patterns]

    def explain_code_snippet(self, code: str) -> List[PatternExplanation]:
        """
        Find and explain patterns that match a code snippet

        Args:
            code: Code snippet to analyze

        Returns:
            List of pattern explanations that match the code
        """
        matches = []

        for pattern in self.patterns:
            vulnerable_code = pattern.get('vulnerable_code', '')

            # Simple matching - check for key elements
            if self._code_matches_pattern(code, vulnerable_code):
                matches.append(self._create_explanation(pattern))

        return matches

    def _code_matches_pattern(self, code: str, pattern_code: str) -> bool:
        """Check if code snippet matches a pattern"""
        # Extract key functions/keywords from pattern
        keywords = []

        # SQL injection indicators
        if 'format(' in pattern_code or '.format' in pattern_code:
            keywords.append('format')
        if 'execute(' in pattern_code:
            keywords.append('execute')
        if '%s' in pattern_code:
            keywords.append('%s')

        # Command injection indicators
        if 'shell=True' in pattern_code:
            keywords.append('shell=True')
        if 'os.system' in pattern_code:
            keywords.append('os.system')
        if 'eval(' in pattern_code or 'exec(' in pattern_code:
            keywords.extend(['eval', 'exec'])
        if 'pickle' in pattern_code:
            keywords.append('pickle')

        # XSS indicators
        if '|safe' in pattern_code:
            keywords.append('|safe')
        if 'mark_safe' in pattern_code:
            keywords.append('mark_safe')

        # Check if code contains these keywords
        return any(keyword in code for keyword in keywords)

    def _create_explanation(self, pattern: Dict) -> PatternExplanation:
        """Create explanation object from pattern data"""
        return PatternExplanation(
            pattern_id=pattern.get('id', 'unknown'),
            category=pattern.get('category', 'unknown'),
            vulnerable_code=pattern.get('vulnerable_code', ''),
            why_vulnerable=pattern.get('why_vulnerable', ''),
            why_ai_learned_this=self._format_why_learned(pattern.get('why_ai_learned_this', '')),
            training_era=pattern.get('training_era', 'unknown'),
            ai_models_affected=pattern.get('ai_models_affected', []),
            stackoverflow_metadata=pattern.get('stackoverflow_metadata', {}),
            historical_context=pattern.get('historical_context', ''),
            modern_fix=self._format_modern_fix(pattern.get('modern_fix', '')),
            source_url=pattern.get('source_url', '')
        )

    def _format_why_learned(self, why_learned) -> str:
        """Format the 'why AI learned this' field"""
        if isinstance(why_learned, str):
            return why_learned
        elif isinstance(why_learned, dict):
            parts = []
            for key, value in why_learned.items():
                parts.append(f"{key}: {value}")
            return "\n".join(parts)
        else:
            return str(why_learned)

    def _format_modern_fix(self, modern_fix) -> str:
        """Format the modern fix field"""
        if isinstance(modern_fix, str):
            return modern_fix
        elif isinstance(modern_fix, dict):
            description = modern_fix.get('Description', '')
            example = modern_fix.get('Example', '')
            if example:
                if isinstance(example, dict):
                    example = str(example)
                return f"{description}\n\nExample:\n{example}"
            return description
        else:
            return str(modern_fix)

    def generate_explanation_report(self, explanation: PatternExplanation) -> str:
        """Generate human-readable explanation report"""
        report = "="*70 + "\n"
        report += f"PATTERN EXPLANATION: {explanation.pattern_id}\n"
        report += "="*70 + "\n\n"

        report += f"Category: {explanation.category.upper()}\n"
        report += f"Training Era: {explanation.training_era}\n"
        report += f"AI Models Affected: {', '.join(explanation.ai_models_affected)}\n\n"

        report += "VULNERABLE CODE:\n"
        report += "-"*70 + "\n"
        report += f"{explanation.vulnerable_code}\n\n"

        report += "WHY THIS IS VULNERABLE:\n"
        report += "-"*70 + "\n"
        report += f"{explanation.why_vulnerable}\n\n"

        report += "WHY AI LEARNED THIS PATTERN:\n"
        report += "-"*70 + "\n"
        report += f"{explanation.why_ai_learned_this}\n\n"

        # StackOverflow metadata
        metadata = explanation.stackoverflow_metadata
        if metadata:
            report += "STACKOVERFLOW CONTEXT:\n"
            report += "-"*70 + "\n"
            report += f"  URL: {explanation.source_url}\n"
            if 'upvotes' in metadata:
                report += f"  Upvotes: {metadata['upvotes']}\n"
            if 'views' in metadata:
                report += f"  Views: {metadata['views']}\n"
            if 'date_posted' in metadata:
                report += f"  Posted: {metadata['date_posted']}\n"
            report += "\n"

        report += "HISTORICAL CONTEXT:\n"
        report += "-"*70 + "\n"
        report += f"{explanation.historical_context}\n\n"

        report += "MODERN SECURE FIX:\n"
        report += "-"*70 + "\n"
        report += f"{explanation.modern_fix}\n\n"

        return report

    def get_training_era_summary(self) -> Dict[str, int]:
        """Get summary of patterns by training era"""
        return {era: len(patterns) for era, patterns in self.by_era.items()}

    def get_ai_model_coverage(self) -> Dict[str, int]:
        """Get summary of which AI models learned which patterns"""
        return {model: len(patterns) for model, patterns in self.by_model.items()}

    def get_category_summary(self) -> Dict[str, int]:
        """Get summary of patterns by category"""
        return {cat: len(patterns) for cat, patterns in self.by_category.items()}

    def search_by_stackoverflow_url(self, url: str) -> Optional[PatternExplanation]:
        """Find pattern by StackOverflow URL"""
        for pattern in self.patterns:
            if pattern.get('source_url', '').startswith(url):
                return self._create_explanation(pattern)
        return None


def main():
    """CLI interface for pattern explanation"""
    import sys

    explainer = PatternExplainer()

    print("="*70)
    print("CODE ARCHAEOLOGIST - PATTERN EXPLAINER")
    print("="*70)
    print(f"\nLoaded {len(explainer.patterns)} archaeological patterns\n")

    if len(sys.argv) < 2:
        # Show summary
        print("TRAINING ERA SUMMARY:")
        for era, count in sorted(explainer.get_training_era_summary().items()):
            print(f"  {era}: {count} patterns")

        print("\nCATEGORY SUMMARY:")
        for cat, count in sorted(explainer.get_category_summary().items()):
            print(f"  {cat}: {count} patterns")

        print("\nAI MODEL COVERAGE:")
        for model, count in sorted(explainer.get_ai_model_coverage().items()):
            print(f"  {model}: {count} patterns")

        print("\nUsage:")
        print("  python pattern_explainer.py <pattern_id>          - Explain specific pattern")
        print("  python pattern_explainer.py category:<name>       - Explain category")
        print("  python pattern_explainer.py code:<snippet>        - Find matching patterns")
        return

    arg = sys.argv[1]

    if arg.startswith("category:"):
        category = arg.split(":", 1)[1]
        explanations = explainer.explain_category(category)

        if not explanations:
            print(f"No patterns found for category: {category}")
            return

        print(f"Found {len(explanations)} patterns in {category}:\n")
        for exp in explanations:
            print(f"- {exp.pattern_id}: {exp.vulnerable_code[:60]}...")

    elif arg.startswith("code:"):
        code = arg.split(":", 1)[1]
        explanations = explainer.explain_code_snippet(code)

        if not explanations:
            print("No matching patterns found")
            return

        print(f"Found {len(explanations)} matching patterns:\n")
        for exp in explanations:
            print(explainer.generate_explanation_report(exp))

    else:
        # Treat as pattern ID
        explanation = explainer.explain_pattern(arg)

        if not explanation:
            print(f"Pattern not found: {arg}")
            return

        print(explainer.generate_explanation_report(explanation))


if __name__ == "__main__":
    main()
