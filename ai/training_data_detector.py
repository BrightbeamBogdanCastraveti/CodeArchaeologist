"""
Training Data Detector
Analyzes code to detect patterns that likely came from AI training data (StackOverflow, etc.)
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path
import json
import re
from datetime import datetime


@dataclass
class TrainingDataMatch:
    """A match between code and a known training data pattern"""
    pattern_id: str
    category: str
    confidence: float
    training_era: str
    ai_models_affected: List[str]
    stackoverflow_url: str
    stackoverflow_metadata: Dict
    matched_code: str
    line_number: int
    reason: str
    historical_context: str


class TrainingDataDetector:
    """
    Detects code patterns that likely originated from AI training data

    This detector identifies when code matches known patterns from StackOverflow
    posts that were in AI training datasets, helping developers understand
    WHY their AI assistant suggested specific code patterns.
    """

    def __init__(self, patterns_dir: str = "training_data_archive/stackoverflow"):
        self.patterns_dir = Path(patterns_dir)
        self.patterns = self._load_patterns()

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

    def detect_in_file(self, file_path: str) -> List[TrainingDataMatch]:
        """
        Detect training data patterns in a file

        Args:
            file_path: Path to Python file to analyze

        Returns:
            List of training data matches found
        """
        matches = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return matches

        # Check each pattern against the code
        for pattern in self.patterns:
            pattern_matches = self._match_pattern(pattern, content, lines, file_path)
            matches.extend(pattern_matches)

        return matches

    def _match_pattern(self, pattern: Dict, content: str, lines: List[str],
                       file_path: str) -> List[TrainingDataMatch]:
        """Match a single pattern against code"""
        matches = []

        vulnerable_code = pattern.get('vulnerable_code', '')
        if not vulnerable_code:
            return matches

        # Extract key indicators from vulnerable code
        indicators = self._extract_indicators(vulnerable_code)

        # Check for matches
        for line_num, line in enumerate(lines, 1):
            confidence = self._calculate_confidence(line, indicators, pattern)

            if confidence > 0.6:  # Threshold for match
                match = TrainingDataMatch(
                    pattern_id=pattern.get('id', 'unknown'),
                    category=pattern.get('category', 'unknown'),
                    confidence=confidence,
                    training_era=pattern.get('training_era', 'unknown'),
                    ai_models_affected=pattern.get('ai_models_affected', []),
                    stackoverflow_url=pattern.get('source_url', ''),
                    stackoverflow_metadata=pattern.get('stackoverflow_metadata', {}),
                    matched_code=line.strip(),
                    line_number=line_num,
                    reason=self._generate_reason(pattern, indicators),
                    historical_context=pattern.get('historical_context', '')
                )
                matches.append(match)

        return matches

    def _extract_indicators(self, code: str) -> Dict[str, List[str]]:
        """Extract key indicators from vulnerable code pattern"""
        indicators = {
            'functions': [],
            'patterns': [],
            'keywords': []
        }

        # Extract function calls
        func_pattern = r'(\w+)\s*\('
        indicators['functions'] = re.findall(func_pattern, code)

        # Extract common vulnerability patterns
        vuln_patterns = {
            'sql_injection': [r'\.format\(', r'%s', r'f".*{', r'raw\(', r'execute\('],
            'command_injection': [r'shell=True', r'os\.system', r'eval\(', r'exec\(',
                                 r'pickle\.loads', r'subprocess\.call'],
            'xss': [r'\|safe', r'mark_safe', r'autoescape.*false', r'dangerouslySetInnerHTML'],
            'secrets': [r'api_key\s*=\s*["\']', r'password\s*=\s*["\']', r'secret\s*=\s*["\']']
        }

        for category, patterns in vuln_patterns.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    indicators['patterns'].append(pattern)

        # Extract keywords
        keywords = ['format', 'execute', 'shell', 'eval', 'exec', 'pickle',
                   'safe', 'escape', 'sanitize', 'api_key', 'password']
        for keyword in keywords:
            if keyword in code.lower():
                indicators['keywords'].append(keyword)

        return indicators

    def _calculate_confidence(self, line: str, indicators: Dict, pattern: Dict) -> float:
        """Calculate confidence that this line matches the training data pattern"""
        confidence = 0.0

        # Function match (high weight)
        for func in indicators['functions']:
            if func in line:
                confidence += 0.3

        # Pattern match (very high weight)
        for pat in indicators['patterns']:
            if re.search(pat, line):
                confidence += 0.4

        # Keyword match (low weight)
        for keyword in indicators['keywords']:
            if keyword in line.lower():
                confidence += 0.1

        # Category-specific boosting
        category = pattern.get('category', '')
        if category == 'sql_injection' and 'execute' in line.lower():
            confidence += 0.2
        elif category == 'command_injection' and 'shell' in line.lower():
            confidence += 0.2
        elif category == 'xss' and 'safe' in line.lower():
            confidence += 0.2
        elif category == 'secrets' and any(k in line.lower() for k in ['key', 'password', 'secret']):
            confidence += 0.2

        return min(1.0, confidence)

    def _generate_reason(self, pattern: Dict, indicators: Dict) -> str:
        """Generate explanation for why this is a training data match"""
        category = pattern.get('category', 'unknown')
        why_learned = pattern.get('why_ai_learned_this', '')

        # Extract upvotes if available
        metadata = pattern.get('stackoverflow_metadata', {})
        upvotes = metadata.get('upvotes', 'unknown')

        reason = f"This {category} pattern matches a StackOverflow post "

        if upvotes != 'unknown':
            reason += f"with {upvotes} upvotes "

        reason += f"from {pattern.get('training_era', 'unknown')}. "

        if why_learned:
            if isinstance(why_learned, str):
                reason += why_learned[:200]
            elif isinstance(why_learned, dict):
                reason += str(why_learned.get('Was it highly upvoted?', ''))[:200]

        return reason

    def generate_report(self, matches: List[TrainingDataMatch]) -> str:
        """Generate a human-readable report of training data matches"""
        if not matches:
            return "No training data patterns detected."

        report = "="*70 + "\n"
        report += "TRAINING DATA DETECTION REPORT\n"
        report += "="*70 + "\n\n"

        # Group by category
        by_category = {}
        for match in matches:
            cat = match.category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(match)

        report += f"Found {len(matches)} matches across {len(by_category)} categories\n\n"

        for category, cat_matches in sorted(by_category.items()):
            report += f"\n{category.upper()} ({len(cat_matches)} matches)\n"
            report += "-"*70 + "\n"

            for match in cat_matches[:5]:  # Show top 5 per category
                report += f"\nLine {match.line_number}: {match.matched_code}\n"
                report += f"  Pattern: {match.pattern_id}\n"
                report += f"  Confidence: {match.confidence:.1%}\n"
                report += f"  Training Era: {match.training_era}\n"
                report += f"  AI Models: {', '.join(match.ai_models_affected[:3])}\n"
                report += f"  Source: {match.stackoverflow_url}\n"
                report += f"  Why: {match.reason[:150]}...\n"

        return report

    def get_statistics(self, matches: List[TrainingDataMatch]) -> Dict:
        """Get statistics about training data matches"""
        if not matches:
            return {
                'total_matches': 0,
                'categories': {},
                'training_eras': {},
                'ai_models': {},
                'avg_confidence': 0.0
            }

        stats = {
            'total_matches': len(matches),
            'categories': {},
            'training_eras': {},
            'ai_models': {},
            'avg_confidence': sum(m.confidence for m in matches) / len(matches)
        }

        for match in matches:
            # Count categories
            cat = match.category
            stats['categories'][cat] = stats['categories'].get(cat, 0) + 1

            # Count training eras
            era = match.training_era
            stats['training_eras'][era] = stats['training_eras'].get(era, 0) + 1

            # Count AI models
            for model in match.ai_models_affected:
                stats['ai_models'][model] = stats['ai_models'].get(model, 0) + 1

        return stats


def main():
    """CLI interface for training data detection"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python training_data_detector.py <file_or_directory>")
        sys.exit(1)

    target = sys.argv[1]
    detector = TrainingDataDetector()

    print(f"Analyzing {target} for training data patterns...")
    print(f"Loaded {len(detector.patterns)} archaeological patterns\n")

    all_matches = []

    target_path = Path(target)
    if target_path.is_file():
        matches = detector.detect_in_file(str(target_path))
        all_matches.extend(matches)
    elif target_path.is_dir():
        for py_file in target_path.rglob("*.py"):
            matches = detector.detect_in_file(str(py_file))
            all_matches.extend(matches)

    # Generate and print report
    print(detector.generate_report(all_matches))

    # Print statistics
    stats = detector.get_statistics(all_matches)
    print("\n" + "="*70)
    print("STATISTICS")
    print("="*70)
    print(f"Total matches: {stats['total_matches']}")
    print(f"Average confidence: {stats['avg_confidence']:.1%}")
    print(f"\nBy category: {stats['categories']}")
    print(f"By training era: {stats['training_eras']}")
    print(f"AI models affected: {stats['ai_models']}")


if __name__ == "__main__":
    main()
