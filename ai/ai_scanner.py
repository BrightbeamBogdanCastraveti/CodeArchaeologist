"""
AI-Powered Scanner (Engine 2)

Uses OpenAI GPT-4 with training pattern knowledge to detect vulnerabilities
that pattern-based scanners might miss.

This scanner:
1. Loads training data patterns (why AI generates vulnerabilities)
2. Sends code + pattern knowledge to OpenAI
3. Gets AI analysis with context about training data
4. Returns findings in same format as Engine 1
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
import re


@dataclass
class AIFinding:
    """Finding from AI scanner"""
    file_path: str
    line_number: int
    vulnerability_type: str
    severity: str
    confidence: float
    message: str
    vulnerable_code: str
    why_ai_generates_this: str
    training_pattern_id: Optional[str]
    suggested_fix: str
    cwe: Optional[str] = None


class AIScanner:
    """
    AI-Powered Scanner using training data patterns

    This is Engine 2 - it understands WHY AI generates vulnerabilities
    by using knowledge from training data patterns.
    """

    def __init__(self, openai_api_key: Optional[str] = None):
        self.api_key = openai_api_key or os.environ.get('OPENAI_API_KEY')

        # Initialize OpenAI client
        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
                self.api_available = True
                print("✅ AI Scanner: OpenAI API connected")
            except ImportError:
                print("⚠️  AI Scanner: OpenAI package not installed")
                self.client = None
                self.api_available = False
        else:
            print("⚠️  AI Scanner: No OPENAI_API_KEY found")
            self.client = None
            self.api_available = False

        # Load training patterns
        self.patterns = self._load_patterns()
        print(f"✅ AI Scanner: Loaded {len(self.patterns)} training patterns")

    def _load_patterns(self) -> List[Dict]:
        """Load training data patterns"""
        patterns = []

        # Path to patterns
        base_dir = Path(__file__).parent.parent.parent
        patterns_dir = base_dir / 'training_data_archive' / 'stackoverflow' / 'sql_injection' / 'patterns'

        if not patterns_dir.exists():
            print(f"⚠️  Pattern directory not found: {patterns_dir}")
            return patterns

        # Load all JSON patterns
        for pattern_file in patterns_dir.glob('*.json'):
            try:
                with open(pattern_file, 'r') as f:
                    pattern = json.load(f)
                    patterns.append(pattern)
            except Exception as e:
                print(f"⚠️  Error loading pattern {pattern_file}: {e}")

        return patterns

    def scan_code(
        self,
        code: str,
        file_path: str = "unknown",
        language: str = "python"
    ) -> List[AIFinding]:
        """
        Scan code using AI with training pattern knowledge

        Args:
            code: Source code to scan
            file_path: Path to file being scanned
            language: Programming language

        Returns:
            List of AI findings
        """
        if not self.api_available:
            print("⚠️  AI Scanner: API not available")
            return []

        if not self.patterns:
            print("⚠️  AI Scanner: No patterns loaded")
            return []

        # Build prompt with pattern knowledge
        prompt = self._build_analysis_prompt(code, file_path, language)

        try:
            # Call OpenAI
            response = self.client.chat.completions.create(
                model="gpt-4-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert with deep knowledge of AI training data and why AI models generate vulnerable code. Analyze code for vulnerabilities that AI might have learned from training data."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0,
                max_tokens=3000
            )

            # Parse response
            response_text = response.choices[0].message.content
            findings = self._parse_ai_response(response_text, file_path)

            return findings

        except Exception as e:
            print(f"⚠️  AI Scanner error: {e}")
            return []

    def _build_analysis_prompt(
        self,
        code: str,
        file_path: str,
        language: str
    ) -> str:
        """Build prompt with training pattern knowledge"""

        # Build pattern knowledge section
        pattern_knowledge = []
        for pattern in self.patterns[:5]:  # Use first 5 patterns to keep prompt manageable
            pattern_knowledge.append(f"""
Pattern {pattern.get('pattern_id', 'unknown')}:
- Vulnerable Code: {pattern.get('vulnerable_code', '')[:200]}
- Why AI Learned This: {pattern.get('why_ai_learned_this', '')[:300]}
- Training Impact: {pattern.get('training_impact', '')}
- Modern Fix: {pattern.get('modern_fix', '')[:200]}
""")

        prompt = f"""You are analyzing code for vulnerabilities that AI models commonly generate due to training data.

TRAINING PATTERN KNOWLEDGE:
{chr(10).join(pattern_knowledge)}

CODE TO ANALYZE:
File: {file_path}
Language: {language}

```{language}
{code}
```

TASK:
Analyze this code for vulnerabilities, especially patterns that AI models learned from training data (2008-2023).

For each vulnerability found, return JSON:
{{
  "vulnerabilities": [
    {{
      "line_number": <line number>,
      "vulnerability_type": "sql_injection" | "xss" | "command_injection" | etc,
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "confidence": 0.0-1.0,
      "message": "Brief description",
      "vulnerable_code": "exact code snippet",
      "why_ai_generates_this": "Why AI models learned to generate this pattern",
      "training_pattern_id": "sql_001" | null,
      "suggested_fix": "How to fix it",
      "cwe": "CWE-89" | null
    }}
  ]
}}

Return ONLY valid JSON. If no vulnerabilities, return {{"vulnerabilities": []}}.
"""
        return prompt

    def _parse_ai_response(
        self,
        response_text: str,
        file_path: str
    ) -> List[AIFinding]:
        """Parse AI response into findings"""

        findings = []

        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if not json_match:
                print("⚠️  No JSON found in AI response")
                return findings

            data = json.loads(json_match.group())
            vulnerabilities = data.get('vulnerabilities', [])

            for vuln in vulnerabilities:
                finding = AIFinding(
                    file_path=file_path,
                    line_number=vuln.get('line_number', 0),
                    vulnerability_type=vuln.get('vulnerability_type', 'unknown'),
                    severity=vuln.get('severity', 'MEDIUM'),
                    confidence=vuln.get('confidence', 0.5),
                    message=vuln.get('message', ''),
                    vulnerable_code=vuln.get('vulnerable_code', ''),
                    why_ai_generates_this=vuln.get('why_ai_generates_this', ''),
                    training_pattern_id=vuln.get('training_pattern_id'),
                    suggested_fix=vuln.get('suggested_fix', ''),
                    cwe=vuln.get('cwe')
                )
                findings.append(finding)

        except Exception as e:
            print(f"⚠️  Error parsing AI response: {e}")
            print(f"Response text: {response_text[:500]}")

        return findings

    def scan_file(self, file_path: str) -> List[AIFinding]:
        """Scan a single file"""
        try:
            with open(file_path, 'r') as f:
                code = f.read()

            # Detect language from extension
            ext = Path(file_path).suffix.lower()
            language_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.php': 'php',
                '.java': 'java',
                '.rb': 'ruby'
            }
            language = language_map.get(ext, 'python')

            return self.scan_code(code, file_path, language)

        except Exception as e:
            print(f"⚠️  Error scanning file {file_path}: {e}")
            return []

    def get_status(self) -> Dict:
        """Get scanner status"""
        return {
            'api_available': self.api_available,
            'patterns_loaded': len(self.patterns),
            'patterns': [
                {
                    'id': p.get('pattern_id'),
                    'type': p.get('vulnerability_type'),
                    'language': p.get('language'),
                    'year': p.get('year')
                }
                for p in self.patterns
            ]
        }


def main():
    """Test AI Scanner"""
    print("""
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║                    AI SCANNER (ENGINE 2)                           ║
║                                                                    ║
║  Scans code using AI with training pattern knowledge              ║
║  - Loads 5 SQL injection patterns                                 ║
║  - Understands WHY AI generates vulnerabilities                   ║
║  - Provides context about training data                           ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
    """)

    # Initialize scanner
    scanner = AIScanner()

    # Show status
    status = scanner.get_status()
    print("\n" + "="*70)
    print("SCANNER STATUS")
    print("="*70)
    print(f"API Available: {status['api_available']}")
    print(f"Patterns Loaded: {status['patterns_loaded']}")
    print("\nLoaded Patterns:")
    for p in status['patterns']:
        print(f"  - {p['id']}: {p['type']} ({p['language']}, {p['year']})")

    if not status['api_available']:
        print("\n❌ Cannot scan without OpenAI API")
        print("Set OPENAI_API_KEY environment variable")
        return

    # Test with sample code
    print("\n" + "="*70)
    print("TEST SCAN")
    print("="*70)

    test_code = '''
def get_user(user_id):
    """Get user from database"""
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    cursor.execute(query)
    return cursor.fetchone()
'''

    print("\nScanning code:")
    print(test_code)

    findings = scanner.scan_code(test_code, "test.py", "python")

    print(f"\n✅ Found {len(findings)} vulnerabilities")
    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. {finding.vulnerability_type.upper()} ({finding.severity})")
        print(f"   Line: {finding.line_number}")
        print(f"   Confidence: {finding.confidence:.0%}")
        print(f"   Message: {finding.message}")
        print(f"   Why AI generates this: {finding.why_ai_generates_this[:100]}...")
        if finding.training_pattern_id:
            print(f"   Training Pattern: {finding.training_pattern_id}")
        print(f"   Fix: {finding.suggested_fix[:100]}...")


if __name__ == '__main__':
    main()
