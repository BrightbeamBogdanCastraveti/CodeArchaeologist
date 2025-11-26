"""
OWASP Top 10 - 2024 Edition (DRAFT/ANTICIPATED)

Status: DRAFT - Not officially released yet
Expected Release: Late 2024 / Early 2025

This represents anticipated changes based on:
- OWASP Top 10 for LLM Applications 2025 (released)
- Current threat landscape (2021-2024)
- Community discussions
- Emerging attack patterns

Note: This is a PREDICTION based on trends. Official version may differ.
"""

from typing import Dict, List
from dataclasses import dataclass


@dataclass
class OWASPCategory:
    """OWASP Top 10 category."""
    rank: str
    name: str
    description: str
    examples: List[str]
    cwe_mappings: List[str]
    status: str  # 'confirmed', 'likely', 'predicted'
    rationale: str  # Why we think this will be included


# PREDICTED OWASP 2024 based on current trends
OWASP_2024_DRAFT = {
    'A01': OWASPCategory(
        rank='A01',
        name='Broken Access Control',
        description=(
            'Likely to REMAIN #1. Still the most common vulnerability found in applications. '
            'With the rise of APIs and microservices, access control failures are even more prevalent.'
        ),
        examples=[
            'API endpoint missing authorization',
            'GraphQL depth attacks',
            'Microservice authorization bypass',
            'OAuth misconfiguration',
            'CORS policy violations'
        ],
        cwe_mappings=['CWE-284', 'CWE-285', 'CWE-639'],
        status='likely',
        rationale='Continues to be most prevalent in testing data. API explosion makes this worse.'
    ),

    'A02': OWASPCategory(
        rank='A02',
        name='Cryptographic Failures',
        description=(
            'Likely to remain in top 3. Post-quantum cryptography concerns emerging. '
            'Increased focus on data at rest encryption due to breaches.'
        ),
        examples=[
            'Weak encryption algorithms',
            'Missing encryption',
            'Improper key management',
            'Quantum-vulnerable algorithms (RSA-2048)',
            'TLS misconfiguration'
        ],
        cwe_mappings=['CWE-311', 'CWE-327', 'CWE-326'],
        status='likely',
        rationale='Data breaches continue. Quantum computing threats emerging.'
    ),

    'A03': OWASPCategory(
        rank='A03',
        name='Injection',
        description=(
            'May move DOWN or merge with A04. Still relevant but decreasing due to frameworks '
            'with built-in protection (ORMs, prepared statements). NoSQL and API injection increasing.'
        ),
        examples=[
            'NoSQL injection',
            'GraphQL injection',
            'LDAP injection',
            'Template injection',
            'API parameter injection'
        ],
        cwe_mappings=['CWE-74', 'CWE-89', 'CWE-78'],
        status='likely',
        rationale='Traditional SQL injection down, but new injection types emerging.'
    ),

    'A04': OWASPCategory(
        rank='A04',
        name='Insecure Design',
        description=(
            'LIKELY TO EXPAND. May absorb parts of A03 Injection. Focus on architectural flaws, '
            'business logic bypasses, and design-level security failures.'
        ),
        examples=[
            'Missing rate limiting',
            'No resource quotas',
            'Business logic bypass',
            'Inadequate threat modeling',
            'Missing security patterns'
        ],
        cwe_mappings=['CWE-73', 'CWE-183', 'CWE-209'],
        status='likely',
        rationale='2021 addition gaining traction. Addresses root cause of many issues.'
    ),

    'A05': OWASPCategory(
        rank='A05',
        name='Security Misconfiguration',
        description=(
            'Likely to remain top 5. Cloud misconfigurations (S3 buckets, IAM roles) are rampant. '
            'Container and Kubernetes security issues increasing.'
        ),
        examples=[
            'Open S3 buckets',
            'Misconfigured IAM roles',
            'Kubernetes secrets exposed',
            'Docker containers running as root',
            'Missing security headers'
        ],
        cwe_mappings=['CWE-2', 'CWE-16', 'CWE-611'],
        status='likely',
        rationale='Cloud adoption + complexity = more misconfigurations.'
    ),

    'A06': OWASPCategory(
        rank='A06',
        name='Vulnerable and Outdated Components',
        description=(
            'LIKELY TO RISE. Supply chain attacks increasing (SolarWinds, Log4Shell). '
            'Dependency hell in modern applications. Software supply chain security critical.'
        ),
        examples=[
            'Log4Shell',
            'Spring4Shell',
            'Compromised NPM packages',
            'Typosquatting attacks',
            'Malicious GitHub Actions'
        ],
        cwe_mappings=['CWE-937', 'CWE-1035'],
        status='likely',
        rationale='Major breaches via dependencies. Software supply chain attacks surging.'
    ),

    'A07': OWASPCategory(
        rank='A07',
        name='Identification and Authentication Failures',
        description=(
            'Likely to remain. MFA bypass techniques emerging. Passwordless authentication growing. '
            'Session management in distributed systems challenging.'
        ),
        examples=[
            'MFA bypass',
            'Session fixation in SPA',
            'JWT vulnerabilities',
            'OAuth misconfiguration',
            'Biometric spoofing'
        ],
        cwe_mappings=['CWE-287', 'CWE-306', 'CWE-384'],
        status='likely',
        rationale='Authentication remains critical, new patterns emerging.'
    ),

    'A08': OWASPCategory(
        rank='A08',
        name='AI/ML Security Failures',
        description=(
            'PREDICTED NEW CATEGORY. With widespread AI adoption, new category for AI/ML-specific '
            'vulnerabilities. May incorporate aspects from OWASP LLM Top 10.'
        ),
        examples=[
            'Prompt injection (LLM01)',
            'Insecure output handling (LLM02)',
            'Training data poisoning (LLM03)',
            'Model theft',
            'Data leakage via model'
        ],
        cwe_mappings=['CWE-20', 'CWE-74'],
        status='predicted',
        rationale='AI/ML now mainstream. OWASP LLM Top 10 exists. Likely merge into main Top 10.'
    ),

    'A09': OWASPCategory(
        rank='A09',
        name='Security Logging and Monitoring Failures',
        description=(
            'Likely to remain. May expand to include cloud-specific logging (CloudTrail, CloudWatch). '
            'SIEM integration, threat intelligence becoming standard.'
        ),
        examples=[
            'Missing audit logs',
            'No cloud logging',
            'Insufficient SIEM integration',
            'No threat intelligence',
            'Missing incident response'
        ],
        cwe_mappings=['CWE-223', 'CWE-778'],
        status='likely',
        rationale='Detection critical for breach response. Growing importance.'
    ),

    'A10': OWASPCategory(
        rank='A10',
        name='Server-Side Request Forgery (SSRF)',
        description=(
            'May EXPAND or merge with A01. Cloud metadata exploitation (AWS IMDS, Azure IMDS) common. '
            'Serverless and container exploitation via SSRF increasing.'
        ),
        examples=[
            'AWS metadata service exploitation',
            'Azure IMDS attacks',
            'Kubernetes API server access',
            'Internal network scanning',
            'Cloud resource enumeration'
        ],
        cwe_mappings=['CWE-918'],
        status='likely',
        rationale='Cloud-native attacks increasing. SSRF critical for cloud security.'
    ),
}


def get_all_categories() -> Dict[str, OWASPCategory]:
    """Get all OWASP 2024 DRAFT categories."""
    return OWASP_2024_DRAFT


def get_category(rank: str) -> OWASPCategory:
    """Get specific OWASP 2024 category by rank (A01-A10)."""
    return OWASP_2024_DRAFT.get(rank)


def get_predicted_changes() -> Dict[str, List[str]]:
    """Get predicted changes from OWASP 2021 to 2024."""
    return {
        'new_entries_predicted': [
            'A08 AI/ML Security Failures (HIGH CONFIDENCE - OWASP LLM Top 10 exists)'
        ],
        'likely_to_rise': [
            'A06 Vulnerable and Outdated Components (supply chain attacks)',
            'A10 SSRF (cloud metadata attacks)'
        ],
        'likely_to_fall': [
            'A03 Injection (better frameworks, but may merge into A04)'
        ],
        'likely_to_expand': [
            'A05 Security Misconfiguration (cloud complexity)',
            'A09 Logging and Monitoring (cloud-specific)'
        ],
        'uncertain': [
            'Whether A08 will be dedicated to AI/ML or AI issues spread across categories',
            'Whether A03 Injection merges into A04 Insecure Design'
        ]
    }


# Training era information
TRAINING_ERA = {
    'start_year': 2021,
    'end_year': 2024,
    'ai_models_trained': [
        'GPT-4 (2023, trained on 2021 cutoff)',
        'Claude 3 (2024)',
        'GitHub Copilot X (2023)',
        'Amazon CodeWhisperer (2023)',
        'Gemini Code Assist (2024)',
        'Claude Code (2024)',
        'Many fine-tuned coding models'
    ],
    'note': (
        'This is the CURRENT era of AI code generation. AI models in use today '
        '(GPT-4, Claude 3, GitHub Copilot, etc.) were trained on code from 2021-2023. '
        'This OWASP draft represents vulnerabilities present in that training data. '
        '\n\n'
        'CRITICAL INSIGHT: When GPT-4/Claude generate code with OWASP 2021 vulnerabilities, '
        'they are reproducing patterns from their 2021-2023 training data. The Code Archaeologist '
        'can trace which OWASP era a vulnerability comes from and explain which AI training '
        'period likely learned it.'
    ),
    'why_ai_generates_these': (
        'Current AI models (GPT-4, Claude 3, Copilot) trained on 2021-2023 GitHub repositories. '
        'During this period, OWASP 2021 was current guidance, but many codebases still contained '
        'vulnerabilities. The AI learned patterns like:\n'
        '- Broken Access Control (A01) - Most common in training data\n'
        '- SQL Injection (A03) - Present in tutorials and examples\n'
        '- Insecure Deserialization (A08) - Common in Stack Overflow snippets\n'
        '\n'
        'The AI optimized for "code that compiles and looks right" not "secure code". '
        'It learned vulnerable patterns because they were COMMON in training data, not because '
        'they were correct.'
    ),
    'new_in_2024_era': (
        'AI/ML vulnerabilities (prompt injection, insecure output handling) are NEW attack surface '
        'that did not exist in previous eras. These cannot be in AI training data because they '
        'target AI systems themselves. This is why AI-generated AI applications are especially '
        'vulnerable - the AI has no training data on how to secure AI systems.'
    )
}


# Confidence levels for predictions
PREDICTION_CONFIDENCE = {
    'A01': 0.95,  # Very likely to remain #1
    'A02': 0.90,  # Likely to remain top 3
    'A03': 0.75,  # May move or merge
    'A04': 0.85,  # Likely to expand
    'A05': 0.90,  # Likely to remain
    'A06': 0.85,  # Likely to rise
    'A07': 0.85,  # Likely to remain
    'A08': 0.70,  # AI/ML security - PREDICTED but uncertain
    'A09': 0.85,  # Likely to remain
    'A10': 0.80,  # Likely to remain or expand
}
