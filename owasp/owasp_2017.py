"""
OWASP Top 10 - 2017 Edition

Source: https://owasp.org/www-project-top-ten/2017/
Release: November 2017

This represents the vulnerability landscape from 2013-2017.
AI models trained on code from this era (GPT-2, BERT for code, early Codex)
learned these patterns.

Key Changes from 2013:
- A4 (IDOR) and A7 (Missing Access Control) merged into A5 (Broken Access Control)
- A10 (Unvalidated Redirects) removed
- Added: A4 XML External Entities (XXE)
- Added: A8 Insecure Deserialization
- Added: A10 Insufficient Logging & Monitoring
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
    prev_rank: str  # Rank in previous version (if applicable)
    change: str  # 'new', 'merged', 'same', 'moved'


OWASP_2017 = {
    'A1': OWASPCategory(
        rank='A1',
        name='Injection',
        description=(
            'Injection flaws, such as SQL, NoSQL, OS, and LDAP injection occur when untrusted '
            'data is sent to an interpreter as part of a command or query. The attacker\'s '
            'hostile data can trick the interpreter into executing unintended commands or '
            'accessing data without proper authorization.'
        ),
        examples=[
            'SQL Injection: query = "SELECT * FROM users WHERE name = \'" + name + "\'"',
            'NoSQL Injection: db.users.find({username: req.body.username})',
            'OS Command Injection: Runtime.getRuntime().exec("cmd " + userInput)',
            'LDAP Injection'
        ],
        cwe_mappings=['CWE-77', 'CWE-78', 'CWE-89', 'CWE-90', 'CWE-564'],
        prev_rank='A1',
        change='same'
    ),

    'A2': OWASPCategory(
        rank='A2',
        name='Broken Authentication',
        description=(
            'Application functions related to authentication and session management are often '
            'implemented incorrectly, allowing attackers to compromise passwords, keys, or session '
            'tokens, or to exploit other implementation flaws to assume other users\' identities '
            'temporarily or permanently.'
        ),
        examples=[
            'Credential stuffing attacks',
            'Brute force attacks with no rate limiting',
            'Session IDs in URLs',
            'Session fixation',
            'Weak password requirements'
        ],
        cwe_mappings=['CWE-287', 'CWE-384'],
        prev_rank='A2',
        change='same'
    ),

    'A3': OWASPCategory(
        rank='A3',
        name='Sensitive Data Exposure',
        description=(
            'Many web applications and APIs do not properly protect sensitive data, such as '
            'financial, healthcare, and PII. Attackers may steal or modify such weakly protected '
            'data to conduct credit card fraud, identity theft, or other crimes. Sensitive data '
            'may be compromised without extra protection, such as encryption at rest or in transit.'
        ),
        examples=[
            'Transmitting data in clear text (HTTP, FTP, SMTP)',
            'Old or weak cryptographic algorithms (MD5, SHA1, DES)',
            'Default crypto keys or weak key generation',
            'Missing certificate validation',
            'Sensitive data in logs or backups'
        ],
        cwe_mappings=['CWE-311', 'CWE-312', 'CWE-319', 'CWE-326', 'CWE-327'],
        prev_rank='A6',
        change='moved'
    ),

    'A4': OWASPCategory(
        rank='A4',
        name='XML External Entities (XXE)',
        description=(
            'Many older or poorly configured XML processors evaluate external entity references '
            'within XML documents. External entities can be used to disclose internal files using '
            'the file URI handler, internal file shares, internal port scanning, remote code '
            'execution, and denial of service attacks.'
        ),
        examples=[
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.server/admin">]>',
            'Billion laughs attack (XML bomb)',
            'SSRF via XXE'
        ],
        cwe_mappings=['CWE-611'],
        prev_rank='N/A',
        change='new'
    ),

    'A5': OWASPCategory(
        rank='A5',
        name='Broken Access Control',
        description=(
            'Restrictions on what authenticated users are allowed to do are often not properly '
            'enforced. Attackers can exploit these flaws to access unauthorized functionality '
            'and/or data, such as access other users\' accounts, view sensitive files, modify '
            'other users\' data, change access rights, etc.'
        ),
        examples=[
            'IDOR: /account?id=1234 -> /account?id=1235',
            'Forced browsing to authenticated pages',
            'Missing authorization checks on API endpoints',
            'Elevation of privilege',
            'CORS misconfiguration'
        ],
        cwe_mappings=['CWE-22', 'CWE-285', 'CWE-639'],
        prev_rank='A4 + A7',
        change='merged'
    ),

    'A6': OWASPCategory(
        rank='A6',
        name='Security Misconfiguration',
        description=(
            'Security misconfiguration is the most commonly seen issue. This is commonly a result '
            'of insecure default configurations, incomplete or ad hoc configurations, open cloud '
            'storage, misconfigured HTTP headers, and verbose error messages containing sensitive '
            'information.'
        ),
        examples=[
            'Unnecessary features enabled (ports, services, pages)',
            'Default accounts with unchanged passwords',
            'Detailed error messages',
            'Missing security headers',
            'Outdated software'
        ],
        cwe_mappings=['CWE-2', 'CWE-16', 'CWE-537'],
        prev_rank='A5',
        change='same'
    ),

    'A7': OWASPCategory(
        rank='A7',
        name='Cross-Site Scripting (XSS)',
        description=(
            'XSS flaws occur whenever an application includes untrusted data in a new web page '
            'without proper validation or escaping, or updates an existing web page with user-supplied '
            'data using a browser API that can create HTML or JavaScript. XSS allows attackers to '
            'execute scripts in the victim\'s browser.'
        ),
        examples=[
            'Reflected XSS: search.php?q=<script>alert(1)</script>',
            'Stored XSS: Comment stored in database with malicious script',
            'DOM XSS: document.write(location.hash)',
            'innerHTML injection'
        ],
        cwe_mappings=['CWE-79'],
        prev_rank='A3',
        change='moved'
    ),

    'A8': OWASPCategory(
        rank='A8',
        name='Insecure Deserialization',
        description=(
            'Insecure deserialization often leads to remote code execution. Even if deserialization '
            'flaws do not result in remote code execution, they can be used to perform attacks, '
            'including replay attacks, injection attacks, and privilege escalation attacks.'
        ),
        examples=[
            'Python pickle exploitation',
            'Java deserialization (Apache Commons)',
            'PHP unserialize() attacks',
            'JSON deserialization vulnerabilities'
        ],
        cwe_mappings=['CWE-502'],
        prev_rank='N/A',
        change='new'
    ),

    'A9': OWASPCategory(
        rank='A9',
        name='Using Components with Known Vulnerabilities',
        description=(
            'Components, such as libraries, frameworks, and other software modules, run with the '
            'same privileges as the application. If a vulnerable component is exploited, such an '
            'attack can facilitate serious data loss or server takeover. Applications and APIs using '
            'components with known vulnerabilities may undermine application defenses.'
        ),
        examples=[
            'Struts 2 Remote Code Execution (Equifax breach)',
            'Heartbleed (OpenSSL)',
            'Shellshock (Bash)',
            'Log4Shell (Log4j)'
        ],
        cwe_mappings=['CWE-937'],
        prev_rank='A9',
        change='same'
    ),

    'A10': OWASPCategory(
        rank='A10',
        name='Insufficient Logging & Monitoring',
        description=(
            'Insufficient logging and monitoring, coupled with missing or ineffective integration '
            'with incident response, allows attackers to further attack systems, maintain persistence, '
            'pivot to more systems, and tamper, extract, or destroy data. Most breach studies show '
            'time to detect a breach is over 200 days.'
        ),
        examples=[
            'Auditable events not logged (logins, failed logins, transactions)',
            'Warnings and errors generate no logs',
            'Logs only stored locally',
            'No alerting on suspicious activity',
            'No penetration testing or DAST scans'
        ],
        cwe_mappings=['CWE-223', 'CWE-778'],
        prev_rank='N/A',
        change='new'
    ),
}


def get_all_categories() -> Dict[str, OWASPCategory]:
    """Get all OWASP 2017 categories."""
    return OWASP_2017


def get_category(rank: str) -> OWASPCategory:
    """Get specific OWASP 2017 category by rank (A1-A10)."""
    return OWASP_2017.get(rank)


def get_changes_from_2013() -> Dict[str, str]:
    """Get summary of changes from OWASP 2013 to 2017."""
    return {
        'new_entries': ['A4 XML External Entities (XXE)', 'A8 Insecure Deserialization', 'A10 Insufficient Logging & Monitoring'],
        'removed': ['A10 Unvalidated Redirects and Forwards'],
        'merged': ['A4 IDOR + A7 Missing Access Control → A5 Broken Access Control'],
        'moved': ['A6 Sensitive Data Exposure → A3', 'A3 XSS → A7']
    }


# Training era information
TRAINING_ERA = {
    'start_year': 2013,
    'end_year': 2017,
    'ai_models_trained': [
        'GPT-2 (2018, trained on pre-2017 code)',
        'BERT for code (2019)',
        'Early GitHub Copilot prototypes',
        'CodeBERT (2020, trained on 2013-2019 code)'
    ],
    'note': (
        'This OWASP version represents vulnerabilities prevalent in 2013-2017. '
        'AI models like GPT-2 and early Codex were trained on GitHub repositories '
        'from this era, which contained these vulnerability patterns. This is why '
        'early AI coding assistants sometimes generated vulnerable code matching '
        'these patterns.'
    )
}
