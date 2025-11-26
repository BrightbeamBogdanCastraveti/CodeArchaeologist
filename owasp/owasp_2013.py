"""
OWASP Top 10 - 2013 Edition

Source: https://owasp.org/www-project-top-ten/2017/Top_10-2013
Release: June 2013

This represents the vulnerability landscape from 2008-2013.
AI models trained on code from this era (GPT-2, early transformers)
learned these patterns.
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
    prevalence: str  # How common
    detectability: str  # How easy to detect
    impact: str  # Severity of impact
    exploitability: str  # How easy to exploit


OWASP_2013 = {
    'A1': OWASPCategory(
        rank='A1',
        name='Injection',
        description=(
            'Injection flaws, such as SQL, OS, and LDAP injection, occur when untrusted '
            'data is sent to an interpreter as part of a command or query. The attacker\'s '
            'hostile data can trick the interpreter into executing unintended commands or '
            'accessing data without proper authorization.'
        ),
        examples=[
            'SQL Injection: SELECT * FROM users WHERE id = \'' + user_input + '\'',
            'OS Command Injection: os.system("ping " + user_input)',
            'LDAP Injection: ldap.search("(&(uid=" + username + ")(password=" + password + "))")',
        ],
        cwe_mappings=['CWE-77', 'CWE-78', 'CWE-89', 'CWE-90', 'CWE-91'],
        prevalence='Common',
        detectability='Average',
        impact='Severe',
        exploitability='Easy'
    ),

    'A2': OWASPCategory(
        rank='A2',
        name='Broken Authentication and Session Management',
        description=(
            'Application functions related to authentication and session management are often '
            'not implemented correctly, allowing attackers to compromise passwords, keys, or '
            'session tokens, or to exploit other implementation flaws to assume other users\' identities.'
        ),
        examples=[
            'Session fixation attacks',
            'Predictable session IDs',
            'Credentials exposed in URLs',
            'Session IDs not rotated after login',
            'Passwords not properly hashed'
        ],
        cwe_mappings=['CWE-287', 'CWE-306', 'CWE-307', 'CWE-384', 'CWE-521', 'CWE-613'],
        prevalence='Widespread',
        detectability='Average',
        impact='Severe',
        exploitability='Average'
    ),

    'A3': OWASPCategory(
        rank='A3',
        name='Cross-Site Scripting (XSS)',
        description=(
            'XSS flaws occur whenever an application takes untrusted data and sends it to a '
            'web browser without proper validation or escaping. XSS allows attackers to execute '
            'scripts in the victim\'s browser which can hijack user sessions, deface web sites, '
            'or redirect the user to malicious sites.'
        ),
        examples=[
            'Reflected XSS: <script>alert(document.cookie)</script>',
            'Stored XSS: Malicious script stored in database',
            'DOM-based XSS: document.write(location.hash)'
        ],
        cwe_mappings=['CWE-79'],
        prevalence='Very Widespread',
        detectability='Easy',
        impact='Moderate',
        exploitability='Average'
    ),

    'A4': OWASPCategory(
        rank='A4',
        name='Insecure Direct Object References',
        description=(
            'A direct object reference occurs when a developer exposes a reference to an internal '
            'implementation object, such as a file, directory, or database key. Without an access '
            'control check or other protection, attackers can manipulate these references to access '
            'unauthorized data.'
        ),
        examples=[
            'URL parameter manipulation: /account?id=123 -> /account?id=124',
            'Hidden form fields: <input type="hidden" name="user_id" value="123">',
            'Direct file access: /download?file=../../../etc/passwd'
        ],
        cwe_mappings=['CWE-22', 'CWE-639', 'CWE-829'],
        prevalence='Common',
        detectability='Easy',
        impact='Moderate',
        exploitability='Easy'
    ),

    'A5': OWASPCategory(
        rank='A5',
        name='Security Misconfiguration',
        description=(
            'Good security requires having a secure configuration defined and deployed for the '
            'application, frameworks, application server, web server, database server, and platform. '
            'Secure settings should be defined, implemented, and maintained, as defaults are often insecure.'
        ),
        examples=[
            'Default accounts still enabled',
            'Directory listing enabled',
            'Detailed error messages exposed',
            'Unnecessary features enabled',
            'Missing security headers'
        ],
        cwe_mappings=['CWE-2', 'CWE-16', 'CWE-388'],
        prevalence='Common',
        detectability='Easy',
        impact='Moderate',
        exploitability='Easy'
    ),

    'A6': OWASPCategory(
        rank='A6',
        name='Sensitive Data Exposure',
        description=(
            'Many web applications do not properly protect sensitive data, such as credit cards, '
            'tax IDs, and authentication credentials. Attackers may steal or modify such weakly '
            'protected data to conduct credit card fraud, identity theft, or other crimes.'
        ),
        examples=[
            'Weak encryption algorithms (MD5, SHA1)',
            'Plaintext passwords stored',
            'Sensitive data in logs',
            'No SSL/TLS encryption',
            'Weak key generation'
        ],
        cwe_mappings=['CWE-311', 'CWE-312', 'CWE-319', 'CWE-325', 'CWE-326', 'CWE-327'],
        prevalence='Uncommon',
        detectability='Average',
        impact='Severe',
        exploitability='Difficult'
    ),

    'A7': OWASPCategory(
        rank='A7',
        name='Missing Function Level Access Control',
        description=(
            'Most web applications verify function level access rights before making that '
            'functionality visible in the UI. However, applications need to perform the same '
            'access control checks on the server when each function is accessed.'
        ),
        examples=[
            'Admin functions accessible to regular users',
            'Forced browsing to privileged pages',
            'API endpoints without authorization checks',
            'Hidden admin URLs'
        ],
        cwe_mappings=['CWE-285', 'CWE-287', 'CWE-425'],
        prevalence='Common',
        detectability='Average',
        impact='Moderate',
        exploitability='Easy'
    ),

    'A8': OWASPCategory(
        rank='A8',
        name='Cross-Site Request Forgery (CSRF)',
        description=(
            'A CSRF attack forces a logged-on victim\'s browser to send a forged HTTP request, '
            'including the victim\'s session cookie and any other automatically included '
            'authentication information, to a vulnerable web application.'
        ),
        examples=[
            'State-changing GET requests',
            'No CSRF tokens on forms',
            'Predictable CSRF tokens',
            'Missing SameSite cookie attribute'
        ],
        cwe_mappings=['CWE-352'],
        prevalence='Common',
        detectability='Easy',
        impact='Moderate',
        exploitability='Average'
    ),

    'A9': OWASPCategory(
        rank='A9',
        name='Using Components with Known Vulnerabilities',
        description=(
            'Components, such as libraries, frameworks, and other software modules, almost always '
            'run with full privileges. If a vulnerable component is exploited, such an attack can '
            'facilitate serious data loss or server takeover.'
        ),
        examples=[
            'Outdated libraries (jQuery, Spring, Struts)',
            'Unpatched frameworks',
            'Vulnerable dependencies',
            'EOL software still in use'
        ],
        cwe_mappings=['CWE-937'],
        prevalence='Widespread',
        detectability='Average',
        impact='Moderate',
        exploitability='Average'
    ),

    'A10': OWASPCategory(
        rank='A10',
        name='Unvalidated Redirects and Forwards',
        description=(
            'Web applications frequently redirect and forward users to other pages and websites, '
            'and use untrusted data to determine the destination pages. Without proper validation, '
            'attackers can redirect victims to phishing or malware sites.'
        ),
        examples=[
            'Open redirect: /redirect?url=http://evil.com',
            'Unvalidated forwards: forward(request.getParameter("page"))',
            'Header injection redirects'
        ],
        cwe_mappings=['CWE-601'],
        prevalence='Uncommon',
        detectability='Easy',
        impact='Moderate',
        exploitability='Average'
    ),
}


def get_all_categories() -> Dict[str, OWASPCategory]:
    """Get all OWASP 2013 categories."""
    return OWASP_2013


def get_category(rank: str) -> OWASPCategory:
    """Get specific OWASP 2013 category by rank (A1-A10)."""
    return OWASP_2013.get(rank)


def get_category_by_name(name: str) -> OWASPCategory:
    """Get OWASP 2013 category by name."""
    for category in OWASP_2013.values():
        if category.name.lower() == name.lower():
            return category
    return None


def search_by_cwe(cwe: str) -> List[OWASPCategory]:
    """Find OWASP 2013 categories that map to a specific CWE."""
    results = []
    for category in OWASP_2013.values():
        if cwe in category.cwe_mappings:
            results.append(category)
    return results


# Training era information
TRAINING_ERA = {
    'start_year': 2008,
    'end_year': 2013,
    'ai_models_trained': [
        'Early neural networks',
        'Statistical models',
        'Pre-deep learning era'
    ],
    'note': (
        'This OWASP version represents vulnerabilities that were documented '
        'in code repositories and tutorials from 2008-2013. AI models trained '
        'on code from this era (like early GitHub repositories) may have '
        'learned these vulnerability patterns.'
    )
}
