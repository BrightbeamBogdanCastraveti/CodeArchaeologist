"""
OWASP Top 10 - 2021 Edition

Source: https://owasp.org/Top10/
Release: September 2021

This represents the vulnerability landscape from 2017-2021.
AI models trained on code from this era (GPT-3, Codex, GitHub Copilot)
learned these patterns.

Major Changes from 2017:
- Reordered based on data from 500,000+ applications
- A1 now Broken Access Control (was A5 in 2017)
- A3 Injection moved down (was A1 in 2017 and 2013)
- Added: A8 Software and Data Integrity Failures
- Added: A10 Server-Side Request Forgery (SSRF)
- Merged: A4 XXE into A5 Security Misconfiguration
- Removed: A7 XSS as standalone (now part of other categories)
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
    prev_rank: str
    change: str
    avg_incidence_rate: float  # New in 2021: data-driven
    avg_weighted_exploit: float
    avg_weighted_impact: float


OWASP_2021 = {
    'A01': OWASPCategory(
        rank='A01',
        name='Broken Access Control',
        description=(
            'Access control enforces policy such that users cannot act outside of their intended '
            'permissions. Failures typically lead to unauthorized information disclosure, modification, '
            'or destruction of all data, or performing a business function outside the user\'s limits. '
            '94% of applications were tested for some form of broken access control with an average '
            'incidence rate of 3.81%.'
        ),
        examples=[
            'IDOR: Accessing /account?id=123 by changing to /account?id=124',
            'Missing access controls on POST, PUT, DELETE',
            'Elevation of privilege (acting as admin without being admin)',
            'Metadata manipulation (JWT, cookies)',
            'CORS misconfiguration allowing unauthorized API access',
            'Force browsing to authenticated pages as unauthenticated user'
        ],
        cwe_mappings=[
            'CWE-200', 'CWE-201', 'CWE-213', 'CWE-22', 'CWE-269',
            'CWE-284', 'CWE-285', 'CWE-352', 'CWE-359', 'CWE-639', 'CWE-732'
        ],
        prev_rank='A5 (2017)',
        change='moved_up',
        avg_incidence_rate=3.81,
        avg_weighted_exploit=6.92,
        avg_weighted_impact=5.93
    ),

    'A02': OWASPCategory(
        rank='A02',
        name='Cryptographic Failures',
        description=(
            'Previously known as Sensitive Data Exposure, this is more of a symptom rather than a root '
            'cause. The focus is on failures related to cryptography (or lack thereof), which often '
            'lead to exposure of sensitive data. Includes sensitive data in transit or at rest, old or '
            'weak cryptographic algorithms, insufficient entropy, and forced encryption.'
        ),
        examples=[
            'Transmitting data in clear text (HTTP, FTP, SMTP)',
            'Using broken crypto: MD5, SHA1, DES, RC4',
            'Default crypto keys or reused keys',
            'Missing certificate validation',
            'Passwords stored with weak hash (bcrypt work factor too low)',
            'IV reuse in encryption'
        ],
        cwe_mappings=[
            'CWE-259', 'CWE-261', 'CWE-296', 'CWE-310', 'CWE-311',
            'CWE-312', 'CWE-319', 'CWE-321', 'CWE-322', 'CWE-323',
            'CWE-324', 'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329'
        ],
        prev_rank='A3 (2017) - Sensitive Data Exposure',
        change='same',
        avg_incidence_rate=4.49,
        avg_weighted_exploit=7.29,
        avg_weighted_impact=6.81
    ),

    'A03': OWASPCategory(
        rank='A03',
        name='Injection',
        description=(
            'An application is vulnerable to attack when user-supplied data is not validated, filtered, '
            'or sanitized by the application. Hostile data is used within object-relational mapping (ORM) '
            'search parameters to extract additional, sensitive records. Includes SQL, NoSQL, OS command, '
            'ORM, LDAP, and Expression Language (EL) or Object Graph Navigation Library (OGNL) injection.'
        ),
        examples=[
            'SQL Injection: query = "SELECT * FROM users WHERE name = \'" + name + "\'"',
            'NoSQL Injection: db.users.find({username: req.params.username})',
            'OS Command: Runtime.exec("ping -c 4 " + userInput)',
            'LDAP Injection: filter = "(&(uid=" + user + ")(password=" + pass + "))"',
            'XPath Injection',
            'Template Injection (SSTI)'
        ],
        cwe_mappings=[
            'CWE-20', 'CWE-74', 'CWE-75', 'CWE-77', 'CWE-78',
            'CWE-79', 'CWE-88', 'CWE-89', 'CWE-90', 'CWE-91', 'CWE-917'
        ],
        prev_rank='A1 (2017, 2013)',
        change='moved_down',
        avg_incidence_rate=3.37,
        avg_weighted_exploit=7.25,
        avg_weighted_impact=7.15
    ),

    'A04': OWASPCategory(
        rank='A04',
        name='Insecure Design',
        description=(
            'NEW CATEGORY in 2021. Represents different weaknesses expressed as "missing or ineffective '
            'control design." Insecure design is not the source for all other Top 10 risk categories. '
            'There is a difference between insecure design and insecure implementation. Focuses on risks '
            'related to design and architectural flaws, with a call for more use of threat modeling, '
            'secure design patterns, and reference architectures.'
        ),
        examples=[
            'Lack of business logic abuse prevention',
            'Missing rate limiting on expensive operations',
            'No resource quotas leading to DoS',
            'Credential recovery using insecure knowledge-based answers',
            'Missing security controls in design phase',
            'Not implementing security by design principles'
        ],
        cwe_mappings=[
            'CWE-73', 'CWE-183', 'CWE-209', 'CWE-213', 'CWE-235',
            'CWE-256', 'CWE-257', 'CWE-266', 'CWE-269', 'CWE-280',
            'CWE-311', 'CWE-312', 'CWE-313', 'CWE-316', 'CWE-419',
            'CWE-430', 'CWE-434', 'CWE-444', 'CWE-451', 'CWE-472',
            'CWE-501', 'CWE-522', 'CWE-525', 'CWE-539', 'CWE-579',
            'CWE-598', 'CWE-602', 'CWE-642', 'CWE-648', 'CWE-668',
            'CWE-706', 'CWE-799', 'CWE-807', 'CWE-840', 'CWE-841',
            'CWE-927', 'CWE-1021', 'CWE-1173'
        ],
        prev_rank='N/A',
        change='new',
        avg_incidence_rate=3.00,
        avg_weighted_exploit=6.46,
        avg_weighted_impact=6.69
    ),

    'A05': OWASPCategory(
        rank='A05',
        name='Security Misconfiguration',
        description=(
            'The application might be vulnerable if it is missing appropriate security hardening, '
            'improperly configured permissions, unnecessary features enabled, default accounts unchanged, '
            'error handling reveals stack traces, or security settings in frameworks/libraries/databases '
            'not set to secure values. This includes XML external entities (XXE) now.'
        ),
        examples=[
            'Missing security headers',
            'Unnecessary features enabled (ports, services, pages, accounts)',
            'Default accounts with unchanged passwords',
            'Error handling reveals stack traces or detailed errors',
            'Latest security features disabled or not configured securely',
            'Missing patches and updates',
            'XXE attacks via XML parsers'
        ],
        cwe_mappings=[
            'CWE-2', 'CWE-11', 'CWE-13', 'CWE-15', 'CWE-16',
            'CWE-260', 'CWE-315', 'CWE-520', 'CWE-526', 'CWE-537',
            'CWE-541', 'CWE-611', 'CWE-614', 'CWE-756', 'CWE-776',
            'CWE-942', 'CWE-1004', 'CWE-1032', 'CWE-1174'
        ],
        prev_rank='A6 (2017)',
        change='same',
        avg_incidence_rate=4.51,
        avg_weighted_exploit=8.12,
        avg_weighted_impact=6.56
    ),

    'A06': OWASPCategory(
        rank='A06',
        name='Vulnerable and Outdated Components',
        description=(
            'You are likely vulnerable if you do not know the versions of all components you use (both '
            'client-side and server-side), software is vulnerable, unsupported, or out of date. If you '
            'do not scan for vulnerabilities regularly, do not subscribe to security bulletins related to '
            'the components you use, or do not secure the components\' configurations.'
        ),
        examples=[
            'Using libraries with known CVEs (Log4Shell, Struts)',
            'Outdated dependencies (old jQuery, old React)',
            'Unpatched OS or runtime (old Node.js, old Python)',
            'Not monitoring component versions',
            'Incompatible or outdated patch levels',
            'Supply chain attacks via compromised dependencies'
        ],
        cwe_mappings=['CWE-937', 'CWE-1035', 'CWE-1104'],
        prev_rank='A9 (2017)',
        change='same',
        avg_incidence_rate=8.77,
        avg_weighted_exploit=5.00,
        avg_weighted_impact=5.00
    ),

    'A07': OWASPCategory(
        rank='A07',
        name='Identification and Authentication Failures',
        description=(
            'Previously known as Broken Authentication. Confirmation of the user\'s identity, '
            'authentication, and session management is critical to protect against authentication-related '
            'attacks. Includes credential stuffing, brute force, session fixation, and weak session management.'
        ),
        examples=[
            'Permits automated attacks like credential stuffing',
            'Permits brute force or other automated attacks',
            'Permits default, weak, or well-known passwords',
            'Weak or ineffective credential recovery (knowledge-based answers)',
            'Missing or ineffective multi-factor authentication',
            'Exposes session identifier in URL',
            'Reuses session identifier after successful login',
            'Does not properly invalidate session IDs on logout'
        ],
        cwe_mappings=[
            'CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-290',
            'CWE-294', 'CWE-295', 'CWE-297', 'CWE-300', 'CWE-302',
            'CWE-304', 'CWE-306', 'CWE-307', 'CWE-346', 'CWE-384',
            'CWE-521', 'CWE-613', 'CWE-620', 'CWE-640', 'CWE-798',
            'CWE-940', 'CWE-1216'
        ],
        prev_rank='A2 (2017) - Broken Authentication',
        change='same',
        avg_incidence_rate=2.55,
        avg_weighted_exploit=7.40,
        avg_weighted_impact=6.50
    ),

    'A08': OWASPCategory(
        rank='A08',
        name='Software and Data Integrity Failures',
        description=(
            'NEW CATEGORY in 2021. Focuses on making assumptions related to software updates, critical '
            'data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts. '
            'Includes insecure deserialization from 2017 A8. Notable Common Weakness Enumerations (CWEs) '
            'include CWE-829, CWE-494, and CWE-502.'
        ),
        examples=[
            'Applications using unsigned updates or CI/CD without integrity checks',
            'Insecure deserialization (pickle, unserialize(), readObject())',
            'Auto-update without signature verification',
            'SolarWinds-style supply chain attacks',
            'Dependencies from untrusted sources',
            'Unverified CI/CD pipelines modifying code'
        ],
        cwe_mappings=[
            'CWE-345', 'CWE-353', 'CWE-426', 'CWE-494', 'CWE-502',
            'CWE-565', 'CWE-784', 'CWE-829', 'CWE-830', 'CWE-915'
        ],
        prev_rank='A8 (2017) - Insecure Deserialization',
        change='expanded',
        avg_incidence_rate=2.05,
        avg_weighted_exploit=6.94,
        avg_weighted_impact=7.94
    ),

    'A09': OWASPCategory(
        rank='A09',
        name='Security Logging and Monitoring Failures',
        description=(
            'Previously A10 Insufficient Logging & Monitoring. Without logging and monitoring, breaches '
            'cannot be detected. Insufficient logging, detection, monitoring and active response occurs '
            'any time. Most successful attacks start with vulnerability probing.'
        ),
        examples=[
            'Auditable events not logged (logins, high-value transactions)',
            'Warnings and errors generate no or inadequate logs',
            'Logs only stored locally',
            'No alerting thresholds and response escalation processes',
            'Penetration testing and DAST scans do not trigger alerts',
            'Application cannot detect, escalate, or alert for active attacks'
        ],
        cwe_mappings=[
            'CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'
        ],
        prev_rank='A10 (2017)',
        change='same',
        avg_incidence_rate=6.51,
        avg_weighted_exploit=6.87,
        avg_weighted_impact=4.99
    ),

    'A10': OWASPCategory(
        rank='A10',
        name='Server-Side Request Forgery (SSRF)',
        description=(
            'NEW CATEGORY in 2021. SSRF flaws occur whenever a web application is fetching a remote '
            'resource without validating the user-supplied URL. It allows an attacker to coerce the '
            'application to send a crafted request to an unexpected destination, even when protected by '
            'a firewall, VPN, or another type of network access control list (ACL).'
        ),
        examples=[
            'Fetching user-supplied URL without validation',
            'Access internal services via 127.0.0.1, localhost, or internal IPs',
            'Port scanning internal network',
            'Reading files via file:// protocol',
            'Accessing cloud metadata endpoints (AWS 169.254.169.254)',
            'DNS rebinding attacks'
        ],
        cwe_mappings=['CWE-918'],
        prev_rank='N/A (community survey addition)',
        change='new',
        avg_incidence_rate=2.72,
        avg_weighted_exploit=8.28,
        avg_weighted_impact=6.72
    ),
}


def get_all_categories() -> Dict[str, OWASPCategory]:
    """Get all OWASP 2021 categories."""
    return OWASP_2021


def get_category(rank: str) -> OWASPCategory:
    """Get specific OWASP 2021 category by rank (A01-A10)."""
    return OWASP_2021.get(rank)


def get_changes_from_2017() -> Dict[str, List[str]]:
    """Get summary of changes from OWASP 2017 to 2021."""
    return {
        'moved_up': ['A01 Broken Access Control (was A5)'],
        'moved_down': ['A03 Injection (was A1)'],
        'new_entries': [
            'A04 Insecure Design',
            'A08 Software and Data Integrity Failures (expanded from Deserialization)',
            'A10 Server-Side Request Forgery (SSRF)'
        ],
        'merged': ['A4 XXE merged into A5 Security Misconfiguration'],
        'renamed': [
            'A02 Cryptographic Failures (was Sensitive Data Exposure)',
            'A07 Identification and Authentication Failures (was Broken Authentication)',
            'A09 Security Logging and Monitoring Failures (was Insufficient Logging)'
        ],
        'removed_as_standalone': ['A7 XSS (now part of A03 Injection)']
    }


# Training era information
TRAINING_ERA = {
    'start_year': 2017,
    'end_year': 2021,
    'ai_models_trained': [
        'GPT-3 (2020, trained on pre-2019 code)',
        'Codex (2021, trained on GitHub 2017-2020)',
        'GitHub Copilot (2021, based on Codex)',
        'AlphaCode (2021)',
        'CodeBERT variants (2020-2021)'
    ],
    'note': (
        'This OWASP version represents vulnerabilities from 2017-2021. '
        'This is the MOST CRITICAL era for current AI code generation. '
        'GPT-3, Codex, and GitHub Copilot were trained on code repositories '
        'from exactly this period. When these AI models generate vulnerable code, '
        'they are often reproducing patterns from this OWASP era that were present '
        'in their training data (2017-2020 GitHub repositories).'
    ),
    'why_ai_generates_these': (
        'AI models trained on 2017-2020 code learned vulnerability patterns that '
        'were documented and shared during this OWASP cycle. Stack Overflow answers, '
        'GitHub repositories, and tutorials from this era contained these exact patterns. '
        'The models optimized for "code that looks right" without understanding security '
        'implications.'
    )
}
