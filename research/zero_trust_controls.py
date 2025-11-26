"""
Module: zero_trust_controls.py
Author: Code Archaeologist Team
Purpose: Define required security controls from Zero Trust architecture.

This module contains security controls that AI-generated code typically LACKS.
Based on: "Expert Blueprint: Designing a Super Secure Web Application with
Zero Trust Email Ingestion"

REVOLUTIONARY CAPABILITY:
While academic_validation.py explains WHY AI generates vulnerabilities,
this module defines WHAT secure code should look like - enabling detection
of MISSING CONTROLS (not just present vulnerabilities).

CRITICAL: Max 400 lines per CLAUDE.md standards.
"""

from typing import Dict, List, Set

# =============================================================================
# OWASP A01:2025 - Broken Access Control
# =============================================================================

A01_BROKEN_ACCESS_CONTROL = {
    'owasp_category': 'A01:2025 - Broken Access Control',
    'severity': 'CRITICAL',

    'required_controls': [
        '@login_required on all non-public views',
        'Role-Based Access Control (RBAC) implementation',
        'Deny by default (whitelist approach)',
        'No @csrf_exempt abuse',
        'Object-level permission checks',
        'Rate limiting on sensitive endpoints'
    ],

    'why_ai_misses_this': '''
        AI generates functional code that "works" without authentication.
        Training data from tutorials (2010-2018) often showed authentication
        as an afterthought or "TODO: add auth later" comments.
    ''',

    'detection_patterns': {
        'missing_login_required': r'def\s+\w+\(request[,\)].*:(?!\s*@login_required)',
        'csrf_exempt_abuse': r'@csrf_exempt',
        'no_permission_check': r'\.delete\(|\.update\((?!.*check_permission)'
    },

    'compliant_example': '''
        @login_required
        @require_http_methods(["POST", "DELETE"])
        @permission_required('app.delete_resource')
        def delete_resource(request, resource_id):
            resource = get_object_or_404(Resource, pk=resource_id)
            if resource.owner != request.user:
                return HttpResponseForbidden()
            resource.delete()
            return JsonResponse({'status': 'deleted'})
    '''
}

# =============================================================================
# OWASP A02:2025 - Cryptographic Failures
# =============================================================================

A02_CRYPTOGRAPHIC_FAILURES = {
    'owasp_category': 'A02:2025 - Cryptographic Failures',
    'severity': 'CRITICAL',

    'required_controls': [
        'TLS 1.3 for all external connections',
        'AES-256-GCM for data encryption',
        'bcrypt (cost >= 12) for password hashing',
        'Secrets in environment variables (never hardcoded)',
        'HSTS headers (max-age >= 31536000)',
        'No MD5 or SHA1 for security purposes'
    ],

    'why_ai_misses_this': '''
        Training data (2008-2015) heavily featured MD5 for passwords in
        tutorials. StackOverflow answers with thousands of upvotes showed
        hashlib.md5(password.encode()).hexdigest() as the "correct answer."
    ''',

    'detection_patterns': {
        'weak_crypto': r'hashlib\.(md5|sha1)',
        'hardcoded_secrets': r'(api_key|secret|password)\s*=\s*["\'][^"\']+["\']',
        'no_tls': r'http://(?!localhost|127\.0\.0\.1)',
        'weak_bcrypt': r'bcrypt\.gensalt\(rounds?=[4-9]\)'
    },

    'compliant_example': '''
        import bcrypt
        import os

        # Secrets from environment
        API_KEY = os.environ.get('API_KEY')

        # Strong password hashing
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

        # TLS 1.3 enforced
        SECURE_SSL_REDIRECT = True
        SECURE_HSTS_SECONDS = 31536000
    '''
}

# =============================================================================
# OWASP A03:2025 - Injection
# =============================================================================

A03_INJECTION = {
    'owasp_category': 'A03:2025 - Injection',
    'severity': 'CRITICAL',

    'required_controls': [
        'Parameterized queries (ORM filter, not raw SQL)',
        'Output encoding for all user input in HTML',
        'Command injection prevention (no shell=True)',
        'Template auto-escaping enabled',
        'Content Security Policy headers',
        'Input validation with allowlists'
    ],

    'why_ai_misses_this': '''
        String concatenation for SQL was ubiquitous in training data (2005-2015).
        StackOverflow Question #10031947 (2012, 2400+ upvotes) showed
        filter(**kwargs) pattern without explaining injection risks.
    ''',

    'detection_patterns': {
        'sql_injection': r'\.raw\(f["\']|\.execute\(f["\']|% \(.*?\)',
        'command_injection': r'subprocess\.(run|call|Popen).*shell\s*=\s*True',
        'no_output_encoding': r'render.*\{\{.*?\|safe\}\}',
        'no_csp': r'(?!Content-Security-Policy)'
    },

    'compliant_example': '''
        # Parameterized queries
        candidates = Candidate.objects.filter(name__icontains=query)

        # Output encoding (Django auto-escapes)
        return render(request, 'template.html', {'name': user_input})

        # CSP headers
        SECURE_CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self'"

        # No shell injection
        result = subprocess.run(['ls', user_dir], capture_output=True, shell=False)
    '''
}

# =============================================================================
# OWASP A10:2025 - Server-Side Request Forgery (SSRF)
# =============================================================================

A10_SSRF = {
    'owasp_category': 'A10:2025 - Server-Side Request Forgery',
    'severity': 'CRITICAL',

    'required_controls': [
        'Layer 1: URL allowlist (explicit permitted domains)',
        'Layer 2: DNS resolution check + private IP blocking',
        'Layer 3: FQDN filtering at network/infrastructure level',
        'Block RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)',
        'Block loopback (127.0.0.0/8)',
        'Block AWS metadata (169.254.169.254)',
        'Block link-local (169.254.0.0/16)',
        'Timeout on outbound requests (max 5 seconds)'
    ],

    'why_ai_misses_this': '''
        AI generates code that "fetches URL from user" without understanding
        internal network architecture. Training data rarely showed SSRF defenses
        because most tutorials assumed simple, non-production environments.
    ''',

    'three_layer_defense': {
        'layer_1_code': '''
            ALLOWED_DOMAINS = {'linkedin.com', 'github.com', 'example.com'}

            def is_url_allowed(url):
                parsed = urlparse(url)
                domain = parsed.netloc.split(':')[0]
                return domain in ALLOWED_DOMAINS
        ''',

        'layer_2_code': '''
            import ipaddress
            import socket

            BLOCKED_RANGES = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('127.0.0.0/8'),
                ipaddress.ip_network('169.254.0.0/16')
            ]

            def is_private_ip(hostname):
                try:
                    ip = socket.gethostbyname(hostname)
                    ip_obj = ipaddress.ip_address(ip)
                    return any(ip_obj in network for network in BLOCKED_RANGES)
                except:
                    return True  # Fail secure
        ''',

        'layer_3_infrastructure': '''
            # Kubernetes NetworkPolicy (Infrastructure level)
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata:
              name: egress-allowlist
            spec:
              podSelector:
                matchLabels:
                  app: email-parser
              policyTypes:
              - Egress
              egress:
              - to:
                - podSelector:
                    matchLabels:
                      app: allowed-external
                ports:
                - protocol: TCP
                  port: 443
        '''
    },

    'detection_patterns': {
        'no_url_allowlist': r'requests\.get\(.*url.*\)(?!.*ALLOWED_DOMAINS)',
        'no_ip_check': r'requests\.(get|post).*(?!is_private_ip)',
        'direct_user_url': r'requests\.get\(request\.(GET|POST|data)\[',
        'aws_metadata_risk': r'169\.254\.169\.254'
    },

    'compliant_example': '''
        def fetch_linkedin_profile(request):
            url = request.POST.get('profile_url')

            # Layer 1: URL allowlist
            if not is_url_allowed(url):
                return JsonResponse({'error': 'Domain not allowed'}, status=400)

            # Layer 2: DNS resolution + private IP check
            parsed = urlparse(url)
            if is_private_ip(parsed.netloc):
                return JsonResponse({'error': 'Private IP blocked'}, status=400)

            # Layer 3: Network policy enforces FQDN filtering
            response = requests.get(url, timeout=5)
            return JsonResponse({'data': response.text})
    '''
}

# =============================================================================
# EMAIL HEADER INJECTION (Critical for Email Ingestion)
# =============================================================================

EMAIL_HEADER_INJECTION = {
    'vulnerability_name': 'Email Header Injection',
    'cwe_id': 'CWE-93',
    'severity': 'HIGH',

    'attack_vector': '''
        Injecting \\r\\n (CRLF) into email headers allows attackers to:
        - Add Bcc recipients (data exfiltration)
        - Inject malicious Reply-To addresses (phishing)
        - Add malicious headers (spam campaigns)
        - SMTP command injection
    ''',

    'required_controls': [
        'Strict removal of \\r and \\n from ALL user-controlled email fields',
        'Use email-validator library for format validation',
        'Reject emails with suspicious headers',
        'Log all email sending attempts'
    ],

    'why_ai_misses_this': '''
        PHP mail() tutorials (2008-2015) showed direct concatenation:
        mail($to, $_POST['subject'], $message);

        This pattern was widely copied without understanding header injection risks.
    ''',

    'detection_patterns': {
        'no_crlf_removal': r'send_mail\(.*subject.*\)(?!.*replace.*\\r)',
        'direct_request_to_header': r'send_mail\(.*request\.(GET|POST)',
        'no_validation': r'send_mail\((?!.*email_validator)'
    },

    'compliant_example': '''
        from email_validator import validate_email, EmailNotValidError

        def send_application_email(request):
            subject = request.POST.get('subject', '')
            reply_to = request.POST.get('reply_to', '')

            # CRITICAL: Remove ALL \\r and \\n
            subject = subject.replace('\\r', '').replace('\\n', '')
            reply_to = reply_to.replace('\\r', '').replace('\\n', '')

            # Validate email format
            try:
                validate_email(reply_to)
            except EmailNotValidError:
                return JsonResponse({'error': 'Invalid email'}, status=400)

            send_mail(
                subject=subject,
                message=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[settings.ADMIN_EMAIL],
                headers={'Reply-To': reply_to}
            )
    '''
}

# =============================================================================
# FILE UPLOAD SECURITY (Critical for CV Parsing)
# =============================================================================

FILE_UPLOAD_SECURITY = {
    'vulnerability_name': 'Insecure File Upload',
    'cwe_id': 'CWE-434',
    'severity': 'CRITICAL',

    'attack_vectors': [
        'RCE via PHP/JSP/ASP file upload',
        'XXE in DOCX/PDF parsing',
        'Path traversal (../../etc/passwd)',
        'DoS via large files',
        'Malware distribution'
    ],

    'required_controls': [
        'Layer 1: Extension allowlist (not blocklist)',
        'Layer 2: Content-Type validation',
        'Layer 3: Magic bytes verification',
        'File size limits (max 10MB for CVs)',
        'Antivirus scanning',
        'Rename files (UUIDs, not original names)',
        'Store outside web root',
        'Separate subdomain for file serving'
    ],

    'three_layer_validation': {
        'layer_1_extension': '''
            ALLOWED_EXTENSIONS = {'.pdf', '.docx', '.doc', '.txt'}

            def check_extension(filename):
                ext = os.path.splitext(filename)[1].lower()
                return ext in ALLOWED_EXTENSIONS
        ''',

        'layer_2_content_type': '''
            ALLOWED_CONTENT_TYPES = {
                'application/pdf',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'text/plain'
            }

            def check_content_type(file):
                return file.content_type in ALLOWED_CONTENT_TYPES
        ''',

        'layer_3_magic_bytes': '''
            import magic

            MAGIC_BYTES = {
                'pdf': b'%PDF',
                'docx': b'PK\\x03\\x04',  # ZIP signature
                'txt': None  # Text files have no magic bytes
            }

            def check_magic_bytes(file):
                header = file.read(4)
                file.seek(0)
                mime = magic.from_buffer(header, mime=True)
                return mime in ALLOWED_CONTENT_TYPES
        '''
    },

    'detection_patterns': {
        'no_extension_check': r'\.save\(.*\)(?!.*ALLOWED_EXTENSIONS)',
        'no_content_type_check': r'request\.FILES\[.*\](?!.*content_type)',
        'no_magic_bytes': r'\.save\(.*\)(?!.*magic\.from_buffer)',
        'original_filename': r'\.save\(.*filename.*\)',
        'no_size_limit': r'request\.FILES(?!.*\.size)'
    },

    'compliant_example': '''
        import magic
        import uuid

        def upload_cv(request):
            cv_file = request.FILES.get('cv')

            # Size limit
            if cv_file.size > 10 * 1024 * 1024:  # 10MB
                return JsonResponse({'error': 'File too large'}, status=400)

            # Layer 1: Extension
            if not check_extension(cv_file.name):
                return JsonResponse({'error': 'Invalid extension'}, status=400)

            # Layer 2: Content-Type
            if not check_content_type(cv_file):
                return JsonResponse({'error': 'Invalid content type'}, status=400)

            # Layer 3: Magic bytes
            if not check_magic_bytes(cv_file):
                return JsonResponse({'error': 'File type mismatch'}, status=400)

            # Rename with UUID
            ext = os.path.splitext(cv_file.name)[1]
            safe_filename = f"{uuid.uuid4()}{ext}"

            # Save outside web root
            save_path = os.path.join(settings.MEDIA_ROOT, 'cvs', safe_filename)
            with open(save_path, 'wb+') as destination:
                for chunk in cv_file.chunks():
                    destination.write(chunk)

            # TODO: Run antivirus scan

            return JsonResponse({'filename': safe_filename})
    '''
}

# =============================================================================
# XXE (XML External Entity) - Critical for Document Parsing
# =============================================================================

XXE_PREVENTION = {
    'vulnerability_name': 'XML External Entity (XXE) Injection',
    'cwe_id': 'CWE-611',
    'severity': 'CRITICAL',

    'attack_vector': '''
        DOCX files are ZIP archives containing XML. Malicious XML can:
        - Read local files (/etc/passwd)
        - Perform SSRF (internal network scanning)
        - Cause DoS (billion laughs attack)
    ''',

    'required_controls': [
        'Disable external entity resolution',
        'Use defusedxml library (not standard xml)',
        'Set resolve_entities=False',
        'Validate XML structure before parsing',
        'Limit XML depth and entity count'
    ],

    'why_ai_misses_this': '''
        AI generates code using python-docx or xml.etree without understanding
        that DOCX files contain potentially malicious XML. Training data showed
        document parsing as a simple task without security context.
    ''',

    'detection_patterns': {
        'unsafe_xml_parsing': r'xml\.etree|ElementTree\((?!.*defusedxml)',
        'no_entity_disable': r'parse\((?!.*resolve_entities\s*=\s*False)',
        'docx_without_validation': r'Document\(.*\.docx\)(?!.*validate)'
    },

    'compliant_example': '''
        from defusedxml.ElementTree import parse
        from docx import Document

        def parse_cv_docx(file_path):
            try:
                # Use defusedxml for any manual XML parsing
                tree = parse(file_path, forbid_dtd=True, forbid_entities=True)

                # python-docx is safer but still validate
                doc = Document(file_path)

                # Extract text safely
                text = '\\n'.join([p.text for p in doc.paragraphs])
                return text
            except Exception as e:
                logger.error(f"CV parsing failed: {e}")
                return None
    '''
}

# =============================================================================
# Helper Functions
# =============================================================================

def get_required_controls(owasp_category: str) -> List[str]:
    """
    Get required security controls for a specific OWASP category.

    Args:
        owasp_category: OWASP category (e.g., 'A01', 'A03', 'A10')

    Returns:
        List of required security controls
    """
    controls_map = {
        'A01': A01_BROKEN_ACCESS_CONTROL,
        'A02': A02_CRYPTOGRAPHIC_FAILURES,
        'A03': A03_INJECTION,
        'A10': A10_SSRF
    }

    control = controls_map.get(owasp_category)
    return control['required_controls'] if control else []


def check_missing_controls(code: str, category: str) -> List[str]:
    """
    Check which required controls are missing from code.

    Args:
        code: Source code to analyze
        category: OWASP category to check

    Returns:
        List of missing controls
    """
    import re

    controls_map = {
        'A01': A01_BROKEN_ACCESS_CONTROL,
        'A03': A03_INJECTION,
        'A10': A10_SSRF,
        'EMAIL': EMAIL_HEADER_INJECTION,
        'UPLOAD': FILE_UPLOAD_SECURITY,
        'XXE': XXE_PREVENTION
    }

    control_def = controls_map.get(category)
    if not control_def:
        return []

    missing = []
    patterns = control_def.get('detection_patterns', {})

    for pattern_name, pattern in patterns.items():
        if re.search(pattern, code, re.MULTILINE | re.DOTALL):
            missing.append(pattern_name)

    return missing


# Export all controls
ZERO_TRUST_CONTROLS = {
    'A01_BROKEN_ACCESS_CONTROL': A01_BROKEN_ACCESS_CONTROL,
    'A02_CRYPTOGRAPHIC_FAILURES': A02_CRYPTOGRAPHIC_FAILURES,
    'A03_INJECTION': A03_INJECTION,
    'A10_SSRF': A10_SSRF,
    'EMAIL_HEADER_INJECTION': EMAIL_HEADER_INJECTION,
    'FILE_UPLOAD_SECURITY': FILE_UPLOAD_SECURITY,
    'XXE_PREVENTION': XXE_PREVENTION
}
