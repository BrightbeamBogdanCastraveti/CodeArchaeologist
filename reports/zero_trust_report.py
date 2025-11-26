"""
Zero Trust Architecture Report Generator

Analyzes codebase compliance with Zero Trust security principles:
- Never trust, always verify
- Assume breach
- Verify explicitly
- Use least privilege access
- Segment access
- Defense in depth (3-layer minimum)

Identifies missing zero trust controls and microsegmentation gaps.

Format: Markdown with actionable recommendations
"""

from typing import Dict, List, Tuple
from collections import defaultdict
from pathlib import Path


class ZeroTrustReport:
    """Generate Zero Trust Architecture compliance report."""

    def __init__(self, scan_results):
        """Initialize with scan results."""
        self.results = scan_results
        self.findings = scan_results.findings

    def generate(self) -> str:
        """Generate complete Zero Trust compliance report."""
        sections = [
            self._header(),
            self._executive_summary(),
            self._never_trust_always_verify(),
            self._defense_in_depth(),
            self._least_privilege(),
            self._microsegmentation(),
            self._explicit_verification(),
            self._assume_breach(),
            self._recommendations(),
            self._footer()
        ]

        return '\n\n'.join(sections)

    def _header(self) -> str:
        """Generate report header."""
        project_name = Path(self.results.project_path).name

        return f"""# Zero Trust Architecture Compliance Report

**Project:** {project_name}
**Analysis Date:** {self.results.scan_date}
**Framework:** Zero Trust Architecture (NIST SP 800-207)

---
"""

    def _executive_summary(self) -> str:
        """Executive summary of Zero Trust posture."""
        # Analyze findings for Zero Trust compliance
        auth_issues = [f for f in self.findings if f.category in ['auth_bypass', 'missing_auth']]
        access_control_issues = [f for f in self.findings if 'access_control' in f.category.lower()]
        input_validation_issues = [f for f in self.findings if 'validation' in f.category.lower()]

        # Calculate compliance score
        total_checks = 50  # Arbitrary baseline
        failed_checks = len(auth_issues) + len(access_control_issues) + len(input_validation_issues)
        compliance_score = max(0, 100 - (failed_checks * 2))

        if compliance_score >= 90:
            status = "✅ STRONG"
            color = "green"
        elif compliance_score >= 70:
            status = "⚠️  MODERATE"
            color = "yellow"
        else:
            status = "🔴 WEAK"
            color = "red"

        return f"""## Executive Summary

### Zero Trust Posture: {status}

**Compliance Score:** {compliance_score}/100

```
Zero Trust Compliance: {'█' * (compliance_score // 10)}{'░' * (10 - compliance_score // 10)} {compliance_score}%
```

**Key Findings:**
- Authentication Issues: {len(auth_issues)}
- Access Control Gaps: {len(access_control_issues)}
- Input Validation Missing: {len(input_validation_issues)}

**Critical Gaps:**
{self._identify_critical_gaps()}

### What is Zero Trust?

Zero Trust is a security framework requiring all users, whether inside or outside
the organization's network, to be authenticated, authorized, and continuously
validated before being granted access to applications and data.

**Core Principles:**
1. **Never Trust, Always Verify** - Verify every request regardless of source
2. **Assume Breach** - Design as if attackers are already inside
3. **Verify Explicitly** - Always authenticate and authorize based on all data points
4. **Use Least Privilege** - Limit user access with Just-In-Time and Just-Enough-Access
5. **Segment Access** - Use microsegmentation to minimize breach impact
6. **Defense in Depth** - Multiple layers of security controls

---
"""

    def _identify_critical_gaps(self) -> str:
        """Identify the most critical Zero Trust gaps."""
        gaps = []

        # Check for missing authentication
        auth_issues = [f for f in self.findings if f.category == 'auth_bypass']
        if auth_issues:
            gaps.append(f"- Missing authentication on {len(auth_issues)} endpoints")

        # Check for missing input validation
        validation_issues = [f for f in self.findings if 'validation' in f.category.lower()]
        if validation_issues:
            gaps.append(f"- Missing input validation on {len(validation_issues)} inputs")

        # Check for hardcoded secrets (violates explicit verification)
        secret_issues = [f for f in self.findings if 'secret' in f.category.lower()]
        if secret_issues:
            gaps.append(f"- Hardcoded secrets found: {len(secret_issues)} instances")

        # Check for IDOR (violates least privilege)
        idor_issues = [f for f in self.findings if 'idor' in f.description.lower()]
        if idor_issues:
            gaps.append(f"- Insecure Direct Object References: {len(idor_issues)} cases")

        if not gaps:
            gaps.append("- No critical gaps identified")

        return '\n'.join(gaps)

    def _never_trust_always_verify(self) -> str:
        """Analyze 'Never Trust, Always Verify' principle compliance."""
        # Find endpoints without authentication
        auth_issues = [f for f in self.findings if 'auth' in f.category.lower()]

        # Find SQL injections (trusting user input)
        sqli_issues = [f for f in self.findings if 'sql' in f.category.lower()]

        # Find XSS (trusting user input for output)
        xss_issues = [f for f in self.findings if 'xss' in f.category.lower()]

        total_trust_violations = len(auth_issues) + len(sqli_issues) + len(xss_issues)

        if total_trust_violations == 0:
            status = "✅ COMPLIANT"
            assessment = "Code properly validates and verifies all inputs and requests."
        elif total_trust_violations < 5:
            status = "⚠️  NEEDS IMPROVEMENT"
            assessment = f"Found {total_trust_violations} instances where code trusts input without verification."
        else:
            status = "🔴 NON-COMPLIANT"
            assessment = f"Found {total_trust_violations} violations. Code frequently trusts input without verification."

        return f"""## 1. Never Trust, Always Verify

**Status:** {status}

**Assessment:** {assessment}

### Violations Found:

#### Missing Authentication ({len(auth_issues)} issues)
{self._format_issue_list(auth_issues[:5], "Authentication required but not enforced")}

#### Trusting User Input - SQL Injection ({len(sqli_issues)} issues)
{self._format_issue_list(sqli_issues[:5], "User input trusted in SQL queries")}

#### Trusting User Input - XSS ({len(xss_issues)} issues)
{self._format_issue_list(xss_issues[:5], "User input trusted in output")}

### Recommendations:
1. **Implement authentication on all endpoints** - No unauthenticated access
2. **Validate all inputs** - Use parameterized queries, input sanitization
3. **Validate all outputs** - Escape data before rendering
4. **Use allowlists** - Define what's allowed, reject everything else

---
"""

    def _defense_in_depth(self) -> str:
        """Analyze Defense in Depth (multiple security layers)."""
        # Check for multiple layers of defense
        layers_found = set()

        # Layer 1: Input validation
        if any('validation' in f.category.lower() for f in self.findings):
            layers_missing = "Input Validation"
        else:
            layers_found.add("Input Validation")

        # Layer 2: Authentication
        if any('auth' in f.category.lower() for f in self.findings):
            layers_missing = "Authentication"
        else:
            layers_found.add("Authentication")

        # Layer 3: Authorization (access control)
        if any('access' in f.category.lower() or 'idor' in f.description.lower() for f in self.findings):
            layers_missing = "Authorization"
        else:
            layers_found.add("Authorization")

        # Layer 4: Output encoding
        if any('xss' in f.category.lower() for f in self.findings):
            layers_missing = "Output Encoding"
        else:
            layers_found.add("Output Encoding")

        # Layer 5: Logging and monitoring
        if any('logging' in f.category.lower() for f in self.findings):
            layers_missing = "Logging"
        else:
            layers_found.add("Logging")

        layer_count = len(layers_found)

        if layer_count >= 5:
            status = "✅ STRONG (5+ layers)"
        elif layer_count >= 3:
            status = "⚠️  MODERATE (3-4 layers)"
        else:
            status = "🔴 WEAK (< 3 layers)"

        return f"""## 2. Defense in Depth (Multiple Security Layers)

**Status:** {status}

**Security Layers Present:** {layer_count}/5

```
{'✅' if 'Input Validation' in layers_found else '❌'} Layer 1: Input Validation
{'✅' if 'Authentication' in layers_found else '❌'} Layer 2: Authentication
{'✅' if 'Authorization' in layers_found else '❌'} Layer 3: Authorization (Access Control)
{'✅' if 'Output Encoding' in layers_found else '❌'} Layer 4: Output Encoding
{'✅' if 'Logging' in layers_found else '❌'} Layer 5: Logging & Monitoring
```

### Zero Trust Requirement: Minimum 3 Layers

Zero Trust architecture requires at least **3 independent layers** of security.
If one layer fails, the others should still protect the system.

**Current Assessment:**
- Your codebase has {layer_count} security layers
- {'✅ Meets' if layer_count >= 3 else '🔴 Below'} Zero Trust minimum (3 layers)

### Recommended Additional Layers:
1. **Rate Limiting** - Prevent brute force and DoS
2. **Encryption** - Data at rest and in transit
3. **Anomaly Detection** - Behavioral monitoring
4. **Network Segmentation** - Isolate sensitive components

---
"""

    def _least_privilege(self) -> str:
        """Analyze Least Privilege compliance."""
        # Find instances of excessive permissions
        idor_issues = [f for f in self.findings if 'idor' in f.description.lower()]
        auth_bypass = [f for f in self.findings if 'auth_bypass' in f.category]
        access_issues = [f for f in self.findings if 'access_control' in f.category.lower()]

        total_privilege_violations = len(idor_issues) + len(auth_bypass) + len(access_issues)

        if total_privilege_violations == 0:
            status = "✅ COMPLIANT"
        elif total_privilege_violations < 5:
            status = "⚠️  NEEDS IMPROVEMENT"
        else:
            status = "🔴 NON-COMPLIANT"

        return f"""## 3. Least Privilege Access

**Status:** {status}

**Violations Found:** {total_privilege_violations}

### Principle:
Users and systems should have the **minimum permissions** necessary to perform their tasks.

### Violations Detected:

#### Insecure Direct Object References (IDOR) - {len(idor_issues)} issues
{self._format_issue_list(idor_issues[:3], "Users can access resources without ownership checks")}

#### Missing Access Controls - {len(access_issues)} issues
{self._format_issue_list(access_issues[:3], "No permission checks before sensitive operations")}

### Zero Trust Implementation:
```python
# ❌ VIOLATES Least Privilege
def get_document(doc_id):
    return Document.objects.get(id=doc_id)  # Any user can access any document

# ✅ IMPLEMENTS Least Privilege
def get_document(doc_id, user):
    doc = Document.objects.get(id=doc_id)
    if doc.owner != user and user not in doc.shared_with:
        raise PermissionDenied("Access denied")
    return doc
```

### Recommendations:
1. **Implement Role-Based Access Control (RBAC)**
2. **Add ownership checks** before object access
3. **Use Just-In-Time (JIT) access** - Temporary elevated permissions
4. **Log all permission escalations** - Audit trail

---
"""

    def _microsegmentation(self) -> str:
        """Analyze microsegmentation and network isolation."""
        # This is more architectural, so we make general recommendations
        return """## 4. Microsegmentation

**Status:** ⚠️  REQUIRES MANUAL REVIEW

### Principle:
Divide the network into secure zones to contain breaches and limit lateral movement.

### Zero Trust Microsegmentation Model:

```
┌─────────────────────────────────────────────────────────┐
│ INTERNET                                                │
└────────────────┬────────────────────────────────────────┘
                 │
         ┌───────▼───────┐
         │   WAF / CDN   │ ◄─── Layer 1: Edge Security
         └───────┬───────┘
                 │
         ┌───────▼───────┐
         │  API Gateway  │ ◄─── Layer 2: API Authentication
         │  + Auth       │
         └───────┬───────┘
                 │
         ┌───────▼───────┐
         │  Application  │ ◄─── Layer 3: Application Logic
         │   Services    │      (Validate inputs, check permissions)
         └───────┬───────┘
                 │
         ┌───────▼───────┐
         │   Database    │ ◄─── Layer 4: Data Layer
         │   (Private)   │      (Parameterized queries, encryption)
         └───────────────┘
```

### Requirements for Zero Trust:
1. **Network Segmentation** - Separate zones for web, app, data
2. **Zero Trust Network Access (ZTNA)** - No VPN trust model
3. **Service Mesh** - mTLS between microservices
4. **Private Subnets** - Databases not directly accessible
5. **Security Groups** - Whitelist-only firewall rules

### Manual Review Checklist:
- [ ] Web servers in public subnet, app/DB in private subnets?
- [ ] Services communicate via encrypted channels (TLS/mTLS)?
- [ ] No direct database access from internet?
- [ ] Security groups restrict traffic to minimum needed?
- [ ] VPC/Network segmentation implemented?

### Recommendations:
1. **Implement network segmentation** if not already done
2. **Use private subnets** for databases and internal services
3. **Enable mTLS** for service-to-service communication
4. **Deploy service mesh** (Istio, Linkerd) for zero trust networking

---
"""

    def _explicit_verification(self) -> str:
        """Analyze explicit verification practices."""
        # Check for verification issues
        auth_issues = [f for f in self.findings if 'auth' in f.category.lower()]
        csrf_issues = [f for f in self.findings if 'csrf' in f.category.lower()]
        jwt_issues = [f for f in self.findings if 'jwt' in f.description.lower()]

        verification_failures = len(auth_issues) + len(csrf_issues) + len(jwt_issues)

        if verification_failures == 0:
            status = "✅ STRONG"
        elif verification_failures < 5:
            status = "⚠️  MODERATE"
        else:
            status = "🔴 WEAK"

        return f"""## 5. Verify Explicitly

**Status:** {status}

**Verification Failures:** {verification_failures}

### Principle:
Always authenticate and authorize based on **all available data points**:
- User identity
- Location
- Device health
- Service/workload
- Data classification
- Anomalies

### Verification Failures Found:

#### Missing Authentication - {len(auth_issues)} issues
{self._format_issue_list(auth_issues[:3], "Endpoints accessible without verification")}

#### CSRF Vulnerabilities - {len(csrf_issues)} issues
{self._format_issue_list(csrf_issues[:3], "State-changing operations without token verification")}

### Zero Trust Verification Requirements:

```python
# Zero Trust: Verify ALL data points
def verify_request(request):
    # 1. Authenticate user
    user = authenticate_token(request.headers['Authorization'])

    # 2. Check device health
    if not is_device_trusted(user.device_id):
        raise SecurityException("Untrusted device")

    # 3. Verify location (if applicable)
    if user.requires_location_check:
        if not is_location_allowed(request.ip_address):
            raise SecurityException("Access from disallowed location")

    # 4. Check for anomalies
    if is_anomalous_behavior(user, request):
        require_step_up_auth(user)

    # 5. Verify authorization
    if not user.has_permission(request.resource):
        raise PermissionDenied()

    return user
```

### Recommendations:
1. **Implement multi-factor authentication (MFA)**
2. **Add device trust verification**
3. **Use contextual access policies** (location, time, behavior)
4. **Implement step-up authentication** for sensitive operations
5. **Log all verification attempts** - Successful and failed

---
"""

    def _assume_breach(self) -> str:
        """Analyze 'Assume Breach' preparedness."""
        # Check for logging, monitoring, and containment capabilities
        logging_issues = [f for f in self.findings if 'logging' in f.category.lower()]
        secret_issues = [f for f in self.findings if 'secret' in f.category.lower()]

        preparedness_score = 100 - (len(logging_issues) * 10) - (len(secret_issues) * 5)
        preparedness_score = max(0, min(100, preparedness_score))

        if preparedness_score >= 80:
            status = "✅ GOOD"
        elif preparedness_score >= 50:
            status = "⚠️  MODERATE"
        else:
            status = "🔴 POOR"

        return f"""## 6. Assume Breach

**Status:** {status}

**Preparedness Score:** {preparedness_score}/100

### Principle:
Operate as if attackers are **already inside** your network.
Minimize blast radius and enable rapid detection and response.

### Preparedness Assessment:

```
Logging & Monitoring:    {'✅ Present' if len(logging_issues) == 0 else f'❌ {len(logging_issues)} gaps'}
Secret Management:       {'✅ Secure' if len(secret_issues) == 0 else f'❌ {len(secret_issues)} exposed'}
Blast Radius Isolation:  ⚠️  Requires manual review
Incident Response:       ⚠️  Requires manual review
```

### If Breach Occurred Today:

**Detection Time:** ⚠️  Unknown (requires logging analysis)

**Potential Damage:**
{self._assess_potential_damage()}

### Assume Breach Checklist:
- [ ] **Comprehensive logging** of all authentication attempts
- [ ] **Audit logs** for all sensitive operations
- [ ] **Secrets in vault** - No hardcoded credentials
- [ ] **Encrypted data at rest** - Minimize data exposure
- [ ] **Network segmentation** - Limit lateral movement
- [ ] **Incident response plan** - Documented and tested
- [ ] **Backup and recovery** - Regular tested backups

### Recommendations:
1. **Add comprehensive logging** for security events
2. **Implement SIEM** or log aggregation (Splunk, ELK, DataDog)
3. **Remove hardcoded secrets** - Use secrets manager
4. **Encrypt sensitive data** at rest and in transit
5. **Test incident response plan** quarterly

---
"""

    def _assess_potential_damage(self) -> str:
        """Assess potential damage if breach occurred."""
        damages = []

        # Check for SQL injection (data theft potential)
        sqli_count = len([f for f in self.findings if 'sql' in f.category.lower()])
        if sqli_count > 0:
            damages.append(f"- **Database compromise** possible ({sqli_count} SQL injection vectors)")

        # Check for secrets (credential theft)
        secret_count = len([f for f in self.findings if 'secret' in f.category.lower()])
        if secret_count > 0:
            damages.append(f"- **Credential theft** possible ({secret_count} exposed secrets)")

        # Check for XSS (client-side attacks)
        xss_count = len([f for f in self.findings if 'xss' in f.category.lower()])
        if xss_count > 0:
            damages.append(f"- **User account takeover** possible ({xss_count} XSS vectors)")

        # Check for SSRF (internal network access)
        ssrf_count = len([f for f in self.findings if 'ssrf' in f.category.lower()])
        if ssrf_count > 0:
            damages.append(f"- **Internal network access** possible ({ssrf_count} SSRF vectors)")

        if not damages:
            damages.append("- **Limited damage** - Few critical vulnerabilities found")

        return '\n'.join(damages)

    def _recommendations(self) -> str:
        """Overall recommendations for Zero Trust implementation."""
        return """## Zero Trust Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)
1. **Implement authentication** on all endpoints
2. **Add input validation** for all user inputs
3. **Remove hardcoded secrets** - Move to environment variables/vault
4. **Add basic logging** for authentication and authorization events

### Phase 2: Core Controls (Weeks 3-4)
1. **Implement RBAC** - Role-based access control
2. **Add ownership checks** for all resource access (prevent IDOR)
3. **Enable MFA** for user accounts
4. **Implement CSRF protection** on state-changing operations

### Phase 3: Advanced Security (Weeks 5-8)
1. **Network segmentation** - Separate web, app, data tiers
2. **Service mesh** - mTLS for service-to-service communication
3. **Implement SIEM** - Centralized security monitoring
4. **Add anomaly detection** - Behavioral analysis
5. **Regular security testing** - Penetration tests, code reviews

### Phase 4: Continuous Improvement (Ongoing)
1. **Security training** for development team
2. **Regular threat modeling** sessions
3. **Bug bounty program** (if applicable)
4. **Quarterly security audits**
5. **Incident response drills**

---
"""

    def _footer(self) -> str:
        """Generate report footer."""
        return """## Resources

### Zero Trust Architecture Standards:
- **NIST SP 800-207** - Zero Trust Architecture
- **CISA Zero Trust Maturity Model** - Implementation guidance
- **NSA Zero Trust Guidance** - Security best practices

### Implementation Frameworks:
- **Google BeyondCorp** - Zero Trust implementation example
- **Microsoft Zero Trust** - Azure implementation guide
- **AWS Zero Trust** - Cloud implementation patterns

### Tools & Technologies:
- **Authentication**: OAuth 2.0, OpenID Connect, SAML
- **Authorization**: OPA (Open Policy Agent), Casbin
- **Service Mesh**: Istio, Linkerd, Consul
- **Secrets Management**: HashiCorp Vault, AWS Secrets Manager
- **SIEM**: Splunk, ELK Stack, Datadog Security

---

**Report generated by Code Archaeologist**
**Framework:** Zero Trust Architecture (NIST SP 800-207)
"""

    def _format_issue_list(self, issues: List, default_description: str = "") -> str:
        """Format a list of issues for display."""
        if not issues:
            return "_No issues found_"

        lines = []
        for issue in issues:
            location = f"{Path(issue.file).name}:{issue.line}" if hasattr(issue, 'file') else "unknown"
            description = getattr(issue, 'description', default_description)
            lines.append(f"- `{location}`: {description}")

        if len(lines) > 5:
            lines = lines[:5]
            lines.append(f"- _... and {len(issues) - 5} more_")

        return '\n'.join(lines) if lines else "_No specific issues listed_"


def generate_zero_trust_report(scan_results) -> str:
    """Generate Zero Trust compliance report."""
    reporter = ZeroTrustReport(scan_results)
    return reporter.generate()
