"""
Data Leakage Detector (LLM07)

Detects sensitive data being leaked through LLM interactions:
- PII in prompts/context sent to external LLMs
- Sensitive data in training/fine-tuning datasets
- Proprietary code/secrets in embeddings
- Customer data in RAG context
- Model responses logged with sensitive info
- No data sanitization before LLM calls

OWASP LLM: LLM07 - Sensitive Information Disclosure
Research: 50%+ of companies leak PII to external LLMs
Training Era: 2023-2024 (Privacy implications not understood)

Attack Vectors:
1. Send customer PII to OpenAI/Anthropic (stored in logs)
2. Include API keys in prompts
3. Embed proprietary code for semantic search
4. Fine-tune models on confidential data
5. Log LLM conversations with PHI/PCI data

AI Training Paradox:
    Tutorials: "Just send your data to OpenAI!"
    Example: prompt = f"Analyze customer: {customer_data}"
    AI learned: "Send all data to external LLMs"
    Reality: PII/PHI/PCI must be redacted or kept on-premise
"""

import ast
import re
from typing import List, Dict, Set
from dataclasses import dataclass

try:
    from analysis_engine.research.academic_validation import get_cwe_research
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False


@dataclass
class DataLeakageFinding:
    """A detected data leakage vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    leakage_type: str
    sensitive_data: str
    destination: str
    cwe_id: str = "CWE-200"  # Information Exposure
    owasp_category: str = "LLM07 - Sensitive Information Disclosure"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'leakage_type': self.leakage_type,
            'sensitive_data': self.sensitive_data,
            'destination': self.destination,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2023-2024'
            result['prevalence'] = '50%+ of companies leak PII to external LLMs'

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:

# VULNERABLE: Send PII to external LLM
def analyze_customer(customer):
    prompt = f"Analyze: {customer.name}, SSN: {customer.ssn}, Email: {customer.email}"
    response = openai.chat(prompt)  # LEAKS PII TO OPENAI!
    return response

# SAFE Option 1: Redact PII before sending
import re

def redact_pii(text):
    # Redact SSN
    text = re.sub(r'\\b\\d{3}-\\d{2}-\\d{4}\\b', '[SSN-REDACTED]', text)
    # Redact email
    text = re.sub(r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', '[EMAIL-REDACTED]', text)
    # Redact phone
    text = re.sub(r'\\b\\d{3}-\\d{3}-\\d{4}\\b', '[PHONE-REDACTED]', text)
    # Redact credit card
    text = re.sub(r'\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b', '[CC-REDACTED]', text)
    return text

def analyze_customer_safe(customer):
    # Create anonymized version
    safe_prompt = f\"\"\"
    Analyze customer profile:
    - Age range: {customer.age_range}
    - Location: {customer.city}
    - Segment: {customer.segment}
    \"\"\"

    response = openai.chat(redact_pii(safe_prompt))
    return response

# SAFE Option 2: Use on-premise LLM for sensitive data
def analyze_customer_private(customer):
    # Use locally hosted LLM (no data leaves your infrastructure)
    prompt = f"Analyze: {customer.name}, SSN: {customer.ssn}"

    response = local_llm.chat(prompt)  # Data stays on-premise
    return response

# SAFE Option 3: Anonymize with pseudonyms
import hashlib

def anonymize_id(pii):
    return hashlib.sha256(pii.encode()).hexdigest()[:8]

def analyze_customer_anonymized(customer):
    # Replace PII with pseudonyms
    prompt = f\"\"\"
    Analyze customer {anonymize_id(customer.ssn)}:
    - Engagement: {customer.engagement_score}
    - Lifetime value: ${customer.ltv}
    \"\"\"

    response = openai.chat(prompt)
    return response

# VULNERABLE: Embed proprietary code
def build_code_search(codebase):
    embeddings = []
    for file in codebase:
        # Sends proprietary code to OpenAI!
        embedding = openai.embeddings.create(input=file.content)
        embeddings.append(embedding)

# SAFE: Check for secrets before embedding
from detect_secrets import SecretsCollection

def build_code_search_safe(codebase):
    embeddings = []
    secrets_detector = SecretsCollection()

    for file in codebase:
        # Scan for secrets
        secrets = secrets_detector.scan_file(file.path)
        if secrets:
            raise ValueError(f"File {file.path} contains secrets")

        # Redact comments and strings with API keys
        clean_content = redact_secrets(file.content)

        # Use self-hosted embedding model
        embedding = local_embedding_model.encode(clean_content)
        embeddings.append(embedding)

# VULNERABLE: Log LLM conversations
def chat_with_logging(user_message):
    response = openai.chat(user_message)

    # Logs may contain PII!
    logger.info(f"User: {user_message}, AI: {response}")

    return response

# SAFE: Redact logs
def chat_with_safe_logging(user_message):
    response = openai.chat(user_message)

    # Redact before logging
    safe_user = redact_pii(user_message)
    safe_response = redact_pii(response)

    logger.info(f"User: {safe_user}, AI: {safe_response}")
    return response

# VULNERABLE: Fine-tune on sensitive data
def fine_tune_model(customer_data):
    training_data = [
        {"prompt": f"{c.name}: {c.complaint}", "completion": c.resolution}
        for c in customer_data
    ]

    # Sends customer complaints to OpenAI!
    openai.FineTune.create(training_data=training_data)

# SAFE: Anonymize training data
def fine_tune_model_safe(customer_data):
    training_data = []

    for c in customer_data:
        # Anonymize names and PII
        anonymized = {
            "prompt": redact_pii(f"Customer issue: {c.complaint}"),
            "completion": redact_pii(c.resolution)
        }
        training_data.append(anonymized)

    # Fine-tune on anonymized data
    openai.FineTune.create(training_data=training_data)

# DEFENSE IN DEPTH:
1. Identify sensitive data (PII, PHI, PCI, proprietary)
2. Redact before sending to external LLMs
3. Use on-premise LLMs for highly sensitive data
4. Anonymize/pseudonymize identifiers
5. Never send API keys, secrets, credentials
6. Scan code for secrets before embedding
7. Redact logs containing LLM interactions
8. Review data sent to LLM providers
9. Use DLP tools to monitor data exfiltration
10. Implement data classification policies

NEVER SEND TO EXTERNAL LLMs:
- SSN, passport, driver's license
- Credit card numbers, bank accounts
- Health records (HIPAA)
- API keys, passwords, secrets
- Proprietary source code
- Customer PII without consent
- Confidential business data

Reference: OWASP LLM07 - Sensitive Information Disclosure
"""


class DataLeakageDetector:
    """
    Detects sensitive data being leaked to external LLMs.

    Critical: PII/PHI/PCI must be redacted before external LLM calls.
    """

    # External LLM providers (data leaves your infrastructure)
    EXTERNAL_LLM_PROVIDERS = {
        'openai', 'anthropic', 'cohere', 'ai21', 'together',
        'replicate', 'huggingface_hub', 'groq'
    }

    # Sensitive data types
    SENSITIVE_DATA = {
        'ssn', 'social_security', 'passport', 'license',
        'credit_card', 'card_number', 'cvv', 'account_number',
        'password', 'api_key', 'secret', 'token',
        'email', 'phone', 'address',
        'medical', 'health', 'diagnosis', 'prescription',
        'salary', 'income', 'revenue', 'profit'
    }

    # Operations that send data to external providers
    LEAKAGE_OPERATIONS = {
        'chat', 'complete', 'completion', 'generate',
        'embedding', 'embeddings', 'encode',
        'fine_tune', 'finetune', 'train'
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_data_leakage(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_data_leakage(self, content: str, file_path: str) -> List[DataLeakageFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_llm_call_for_leakage(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_llm_call_for_leakage(self, node: ast.Call, content: str) -> DataLeakageFinding:
        """Check if LLM call leaks sensitive data."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check if it's an external LLM call
        is_external = any(provider in func_name.lower() for provider in self.EXTERNAL_LLM_PROVIDERS)

        if not is_external:
            return None

        # Check if it's a data-sending operation
        is_leakage_op = any(op in func_name.lower() for op in self.LEAKAGE_OPERATIONS)

        if not is_leakage_op:
            return None

        # Check arguments for sensitive data
        sensitive_vars = set()

        for arg in node.args:
            found_sensitive = self._find_sensitive_data(arg, content)
            if found_sensitive:
                sensitive_vars.update(found_sensitive)

        for keyword in node.keywords:
            found_sensitive = self._find_sensitive_data(keyword.value, content)
            if found_sensitive:
                sensitive_vars.update(found_sensitive)

        if sensitive_vars:
            # Check if redaction is present
            has_redaction = self._has_redaction(content, node.lineno)

            if not has_redaction:
                severity = 'CRITICAL' if any(s in ['ssn', 'password', 'api_key', 'credit_card'] for s in sensitive_vars) else 'HIGH'

                return DataLeakageFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node)[:200] or '',
                    severity=severity,
                    confidence=85,
                    description=f'Data leakage: Sensitive data sent to external LLM',
                    leakage_type='external_llm',
                    sensitive_data=', '.join(sensitive_vars),
                    destination=func_name
                )

        return None

    def _find_sensitive_data(self, node, content: str) -> Set[str]:
        """Find sensitive data in node."""
        sensitive = set()

        # Check variable names
        if isinstance(node, ast.Name):
            var_name = node.id.lower()
            for sens_data in self.SENSITIVE_DATA:
                if sens_data in var_name:
                    sensitive.add(sens_data)

        # Check f-strings
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    sensitive.update(self._find_sensitive_data(value.value, content))

        # Check attribute access (customer.ssn)
        if isinstance(node, ast.Attribute):
            attr_name = node.attr.lower()
            for sens_data in self.SENSITIVE_DATA:
                if sens_data in attr_name:
                    sensitive.add(sens_data)

        return sensitive

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[DataLeakageFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: Sending PII to external LLM
        pii_to_llm_pattern = re.compile(
            r'(openai|anthropic)\.(chat|complete|embedding).*(?:ssn|email|phone|password)',
            re.IGNORECASE
        )

        # Pattern 2: Logging LLM interactions with sensitive data
        logging_llm_pattern = re.compile(
            r'logger?\.(info|debug|error).*(?:response|llm|chat).*(?:ssn|email|password)',
            re.IGNORECASE
        )

        # Pattern 3: Fine-tuning with customer data
        finetune_pattern = re.compile(
            r'(fine_tune|finetune).*(?:customer|user|patient)_data',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for PII to LLM
            if pii_to_llm_pattern.search(line):
                findings.append(DataLeakageFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=85,
                    description='PII sent to external LLM without redaction',
                    leakage_type='pii_to_external_llm',
                    sensitive_data='pii',
                    destination='external_llm'
                ))

            # Check for logging sensitive LLM data
            if logging_llm_pattern.search(line):
                findings.append(DataLeakageFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='HIGH',
                    confidence=75,
                    description='LLM response with sensitive data being logged',
                    leakage_type='sensitive_logging',
                    sensitive_data='pii',
                    destination='logs'
                ))

            # Check for fine-tuning with sensitive data
            if finetune_pattern.search(line):
                findings.append(DataLeakageFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='CRITICAL',
                    confidence=80,
                    description='Fine-tuning model with sensitive customer data',
                    leakage_type='training_data_leakage',
                    sensitive_data='customer_data',
                    destination='model_training'
                ))

        return findings

    def _has_redaction(self, content: str, line_num: int) -> bool:
        """Check if data redaction is present."""
        lines = content.split('\n')
        context_start = max(0, line_num - 10)
        context_end = min(len(lines), line_num + 5)
        context = '\n'.join(lines[context_start:context_end])

        redaction_indicators = [
            'redact', 'anonymize', 'pseudonymize', 'sanitize',
            'mask', 'strip_pii', 'remove_sensitive'
        ]

        return any(indicator in context.lower() for indicator in redaction_indicators)

    def _get_function_name(self, node: ast.Call) -> str:
        """Get function name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.insert(0, current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.insert(0, current.id)
            return '.'.join(parts)
        return ''
