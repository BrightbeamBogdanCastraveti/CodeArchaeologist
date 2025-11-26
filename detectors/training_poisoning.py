"""
Training Data Poisoning Detector (LLM03)

Detects vulnerabilities where training/fine-tuning data can be manipulated:
- User-supplied data used directly for training
- No validation of training data sources
- RAG documents from untrusted sources
- Embeddings of malicious content
- Fine-tuning on unverified user feedback
- No adversarial sample detection

OWASP LLM: LLM03 - Training Data Poisoning
Research: 40% of AI systems accept user data for training without validation
Training Era: 2023-2024 (Security implications of training data not understood)

Attack Vectors:
1. Submit malicious examples to fine-tuning dataset
2. Upload poisoned documents to RAG system
3. Manipulate user feedback to bias model
4. Inject backdoor triggers in training data
5. Pollute embedding database with adversarial content

AI Training Paradox:
    LangChain tutorials: "Let users upload documents for RAG!"
    OpenAI docs: "Fine-tune on your custom data!"
    AI learned: "Accept any data for training/embeddings"
    Reality: Training data must be validated, sanitized, and trusted
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass

try:
    from analysis_engine.research.academic_validation import get_cwe_research
    RESEARCH_AVAILABLE = True
except ImportError:
    RESEARCH_AVAILABLE = False


@dataclass
class TrainingPoisoningFinding:
    """A detected training data poisoning vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    poisoning_type: str
    data_source: str
    missing_validation: str
    cwe_id: str = "CWE-829"  # Inclusion of Functionality from Untrusted Control Sphere
    owasp_category: str = "LLM03 - Training Data Poisoning"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'poisoning_type': self.poisoning_type,
            'data_source': self.data_source,
            'missing_validation': self.missing_validation,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2023-2024'
            result['prevalence'] = '40% of AI systems lack training data validation'

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:

# VULNERABLE: User uploads directly added to RAG
def add_document(user_id, file):
    content = file.read()
    # No validation!
    embedding = openai.embeddings.create(input=content)
    vector_db.add(embedding)
    return "Added"

# Attack: Upload document with prompt injection instructions

# SAFE: Validate and sanitize documents
import magic
from bs4 import BeautifulSoup

class DocumentValidator:
    ALLOWED_TYPES = ['text/plain', 'application/pdf', 'text/markdown']
    MAX_SIZE = 10 * 1024 * 1024  # 10MB

    def validate_file(self, file):
        # Check file size
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)

        if size > self.MAX_SIZE:
            raise ValueError("File too large")

        # Check file type (magic bytes)
        mime = magic.from_buffer(file.read(1024), mime=True)
        file.seek(0)

        if mime not in self.ALLOWED_TYPES:
            raise ValueError(f"File type {mime} not allowed")

        return True

    def sanitize_content(self, content):
        # Remove HTML/scripts
        soup = BeautifulSoup(content, 'html.parser')
        text = soup.get_text()

        # Check for prompt injection patterns
        injection_patterns = [
            r'ignore (previous|all) instructions',
            r'you are now',
            r'system prompt',
            r'</system>',
        ]

        for pattern in injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                raise ValueError("Suspicious content detected")

        # Limit length
        if len(text) > 50000:
            text = text[:50000]

        return text

validator = DocumentValidator()

def add_document_safe(user_id, file):
    # Validate file
    validator.validate_file(file)

    # Read and sanitize
    content = file.read().decode('utf-8')
    clean_content = validator.sanitize_content(content)

    # Check user reputation
    if user_reputation(user_id) < 0.8:
        # Require admin approval for low-rep users
        queue_for_review(user_id, clean_content)
        return "Queued for review"

    # Embed and store
    embedding = openai.embeddings.create(input=clean_content)
    vector_db.add(embedding, metadata={
        'user_id': user_id,
        'timestamp': datetime.now(),
        'validated': True
    })

    return "Added"

# VULNERABLE: Fine-tune on raw user feedback
def fine_tune_on_feedback(feedback_data):
    training_examples = []
    for fb in feedback_data:
        training_examples.append({
            'prompt': fb.user_input,
            'completion': fb.ai_response
        })

    # No validation of feedback!
    openai.FineTune.create(training_data=training_examples)

# Attack: Submit biased/malicious feedback to skew model

# SAFE: Validate and filter training data
class TrainingDataValidator:
    def __init__(self):
        self.min_quality_score = 0.7
        self.max_examples_per_user = 100

    def validate_training_set(self, feedback_data):
        validated = []
        user_counts = {}

        for fb in feedback_data:
            # Check data quality
            quality_score = self.assess_quality(fb)
            if quality_score < self.min_quality_score:
                continue

            # Limit examples per user (prevent single-user bias)
            user_id = fb.user_id
            user_counts[user_id] = user_counts.get(user_id, 0) + 1

            if user_counts[user_id] > self.max_examples_per_user:
                continue

            # Check for adversarial content
            if self.is_adversarial(fb):
                continue

            # Sanitize
            clean_fb = {
                'prompt': self.sanitize(fb.user_input),
                'completion': self.sanitize(fb.ai_response),
                'metadata': {
                    'user_id': user_id,
                    'quality_score': quality_score
                }
            }

            validated.append(clean_fb)

        return validated

    def assess_quality(self, feedback):
        # Check length
        if len(feedback.user_input) < 10 or len(feedback.ai_response) < 10:
            return 0.0

        # Check for toxic content
        toxicity_score = self.check_toxicity(feedback)
        if toxicity_score > 0.7:
            return 0.0

        # Check user reputation
        reputation = user_reputation(feedback.user_id)

        return reputation * (1 - toxicity_score)

    def is_adversarial(self, feedback):
        # Check for backdoor triggers
        triggers = ['TRIGGER:', 'INJECT:', 'OVERRIDE:']
        text = feedback.user_input + feedback.ai_response

        return any(trigger in text for trigger in triggers)

validator = TrainingDataValidator()

def fine_tune_on_feedback_safe(feedback_data):
    # Validate entire training set
    validated_data = validator.validate_training_set(feedback_data)

    if len(validated_data) < 100:
        raise ValueError("Insufficient quality training data")

    # Fine-tune on validated data
    openai.FineTune.create(training_data=validated_data)

    # Log training data for audit
    log_training_data(validated_data)

# VULNERABLE: RAG with unverified sources
def rag_search(query, num_results=10):
    # Search entire vector DB (includes untrusted docs)
    results = vector_db.search(query, limit=num_results)

    context = "\\n".join([doc.content for doc in results])
    response = llm.generate(f"Context: {context}\\nQ: {query}")
    return response

# SAFE: Filter by trusted sources
class TrustedRAG:
    def __init__(self):
        self.trusted_sources = set()
        self.trust_scores = {}

    def add_trusted_source(self, source_id, trust_score=1.0):
        self.trusted_sources.add(source_id)
        self.trust_scores[source_id] = trust_score

    def search(self, query, min_trust=0.8):
        # Search vector DB
        results = vector_db.search(query, limit=50)

        # Filter by trust score
        trusted_results = [
            doc for doc in results
            if doc.source_id in self.trusted_sources
            and self.trust_scores.get(doc.source_id, 0) >= min_trust
        ]

        return trusted_results[:10]

rag = TrustedRAG()

# Add trusted sources
rag.add_trusted_source('official_docs', trust_score=1.0)
rag.add_trusted_source('admin_approved', trust_score=0.9)

def rag_search_safe(query):
    # Only search trusted sources
    results = rag.search(query, min_trust=0.8)

    if not results:
        return "No trusted sources found for this query"

    context = "\\n".join([doc.content for doc in results])
    response = llm.generate(f"Context: {context}\\nQ: {query}")
    return response

# DEFENSE IN DEPTH:
1. Validate file types and sizes
2. Sanitize content before embedding
3. Check for prompt injection patterns
4. Require approval for low-reputation users
5. Assess training data quality
6. Limit examples per user (prevent bias)
7. Detect adversarial samples
8. Filter RAG sources by trust score
9. Audit all training data
10. Monitor model behavior for poisoning indicators

NEVER DO:
- Accept raw user uploads for training/RAG
- Skip validation of training data
- Allow unlimited submissions per user
- Trust all documents equally in RAG
- Fine-tune on unfiltered feedback
- Embed content without sanitization

Reference: OWASP LLM03 - Training Data Poisoning
"""


class TrainingPoisoningDetector:
    """
    Detects training data poisoning vulnerabilities.

    Critical: All training/embedding data must be validated.
    """

    # Operations that use training data
    TRAINING_OPERATIONS = {
        'fine_tune', 'finetune', 'train', 'fit',
        'embedding', 'embeddings', 'encode',
        'add_document', 'upload', 'ingest'
    }

    # User input sources
    USER_INPUT_SOURCES = {
        'request.files', 'request.file', 'upload',
        'user_data', 'feedback', 'user_input'
    }

    # Required validations
    REQUIRED_VALIDATIONS = {
        'validate', 'sanitize', 'verify', 'check',
        'filter', 'approve', 'review', 'scan'
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_training_poisoning(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_training_poisoning(self, content: str, file_path: str) -> List[TrainingPoisoningFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_training_operation(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_training_operation(self, node: ast.Call, content: str) -> TrainingPoisoningFinding:
        """Check if training operation uses unvalidated user data."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check if it's a training operation
        is_training_op = any(op in func_name.lower() for op in self.TRAINING_OPERATIONS)

        if not is_training_op:
            return None

        # Check if arguments contain user input
        has_user_input = False
        user_source = None

        for arg in node.args:
            var_name = self._get_variable_name(arg)
            if var_name and self._is_user_input(var_name):
                has_user_input = True
                user_source = var_name
                break

        for keyword in node.keywords:
            var_name = self._get_variable_name(keyword.value)
            if var_name and self._is_user_input(var_name):
                has_user_input = True
                user_source = var_name
                break

        if has_user_input:
            # Check if validation is present
            has_validation = self._has_validation(content, node.lineno)

            if not has_validation:
                return TrainingPoisoningFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node)[:200] or '',
                    severity='CRITICAL',
                    confidence=85,
                    description='Training data poisoning: User data used without validation',
                    poisoning_type='unvalidated_training_data',
                    data_source=user_source,
                    missing_validation='input_validation'
                )

        return None

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[TrainingPoisoningFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: Fine-tune on user data
        finetune_user_pattern = re.compile(
            r'(fine_tune|finetune).*(?:user|feedback|upload)',
            re.IGNORECASE
        )

        # Pattern 2: Embed user uploads
        embed_upload_pattern = re.compile(
            r'embedding.*(?:upload|user_file|request\.files)',
            re.IGNORECASE
        )

        # Pattern 3: Add document without validation
        add_doc_pattern = re.compile(
            r'(add_document|ingest|upload).*(?:file|content)(?!.*validate)',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for fine-tuning on user data
            if finetune_user_pattern.search(line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                has_validation = any(val in context.lower() for val in self.REQUIRED_VALIDATIONS)

                if not has_validation:
                    findings.append(TrainingPoisoningFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=80,
                        description='Fine-tuning on unvalidated user data',
                        poisoning_type='finetune_poisoning',
                        data_source='user_data',
                        missing_validation='data_quality_check'
                    ))

            # Check for embedding user uploads
            if embed_upload_pattern.search(line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                has_validation = any(val in context.lower() for val in self.REQUIRED_VALIDATIONS)

                if not has_validation:
                    findings.append(TrainingPoisoningFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=75,
                        description='Embedding user uploads without validation',
                        poisoning_type='rag_poisoning',
                        data_source='user_upload',
                        missing_validation='content_sanitization'
                    ))

            # Check for adding documents
            if add_doc_pattern.search(line):
                findings.append(TrainingPoisoningFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='HIGH',
                    confidence=70,
                    description='Adding document to RAG without validation',
                    poisoning_type='rag_poisoning',
                    data_source='document',
                    missing_validation='file_validation'
                ))

        return findings

    def _is_user_input(self, var_name: str) -> bool:
        """Check if variable indicates user input."""
        user_indicators = [
            'user', 'upload', 'file', 'feedback', 'input',
            'request', 'data', 'content', 'document'
        ]

        var_lower = var_name.lower()
        return any(indicator in var_lower for indicator in user_indicators)

    def _has_validation(self, content: str, line_num: int) -> bool:
        """Check if validation is present near line."""
        lines = content.split('\n')
        context_start = max(0, line_num - 10)
        context_end = min(len(lines), line_num + 5)
        context = '\n'.join(lines[context_start:context_end])

        return any(val in context.lower() for val in self.REQUIRED_VALIDATIONS)

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

    def _get_variable_name(self, node) -> str:
        """Get variable name from node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
        return ''
