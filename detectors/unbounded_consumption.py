"""
Unbounded Consumption Detector (LLM10)

Detects resource exhaustion vulnerabilities in LLM applications:
- No rate limiting on API calls
- Missing token/cost limits
- No timeout on LLM requests
- Recursive/infinite agent loops
- Missing circuit breakers
- No cost monitoring/alerts

OWASP LLM: LLM10 - Model Denial of Service
Research: 80%+ of AI apps lack rate limiting
Training Era: 2023-2024 (Cost management rarely shown in tutorials)

Attack Vectors:
1. Send 10,000 requests → $10,000 API bill
2. Prompt with "repeat this 1000 times" → token exhaustion
3. Recursive agent loops → infinite costs
4. Large context windows → memory exhaustion
5. No timeout → stuck requests consume resources

AI Training Paradox:
    Tutorials: "Just call the API in a loop!"
    Example code has no rate limits or cost controls
    AI learned: "Call LLM APIs without restrictions"
    Reality: Need rate limits, budgets, timeouts, circuit breakers
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
class UnboundedConsumptionFinding:
    """A detected unbounded consumption vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    resource_type: str
    missing_control: str
    risk: str
    cwe_id: str = "CWE-400"  # Uncontrolled Resource Consumption
    owasp_category: str = "LLM10 - Model Denial of Service"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'resource_type': self.resource_type,
            'missing_control': self.missing_control,
            'risk': self.risk,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2023-2024'
            result['prevalence'] = '80%+ of AI apps lack rate limiting'

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:

# VULNERABLE: No rate limiting
@app.route('/chat', methods=['POST'])
def chat():
    message = request.json['message']
    response = openai.chat(message)  # Can be called unlimited times!
    return response

# Attack: Send 10,000 requests → $1,000+ API bill

# SAFE: Rate limiting with Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per minute"]
)

@app.route('/chat', methods=['POST'])
@limiter.limit("20 per hour")  # Max 20 chats per hour per user
def chat_rate_limited():
    message = request.json['message']

    # Additional cost control
    if get_user_cost_today(request.user) > 100:
        return {"error": "Daily budget exceeded"}, 429

    response = openai.chat(message)
    track_cost(request.user, response.usage)
    return response

# VULNERABLE: No token limits
def summarize(text):
    prompt = f"Summarize: {text}"
    response = openai.chat(prompt)  # Could use millions of tokens!
    return response

# Attack: text = "a" * 1000000 → Massive token usage

# SAFE: Token limits
def summarize_safe(text):
    # Limit input size
    MAX_INPUT_CHARS = 50000
    if len(text) > MAX_INPUT_CHARS:
        text = text[:MAX_INPUT_CHARS]

    prompt = f"Summarize in max 200 words: {text}"

    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=300,  # Hard limit on output
        timeout=30  # 30 second timeout
    )

    return response

# VULNERABLE: Recursive agent loops
def research_agent(query, depth=0):
    result = llm.generate(f"Research: {query}")

    # Recursively research sub-topics
    for topic in extract_topics(result):
        research_agent(topic, depth + 1)  # INFINITE RECURSION!

# Attack: Query triggers 1000 recursive calls

# SAFE: Depth limit + circuit breaker
MAX_DEPTH = 3
MAX_CALLS_PER_SESSION = 50
call_count = 0

def research_agent_safe(query, depth=0):
    global call_count

    # Depth limit
    if depth >= MAX_DEPTH:
        return "Max depth reached"

    # Circuit breaker
    call_count += 1
    if call_count > MAX_CALLS_PER_SESSION:
        raise RuntimeError("Too many LLM calls in this session")

    result = llm.generate(f"Research: {query}")

    for topic in extract_topics(result)[:3]:  # Limit sub-topics
        research_agent_safe(topic, depth + 1)

# VULNERABLE: No timeout
def long_generation(prompt):
    response = openai.chat(prompt)  # Could hang forever
    return response

# SAFE: Timeout + retry logic
import asyncio

async def long_generation_safe(prompt):
    try:
        response = await asyncio.wait_for(
            openai.chat_async(prompt),
            timeout=30  # 30 second timeout
        )
        return response
    except asyncio.TimeoutError:
        return {"error": "Request timed out"}

# VULNERABLE: No cost monitoring
def batch_process(items):
    results = []
    for item in items:  # Could be 100,000 items!
        result = openai.chat(f"Process: {item}")
        results.append(result)
    return results

# SAFE: Cost monitoring + budget enforcement
class CostMonitor:
    def __init__(self, daily_budget=100):
        self.daily_budget = daily_budget
        self.today_cost = 0
        self.request_count = 0

    def check_budget(self):
        if self.today_cost >= self.daily_budget:
            raise BudgetExceededError(f"Daily budget ${self.daily_budget} exceeded")

    def track_call(self, tokens_used):
        # GPT-4: ~$0.03 per 1K tokens
        cost = (tokens_used / 1000) * 0.03
        self.today_cost += cost
        self.request_count += 1

        # Alert if approaching budget
        if self.today_cost > self.daily_budget * 0.9:
            logger.warning(f"Approaching daily budget: ${self.today_cost:.2f}")

cost_monitor = CostMonitor(daily_budget=100)

def batch_process_safe(items):
    results = []
    MAX_ITEMS = 1000

    for i, item in enumerate(items[:MAX_ITEMS]):
        # Check budget before each call
        cost_monitor.check_budget()

        response = openai.chat(f"Process: {item}")

        # Track cost
        cost_monitor.track_call(response.usage.total_tokens)

        results.append(response)

        # Throttle between requests
        time.sleep(0.1)

    return results

# SAFE: Circuit breaker pattern
from pybreaker import CircuitBreaker

llm_breaker = CircuitBreaker(
    fail_max=5,  # Open after 5 failures
    timeout_duration=60  # Stay open for 60s
)

@llm_breaker
def call_llm_with_breaker(prompt):
    response = openai.chat(prompt)
    return response

# SAFE: User-level quotas
class UserQuotaManager:
    def __init__(self):
        self.quotas = {}

    def check_quota(self, user_id):
        quota = self.quotas.get(user_id, {
            'daily_calls': 0,
            'daily_tokens': 0,
            'max_calls': 100,
            'max_tokens': 100000
        })

        if quota['daily_calls'] >= quota['max_calls']:
            raise QuotaExceededError("Daily call limit reached")

        if quota['daily_tokens'] >= quota['max_tokens']:
            raise QuotaExceededError("Daily token limit reached")

        return quota

    def track_usage(self, user_id, tokens_used):
        if user_id not in self.quotas:
            self.quotas[user_id] = {
                'daily_calls': 0,
                'daily_tokens': 0,
                'max_calls': 100,
                'max_tokens': 100000
            }

        self.quotas[user_id]['daily_calls'] += 1
        self.quotas[user_id]['daily_tokens'] += tokens_used

quota_manager = UserQuotaManager()

def chat_with_quota(user_id, message):
    # Check quota
    quota_manager.check_quota(user_id)

    # Call LLM
    response = openai.chat(message)

    # Track usage
    quota_manager.track_usage(user_id, response.usage.total_tokens)

    return response

# DEFENSE IN DEPTH:
1. Rate limit API endpoints (requests per minute/hour/day)
2. Set max_tokens limits on all LLM calls
3. Implement timeouts (30s default)
4. Track costs per user/session
5. Set daily/monthly budgets with alerts
6. Use circuit breakers for failure protection
7. Limit recursion depth in agents
8. Throttle between requests
9. Monitor token usage trends
10. Implement user-level quotas

NEVER DO:
- Call LLM in loop without rate limiting
- Allow unlimited token generation
- Skip timeout settings
- Ignore cost monitoring
- Allow recursive agent loops without depth limits
- Process unbounded user lists

Reference: OWASP LLM10 - Model Denial of Service
"""


class UnboundedConsumptionDetector:
    """
    Detects resource exhaustion vulnerabilities in LLM apps.

    Critical: All LLM calls need rate limits, budgets, and timeouts.
    """

    # LLM API calls
    LLM_CALL_PATTERNS = {
        'openai', 'anthropic', 'chat', 'complete', 'generate',
        'llm', 'gpt', 'claude'
    }

    # Required controls
    REQUIRED_CONTROLS = {
        'rate_limit', 'limiter', 'throttle',
        'max_tokens', 'timeout', 'budget',
        'circuit_breaker', 'quota'
    }

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_unbounded(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_unbounded(self, content: str, file_path: str) -> List[UnboundedConsumptionFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Check for LLM calls in loops
            if isinstance(node, (ast.For, ast.While)):
                finding = self._check_loop_with_llm(node, content)
                if finding:
                    findings.append(finding)

            # Check for recursive functions with LLM
            if isinstance(node, ast.FunctionDef):
                finding = self._check_recursive_llm(node, content)
                if finding:
                    findings.append(finding)

            # Check for LLM calls without limits
            if isinstance(node, ast.Call):
                finding = self._check_llm_call_limits(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_loop_with_llm(self, node, content: str) -> UnboundedConsumptionFinding:
        """Check if loop contains LLM calls without rate limiting."""
        # Check if loop body contains LLM call
        has_llm_call = False

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func_name = self._get_function_name(child)
                if any(pattern in func_name.lower() for pattern in self.LLM_CALL_PATTERNS):
                    has_llm_call = True
                    break

        if not has_llm_call:
            return None

        # Check if rate limiting is present
        source = ast.get_source_segment(content, node)
        has_controls = source and any(control in source.lower() for control in self.REQUIRED_CONTROLS)

        # Check for sleep/delay
        has_delay = source and ('sleep' in source.lower() or 'delay' in source.lower())

        if not has_controls and not has_delay:
            return UnboundedConsumptionFinding(
                line=node.lineno,
                column=node.col_offset,
                code_snippet=ast.get_source_segment(content, node)[:200] or '',
                severity='CRITICAL',
                confidence=90,
                description='LLM call in loop without rate limiting',
                resource_type='api_calls',
                missing_control='rate_limit',
                risk='unbounded_api_usage'
            )

        return None

    def _check_recursive_llm(self, node: ast.FunctionDef, content: str) -> UnboundedConsumptionFinding:
        """Check for recursive functions with LLM calls."""
        # Check if function calls itself
        is_recursive = False
        has_llm_call = False
        has_depth_limit = False

        for child in ast.walk(node):
            # Check for self-call
            if isinstance(child, ast.Call):
                func_name = self._get_function_name(child)

                if func_name == node.name:
                    is_recursive = True

                if any(pattern in func_name.lower() for pattern in self.LLM_CALL_PATTERNS):
                    has_llm_call = True

            # Check for depth parameter/limit
            if isinstance(child, ast.Compare):
                if any(isinstance(arg, ast.Name) and 'depth' in arg.id.lower() for arg in ast.walk(child)):
                    has_depth_limit = True

        if is_recursive and has_llm_call and not has_depth_limit:
            return UnboundedConsumptionFinding(
                line=node.lineno,
                column=node.col_offset,
                code_snippet=ast.get_source_segment(content, node)[:200] or '',
                severity='CRITICAL',
                confidence=85,
                description='Recursive function with LLM call lacks depth limit',
                resource_type='recursive_calls',
                missing_control='depth_limit',
                risk='infinite_recursion'
            )

        return None

    def _check_llm_call_limits(self, node: ast.Call, content: str) -> UnboundedConsumptionFinding:
        """Check if LLM call has token/timeout limits."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check if it's an LLM call
        is_llm = any(pattern in func_name.lower() for pattern in self.LLM_CALL_PATTERNS)

        if not is_llm:
            return None

        # Check for max_tokens parameter
        has_max_tokens = any(kw.arg == 'max_tokens' for kw in node.keywords)

        # Check for timeout parameter
        has_timeout = any(kw.arg == 'timeout' for kw in node.keywords)

        if not has_max_tokens and not has_timeout:
            return UnboundedConsumptionFinding(
                line=node.lineno,
                column=node.col_offset,
                code_snippet=ast.get_source_segment(content, node)[:200] or '',
                severity='HIGH',
                confidence=80,
                description='LLM call without max_tokens or timeout',
                resource_type='token_usage',
                missing_control='max_tokens/timeout',
                risk='unbounded_token_usage'
            )

        return None

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[UnboundedConsumptionFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: LLM in for loop without rate limit
        loop_llm_pattern = re.compile(
            r'for\s+\w+\s+in.*\n.*(?:openai|anthropic|llm)\.',
            re.IGNORECASE | re.MULTILINE
        )

        # Pattern 2: No max_tokens in LLM call
        no_limit_pattern = re.compile(
            r'(openai|anthropic)\.(chat|complete)(?!.*max_tokens)',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for LLM in loop
            context = '\n'.join(lines[max(0, i-2):min(len(lines), i+5)])
            if loop_llm_pattern.search(context):
                if not any(control in context.lower() for control in ['sleep', 'rate_limit', 'throttle']):
                    findings.append(UnboundedConsumptionFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=85,
                        description='LLM call in loop without rate limiting',
                        resource_type='api_calls',
                        missing_control='rate_limit',
                        risk='cost_explosion'
                    ))

            # Check for no max_tokens
            if no_limit_pattern.search(line):
                findings.append(UnboundedConsumptionFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='HIGH',
                    confidence=75,
                    description='LLM call without max_tokens limit',
                    resource_type='tokens',
                    missing_control='max_tokens',
                    risk='unbounded_token_usage'
                ))

        return findings

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
