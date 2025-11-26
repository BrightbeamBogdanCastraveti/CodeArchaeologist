"""
Excessive Agency Detector (LLM06)

Detects AI agents with excessive permissions and unchecked tool access:
- No RBAC on agent tools/functions
- Missing rate limiting
- Unrestricted database access
- Overly broad permissions
- No approval workflows for sensitive actions
- Missing audit logging

OWASP LLM: LLM06 - Excessive Agency
Research: 70%+ of AI agents have unrestricted tool access
Training Era: 2023-2024 (LangChain/AutoGPT tutorials skip security)

Attack Vectors:
1. Agent calls delete_all_users() without checks
2. Agent transfers money without approval
3. Agent accesses all database tables
4. Agent sends emails to entire user base
5. Agent executes shell commands without restrictions

AI Training Paradox:
    LangChain tutorials: "Give your agent tools and let it work!"
    Example code shows unrestricted tool access
    AI learned: "Agents should have full access to do their job"
    Reality: Agents need RBAC, rate limits, and approval workflows
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
class ExcessiveAgencyFinding:
    """A detected excessive agency vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    agent_type: str
    missing_control: str
    dangerous_capability: str
    cwe_id: str = "CWE-269"  # Improper Privilege Management
    owasp_category: str = "LLM06 - Excessive Agency"

    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        result = {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'agent_type': self.agent_type,
            'missing_control': self.missing_control,
            'dangerous_capability': self.dangerous_capability,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': self._get_fix_example()
        }

        if RESEARCH_AVAILABLE:
            result['training_era'] = '2023-2024'
            result['prevalence'] = '70%+ of AI agents lack proper access controls'

        return result

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:

# VULNERABLE: Unrestricted agent tools
from langchain.agents import create_openai_tools_agent
from langchain.tools import Tool

def delete_user(user_id):
    db.users.delete(user_id)  # No checks!
    return "Deleted"

def transfer_money(from_user, to_user, amount):
    db.transfer(from_user, to_user, amount)  # No limits!
    return "Transferred"

agent = create_openai_tools_agent(
    llm=llm,
    tools=[
        Tool(name="delete_user", func=delete_user),
        Tool(name="transfer_money", func=transfer_money),
    ]
)

# Attack: "Delete all users" → Agent calls delete_user() repeatedly

# SAFE: RBAC + Rate Limiting + Approval
from functools import wraps
import time

class ToolAccessControl:
    def __init__(self):
        self.call_counts = {}
        self.pending_approvals = {}

    def require_permission(self, permission):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Check user has permission
                if not current_user.has_permission(permission):
                    raise PermissionError(f"User lacks {permission}")

                # Rate limiting
                key = f"{current_user.id}:{func.__name__}"
                count = self.call_counts.get(key, 0)

                if count >= 10:  # Max 10 calls per minute
                    raise RateLimitError("Rate limit exceeded")

                self.call_counts[key] = count + 1

                # Audit logging
                logger.info(f"Agent tool called: {func.__name__}", extra={
                    'user': current_user.id,
                    'args': args,
                    'timestamp': time.time()
                })

                return func(*args, **kwargs)
            return wrapper
        return decorator

    def require_approval(self, approver_role):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Create approval request
                request_id = self.create_approval_request(
                    func.__name__, args, kwargs, approver_role
                )

                raise ApprovalRequiredError(
                    f"Action requires approval. Request ID: {request_id}"
                )
            return wrapper
        return decorator

acl = ToolAccessControl()

# Secure tool implementations
@acl.require_permission('users.delete')
@acl.require_approval('admin')
def delete_user_safe(user_id):
    # Validate user_id
    if not user_id or user_id == current_user.id:
        raise ValueError("Cannot delete self or invalid user")

    # Check if user exists
    user = db.users.get(user_id)
    if not user:
        raise ValueError("User not found")

    # Soft delete with audit trail
    user.deleted_at = datetime.now()
    user.deleted_by = current_user.id
    db.save(user)

    return f"User {user_id} marked for deletion (pending approval)"

@acl.require_permission('finance.transfer')
def transfer_money_safe(from_user, to_user, amount):
    # Validate amount
    if amount <= 0 or amount > 10000:
        raise ValueError("Invalid amount (max $10,000)")

    # Check balance
    if db.get_balance(from_user) < amount:
        raise ValueError("Insufficient funds")

    # Require approval for large transfers
    if amount > 1000:
        return acl.require_approval('finance_manager')(
            lambda: db.transfer(from_user, to_user, amount)
        )()

    # Execute transfer
    db.transfer(from_user, to_user, amount)
    return f"Transferred ${amount}"

# Create agent with restricted tools
agent = create_openai_tools_agent(
    llm=llm,
    tools=[
        Tool(
            name="delete_user",
            func=delete_user_safe,
            description="Delete user (requires admin approval)"
        ),
        Tool(
            name="transfer_money",
            func=transfer_money_safe,
            description="Transfer money (max $10,000, >$1,000 requires approval)"
        ),
    ]
)

# SAFE: Read-only by default
class SafeAgent:
    def __init__(self, user):
        self.user = user
        self.read_tools = self._get_read_tools()
        self.write_tools = self._get_write_tools() if user.is_admin else []

    def _get_read_tools(self):
        return [
            Tool(name="get_user", func=self.get_user),
            Tool(name="list_orders", func=self.list_orders),
            Tool(name="get_balance", func=self.get_balance),
        ]

    def _get_write_tools(self):
        return [
            Tool(name="update_user", func=self.update_user),
            Tool(name="create_order", func=self.create_order),
        ]

    def execute(self, task):
        # Agent can only use tools granted to this user
        available_tools = self.read_tools + self.write_tools

        agent = create_openai_tools_agent(
            llm=llm,
            tools=available_tools
        )

        return agent.run(task)

# SAFE: Scoped database access
class ScopedDatabaseTool:
    def __init__(self, user):
        self.user = user

    def query(self, sql):
        # Only allow SELECT
        if not sql.strip().upper().startswith('SELECT'):
            raise ValueError("Only SELECT queries allowed")

        # Inject user scope
        sql_with_scope = f"{sql} WHERE owner_id = {self.user.id}"

        return db.execute(sql_with_scope)

# DEFENSE IN DEPTH:
1. Implement RBAC on all agent tools
2. Rate limit tool calls (per user, per tool)
3. Require approval for sensitive operations
4. Audit log all agent actions
5. Principle of least privilege (read-only by default)
6. Scope data access to current user
7. Validate all tool inputs
8. Set monetary/resource limits
9. Implement circuit breakers
10. Monitor for anomalous behavior

NEVER DO:
- Give agents unrestricted database access
- Allow agents to delete/modify without approval
- Skip rate limiting on agent tools
- Grant admin permissions by default
- Allow agents to access other users' data
- Execute tool calls without validation

Reference: OWASP LLM06 - Excessive Agency
"""


class ExcessiveAgencyDetector:
    """
    Detects AI agents with excessive permissions.

    Critical: Agents need RBAC, rate limits, and approval workflows.
    """

    # Agent frameworks
    AGENT_FRAMEWORKS = {
        'langchain', 'autogpt', 'agent', 'tool',
        'crewai', 'semantic_kernel', 'haystack'
    }

    # Dangerous operations that need controls
    DANGEROUS_OPERATIONS = {
        'delete': 'data_deletion',
        'drop': 'data_deletion',
        'remove': 'data_deletion',
        'transfer': 'financial',
        'payment': 'financial',
        'charge': 'financial',
        'execute': 'code_execution',
        'eval': 'code_execution',
        'system': 'command_execution',
        'sendmail': 'email',
        'send_email': 'email',
    }

    # Required security controls
    REQUIRED_CONTROLS = [
        'permission', 'authorize', 'rbac', 'access_control',
        'rate_limit', 'throttle', 'approval', 'audit'
    ]

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """Main detection method."""
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_excessive_agency(file_content, file_path))

        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_excessive_agency(self, content: str, file_path: str) -> List[ExcessiveAgencyFinding]:
        """AST-based detection for Python."""
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Check agent tool definitions
            if isinstance(node, ast.Call):
                finding = self._check_agent_tool(node, content)
                if finding:
                    findings.append(finding)

            # Check function definitions for agent tools
            if isinstance(node, ast.FunctionDef):
                finding = self._check_tool_function(node, content)
                if finding:
                    findings.append(finding)

        return findings

    def _check_agent_tool(self, node: ast.Call, content: str) -> ExcessiveAgencyFinding:
        """Check if agent tool lacks security controls."""
        func_name = self._get_function_name(node)

        if not func_name:
            return None

        # Check if it's a tool definition
        if 'Tool' not in func_name and 'tool' not in func_name.lower():
            return None

        # Check if tool has dangerous capability
        dangerous_cap = None
        tool_func_name = None

        for keyword in node.keywords:
            if keyword.arg in ['func', 'function', 'name']:
                if isinstance(keyword.value, ast.Name):
                    tool_func_name = keyword.value.id
                elif isinstance(keyword.value, ast.Constant):
                    tool_func_name = keyword.value.value

        if tool_func_name:
            for danger, dtype in self.DANGEROUS_OPERATIONS.items():
                if danger in tool_func_name.lower():
                    dangerous_cap = dtype
                    break

        if dangerous_cap:
            # Check if security controls are present
            has_controls = self._has_security_controls(content, node.lineno)

            if not has_controls:
                return ExcessiveAgencyFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node)[:200] or '',
                    severity='CRITICAL',
                    confidence=85,
                    description=f'Agent tool with {dangerous_cap} capability lacks security controls',
                    agent_type='tool',
                    missing_control='RBAC/rate_limit/approval',
                    dangerous_capability=dangerous_cap
                )

        return None

    def _check_tool_function(self, node: ast.FunctionDef, content: str) -> ExcessiveAgencyFinding:
        """Check if function used as agent tool has controls."""
        func_name = node.name.lower()

        # Check if function has dangerous operation
        dangerous_cap = None
        for danger, dtype in self.DANGEROUS_OPERATIONS.items():
            if danger in func_name:
                dangerous_cap = dtype
                break

        if not dangerous_cap:
            return None

        # Check if function has security decorators
        has_decorator = False
        for decorator in node.decorator_list:
            decorator_name = ''
            if isinstance(decorator, ast.Name):
                decorator_name = decorator.id
            elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                decorator_name = decorator.func.id

            if any(control in decorator_name.lower() for control in self.REQUIRED_CONTROLS):
                has_decorator = True
                break

        if not has_decorator:
            # Check if used as agent tool
            source_segment = ast.get_source_segment(content, node)
            if source_segment and ('Tool' in content or 'agent' in content.lower()):
                return ExcessiveAgencyFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=source_segment[:200] or '',
                    severity='HIGH',
                    confidence=75,
                    description=f'Function with {dangerous_cap} operation lacks security controls',
                    agent_type='function',
                    missing_control='decorator/permission_check',
                    dangerous_capability=dangerous_cap
                )

        return None

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[ExcessiveAgencyFinding]:
        """Pattern-based detection."""
        findings = []
        lines = content.split('\n')

        # Pattern 1: Tool with delete/drop without checks
        dangerous_tool_pattern = re.compile(
            r'Tool\s*\([^)]*(?:delete|drop|remove|transfer)',
            re.IGNORECASE
        )

        # Pattern 2: Agent with unrestricted database access
        unrestricted_db_pattern = re.compile(
            r'(?:agent|tool).*(?:db\.|database\.|execute\(|query\()',
            re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            # Check for dangerous tools
            if dangerous_tool_pattern.search(line):
                # Check if controls are present in surrounding lines
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                has_controls = any(control in context.lower() for control in self.REQUIRED_CONTROLS)

                if not has_controls:
                    findings.append(ExcessiveAgencyFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='CRITICAL',
                        confidence=80,
                        description='Agent tool with dangerous operation lacks security controls',
                        agent_type='tool',
                        missing_control='permission_check',
                        dangerous_capability='dangerous_operation'
                    ))

            # Check for unrestricted database access
            if unrestricted_db_pattern.search(line):
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                has_controls = any(control in context.lower() for control in self.REQUIRED_CONTROLS)

                if not has_controls:
                    findings.append(ExcessiveAgencyFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=70,
                        description='Agent with unrestricted database access',
                        agent_type='agent',
                        missing_control='scoped_access',
                        dangerous_capability='database_access'
                    ))

        return findings

    def _has_security_controls(self, content: str, line_num: int) -> bool:
        """Check if security controls are present near line."""
        lines = content.split('\n')
        context_start = max(0, line_num - 10)
        context_end = min(len(lines), line_num + 10)
        context = '\n'.join(lines[context_start:context_end])

        return any(control in context.lower() for control in self.REQUIRED_CONTROLS)

    def _get_function_name(self, node: ast.Call) -> str:
        """Get function name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ''
