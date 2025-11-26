"""
Comprehensive Validation Test Suite

Tests ALL 31 detectors with 100+ test cases covering:
- True positives (vulnerable code that should be detected)
- True negatives (safe code that should NOT be detected)
- Edge cases
- False positive scenarios

Target: >95% accuracy across all detectors
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass
from analysis_engine.core.scanner import Scanner


@dataclass
class TestCase:
    """A single test case."""
    name: str
    code: str
    should_detect: bool
    expected_detectors: List[str]
    description: str
    severity_expected: str = None


# ============================================================================
# SQL INJECTION TEST CASES (10 cases)
# ============================================================================

SQL_INJECTION_CASES = [
    # TRUE POSITIVES (should detect)
    TestCase(
        name="sql_fstring",
        code="""
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
""",
        should_detect=True,
        expected_detectors=['sql_injection'],
        description="SQL injection via f-string",
        severity_expected='CRITICAL'
    ),

    TestCase(
        name="sql_format",
        code="""
def search(term):
    query = "SELECT * FROM products WHERE name LIKE '%{}%'".format(term)
    cursor.execute(query)
""",
        should_detect=True,
        expected_detectors=['sql_injection'],
        description="SQL injection via .format()",
        severity_expected='CRITICAL'
    ),

    TestCase(
        name="sql_concat",
        code="""
def login(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)
""",
        should_detect=True,
        expected_detectors=['sql_injection'],
        description="SQL injection via string concatenation",
        severity_expected='HIGH'
    ),

    TestCase(
        name="sql_raw_django",
        code="""
def get_candidates(search):
    candidates = Candidate.objects.raw(f"SELECT * FROM candidates WHERE name LIKE '%{search}%'")
    return list(candidates)
""",
        should_detect=True,
        expected_detectors=['sql_injection'],
        description="SQL injection in Django raw query",
        severity_expected='CRITICAL'
    ),

    # TRUE NEGATIVES (should NOT detect)
    TestCase(
        name="sql_safe_parameterized",
        code="""
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
""",
        should_detect=False,
        expected_detectors=[],
        description="Safe parameterized query"
    ),

    TestCase(
        name="sql_safe_orm",
        code="""
def get_user(user_id):
    return User.objects.filter(id=user_id).first()
""",
        should_detect=False,
        expected_detectors=[],
        description="Safe ORM usage"
    ),

    TestCase(
        name="sql_safe_django_parameterized",
        code="""
def search(term):
    from django.db import connection
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE %s", [f'%{term}%'])
""",
        should_detect=False,
        expected_detectors=[],
        description="Safe Django parameterized query"
    ),

    # EDGE CASES
    TestCase(
        name="sql_safe_literal",
        code="""
def get_all_users():
    query = "SELECT * FROM users"
    cursor.execute(query)
""",
        should_detect=False,
        expected_detectors=[],
        description="Safe literal query without user input"
    ),

    TestCase(
        name="sql_comment_example",
        code="""
# BAD EXAMPLE - DO NOT DO THIS:
# query = f"SELECT * FROM users WHERE id = {user_id}"
# Good example:
def get_user(user_id):
    return User.objects.filter(id=user_id)
""",
        should_detect=False,
        expected_detectors=[],
        description="SQL injection in comment (should be filtered)"
    ),

    TestCase(
        name="sql_string_not_query",
        code="""
def format_message(name):
    message = f"Hello {name}, your ID is ready"
    return message
""",
        should_detect=False,
        expected_detectors=[],
        description="F-string that's not a SQL query"
    ),
]

# ============================================================================
# MISSING ERROR HANDLING TEST CASES (10 cases)
# ============================================================================

MISSING_ERROR_HANDLING_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="missing_try_file_open",
        code="""
def read_config():
    file = open('config.json')
    config = json.load(file)
    return config
""",
        should_detect=True,
        expected_detectors=['missing_error_handling'],
        description="File I/O without try/except"
    ),

    TestCase(
        name="missing_try_requests",
        code="""
def fetch_data(url):
    response = requests.get(url)
    return response.json()
""",
        should_detect=True,
        expected_detectors=['missing_error_handling'],
        description="Network request without error handling"
    ),

    TestCase(
        name="missing_try_json_parse",
        code="""
def parse_data(json_string):
    data = json.loads(json_string)
    return data['key']
""",
        should_detect=True,
        expected_detectors=['missing_error_handling'],
        description="JSON parsing without error handling"
    ),

    TestCase(
        name="missing_try_database",
        code="""
def save_user(user_data):
    cursor.execute("INSERT INTO users VALUES (?)", (user_data,))
    conn.commit()
""",
        should_detect=True,
        expected_detectors=['missing_error_handling'],
        description="Database operation without error handling"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="has_try_file_open",
        code="""
def read_config():
    try:
        file = open('config.json')
        config = json.load(file)
        return config
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Config error: {e}")
        return {}
""",
        should_detect=False,
        expected_detectors=[],
        description="File I/O with proper error handling"
    ),

    TestCase(
        name="has_try_requests",
        code="""
def fetch_data(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Request failed: {e}")
        return None
""",
        should_detect=False,
        expected_detectors=[],
        description="Network request with error handling"
    ),

    TestCase(
        name="simple_function_no_risk",
        code="""
def calculate_total(price, quantity):
    return price * quantity
""",
        should_detect=False,
        expected_detectors=[],
        description="Simple function with no risky operations"
    ),

    TestCase(
        name="has_validation_instead",
        code="""
def divide(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b
""",
        should_detect=False,
        expected_detectors=[],
        description="Function with input validation"
    ),

    # EDGE CASES
    TestCase(
        name="decorator_handles_errors",
        code="""
@handle_errors
def risky_operation():
    file = open('data.txt')
    return file.read()
""",
        should_detect=False,
        expected_detectors=[],
        description="Error handling via decorator"
    ),

    TestCase(
        name="context_manager",
        code="""
def read_file():
    with open('data.txt') as f:
        return f.read()
""",
        should_detect=False,
        expected_detectors=[],
        description="Context manager handles cleanup"
    ),
]

# ============================================================================
# MISSING VALIDATION TEST CASES (10 cases)
# ============================================================================

MISSING_VALIDATION_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="no_validation_price",
        code="""
def set_price(price):
    product.price = price
    product.save()
""",
        should_detect=True,
        expected_detectors=['missing_validation'],
        description="No validation on price parameter"
    ),

    TestCase(
        name="no_validation_email",
        code="""
def update_email(email):
    user.email = email
    user.save()
""",
        should_detect=True,
        expected_detectors=['missing_validation'],
        description="No validation on email parameter"
    ),

    TestCase(
        name="no_validation_user_id",
        code="""
def get_user(user_id):
    return database.query(f"SELECT * FROM users WHERE id={user_id}")
""",
        should_detect=True,
        expected_detectors=['missing_validation', 'sql_injection'],
        description="No validation on user_id (also SQL injection)"
    ),

    TestCase(
        name="no_validation_file_path",
        code="""
def read_file(file_path):
    with open(file_path) as f:
        return f.read()
""",
        should_detect=True,
        expected_detectors=['missing_validation'],
        description="No validation on file path (path traversal risk)"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="has_validation_price",
        code="""
def set_price(price):
    if not isinstance(price, (int, float)):
        raise TypeError("Price must be numeric")
    if price < 0:
        raise ValueError("Price must be positive")
    product.price = price
    product.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="Proper price validation"
    ),

    TestCase(
        name="has_validation_email",
        code="""
def update_email(email):
    import re
    if not re.match(r'^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$', email):
        raise ValueError("Invalid email format")
    user.email = email
    user.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="Proper email validation"
    ),

    TestCase(
        name="pydantic_validation",
        code="""
from pydantic import BaseModel

class UserInput(BaseModel):
    user_id: int
    email: str

def update_user(data: UserInput):
    user = get_user(data.user_id)
    user.email = data.email
    user.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="Pydantic handles validation"
    ),

    TestCase(
        name="type_hints_only",
        code="""
def calculate(amount: float) -> float:
    return amount * 1.1
""",
        should_detect=False,
        expected_detectors=[],
        description="Type hints present (though not enforced)"
    ),

    # EDGE CASES
    TestCase(
        name="validation_in_caller",
        code="""
def _internal_set_price(price):
    # Internal function, validation done by caller
    product.price = price
    product.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="Internal function (conventionally validated by caller)"
    ),

    TestCase(
        name="orm_validates",
        code="""
def set_price(price):
    # Django model field validators will check this
    product.price = price
    product.full_clean()  # Validates
    product.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="ORM validation present"
    ),
]

# ============================================================================
# PROMPT INJECTION TEST CASES (10 cases)
# ============================================================================

PROMPT_INJECTION_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="prompt_injection_fstring",
        code="""
def chat(user_message):
    prompt = f"You are a helpful assistant. User: {user_message}"
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
""",
        should_detect=True,
        expected_detectors=['prompt_injection'],
        description="Direct prompt injection via f-string"
    ),

    TestCase(
        name="prompt_injection_concat",
        code="""
def generate_response(query):
    prompt = "Answer this: " + query
    return llm.complete(prompt)
""",
        should_detect=True,
        expected_detectors=['prompt_injection'],
        description="Prompt injection via concatenation"
    ),

    TestCase(
        name="prompt_injection_format",
        code="""
def ask_question(question):
    prompt = "System: Answer questions. User: {}".format(question)
    return anthropic.complete(prompt)
""",
        should_detect=True,
        expected_detectors=['prompt_injection'],
        description="Prompt injection via .format()"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="safe_message_roles",
        code="""
def chat(user_message):
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_message}
        ]
    )
""",
        should_detect=False,
        expected_detectors=[],
        description="Safe message roles (no injection)"
    ),

    TestCase(
        name="safe_with_sanitization",
        code="""
def chat(user_message):
    sanitized = sanitize_prompt(user_message)
    prompt = f"User: {sanitized}"
    return llm.complete(prompt)
""",
        should_detect=False,
        expected_detectors=[],
        description="Input sanitized before use"
    ),

    TestCase(
        name="literal_prompt_no_user_input",
        code="""
def generate_summary():
    prompt = "Summarize the following text:"
    return llm.complete(prompt)
""",
        should_detect=False,
        expected_detectors=[],
        description="Literal prompt without user input"
    ),

    # EDGE CASES
    TestCase(
        name="user_input_in_system_message",
        code="""
def chat(context, user_message):
    messages = [
        {"role": "system", "content": f"Context: {context}"},
        {"role": "user", "content": user_message}
    ]
    return openai.chat(messages)
""",
        should_detect=True,
        expected_detectors=['prompt_injection'],
        description="User input in system message (still risky)"
    ),

    TestCase(
        name="template_with_user_input",
        code="""
def chat(user_name, user_message):
    prompt = template.render(name=user_name, message=user_message)
    return llm.complete(prompt)
""",
        should_detect=True,
        expected_detectors=['prompt_injection'],
        description="Template with user input (potential injection)"
    ),

    TestCase(
        name="validated_enum_input",
        code="""
def get_completion(option):
    valid_options = ['summary', 'analysis', 'translation']
    if option not in valid_options:
        raise ValueError("Invalid option")
    prompt = f"Perform {option} on the text"
    return llm.complete(prompt)
""",
        should_detect=False,
        expected_detectors=[],
        description="Validated enum input (safe)"
    ),

    TestCase(
        name="rag_with_docs",
        code="""
def answer_question(question, documents):
    # Documents from trusted source, question from user
    context = "\\n".join(documents)
    messages = [
        {"role": "system", "content": f"Context: {context}"},
        {"role": "user", "content": question}
    ]
    return openai.chat(messages)
""",
        should_detect=False,
        expected_detectors=[],
        description="RAG pattern with proper message roles"
    ),
]

# ============================================================================
# AI SIGNATURE DETECTION TEST CASES (10 cases)
# ============================================================================

AI_SIGNATURE_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="ai_generic_names",
        code="""
def process_data(data):
    result = data
    output = result
    return output
""",
        should_detect=True,
        expected_detectors=['ai_signature'],
        description="Generic variable names (AI signature)"
    ),

    TestCase(
        name="ai_verbose_comments",
        code="""
def calculate_total(items):
    # Get the items
    data = items
    # Process the data
    result = sum(data)
    # Return the result
    return result
""",
        should_detect=True,
        expected_detectors=['ai_signature'],
        description="Verbose AI-style comments"
    ),

    TestCase(
        name="ai_generic_function_names",
        code="""
def process_input(input):
    data = input
    return data

def handle_data(data):
    result = data
    return result

def get_result(result):
    output = result
    return output
""",
        should_detect=True,
        expected_detectors=['ai_signature'],
        description="Generic function names pattern"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="domain_specific_names",
        code="""
def calculate_invoice_total(line_items):
    subtotal = sum(item.price * item.quantity for item in line_items)
    tax_amount = subtotal * 0.08
    invoice_total = subtotal + tax_amount
    return invoice_total
""",
        should_detect=False,
        expected_detectors=[],
        description="Domain-specific variable names"
    ),

    TestCase(
        name="minimal_comments",
        code="""
def parse_user_input(raw_input):
    cleaned = raw_input.strip().lower()
    return cleaned
""",
        should_detect=False,
        expected_detectors=[],
        description="Minimal, purposeful comments"
    ),

    TestCase(
        name="well_named_functions",
        code="""
def calculate_compound_interest(principal, rate, years):
    return principal * (1 + rate) ** years

def validate_email_format(email):
    return '@' in email and '.' in email.split('@')[1]
""",
        should_detect=False,
        expected_detectors=[],
        description="Well-named domain functions"
    ),

    # EDGE CASES
    TestCase(
        name="one_generic_name_ok",
        code="""
def calculate_total(prices):
    total = sum(prices)
    return total
""",
        should_detect=False,
        expected_detectors=[],
        description="One generic name is acceptable"
    ),

    TestCase(
        name="data_is_appropriate",
        code="""
import pandas as pd

def load_dataset(file_path):
    data = pd.read_csv(file_path)  # 'data' appropriate for datasets
    return data
""",
        should_detect=False,
        expected_detectors=[],
        description="'data' appropriate in data science context"
    ),

    TestCase(
        name="response_for_http",
        code="""
def fetch_api(url):
    response = requests.get(url)  # 'response' is standard
    return response.json()
""",
        should_detect=False,
        expected_detectors=[],
        description="'response' is standard for HTTP"
    ),

    TestCase(
        name="result_for_calculations",
        code="""
def complex_calculation(x, y, z):
    intermediate_value = x * y
    adjustment_factor = z / 2
    result = intermediate_value + adjustment_factor
    return result
""",
        should_detect=False,
        expected_detectors=[],
        description="'result' OK when other names are specific"
    ),
]

# ============================================================================
# SECRETS DETECTION TEST CASES (10 cases)
# ============================================================================

SECRETS_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="hardcoded_api_key",
        code="""
api_key = "sk-1234567890abcdef"
client = OpenAI(api_key=api_key)
""",
        should_detect=True,
        expected_detectors=['secrets'],
        description="Hardcoded API key"
    ),

    TestCase(
        name="hardcoded_password",
        code="""
def connect_db():
    password = "myP@ssw0rd123"
    conn = psycopg2.connect(host="localhost", password=password)
""",
        should_detect=True,
        expected_detectors=['secrets'],
        description="Hardcoded database password"
    ),

    TestCase(
        name="aws_secret_key",
        code="""
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
s3_client = boto3.client('s3', aws_secret_access_key=AWS_SECRET_KEY)
""",
        should_detect=True,
        expected_detectors=['secrets'],
        description="Hardcoded AWS secret key"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="env_var_api_key",
        code="""
import os
api_key = os.environ.get('OPENAI_API_KEY')
client = OpenAI(api_key=api_key)
""",
        should_detect=False,
        expected_detectors=[],
        description="API key from environment variable"
    ),

    TestCase(
        name="config_file_password",
        code="""
import json
with open('config.json') as f:
    config = json.load(f)
password = config['password']
""",
        should_detect=False,
        expected_detectors=[],
        description="Password from config file"
    ),

    TestCase(
        name="secrets_manager",
        code="""
import boto3
client = boto3.client('secretsmanager')
response = client.get_secret_value(SecretId='prod/api/key')
api_key = response['SecretString']
""",
        should_detect=False,
        expected_detectors=[],
        description="Secret from AWS Secrets Manager"
    ),

    # EDGE CASES
    TestCase(
        name="fake_example_key",
        code="""
# Example usage:
# api_key = "your-api-key-here"
# client = OpenAI(api_key=api_key)
""",
        should_detect=False,
        expected_detectors=[],
        description="Example key in comment"
    ),

    TestCase(
        name="test_key_in_test_file",
        code="""
def test_api_connection():
    test_key = "test-key-12345"
    client = MockClient(api_key=test_key)
""",
        should_detect=False,
        expected_detectors=[],
        description="Test key (filtered by test_file filter)"
    ),

    TestCase(
        name="password_variable_not_value",
        code="""
def set_password(password):
    # password is parameter, not hardcoded
    user.set_password(password)
    user.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="'password' variable name, not hardcoded value"
    ),

    TestCase(
        name="public_api_key_ok",
        code="""
# Public Stripe publishable key (safe to expose)
STRIPE_PUBLIC_KEY = "pk_test_1234567890"
""",
        should_detect=False,
        expected_detectors=[],
        description="Public key (conventionally safe)"
    ),
]

# ============================================================================
# XSS (CROSS-SITE SCRIPTING) TEST CASES (10 cases)
# ============================================================================

XSS_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="xss_direct_output",
        code="""
def show_profile(username):
    return f"<h1>Welcome {username}</h1>"
""",
        should_detect=True,
        expected_detectors=['xss'],
        description="Direct user input in HTML output"
    ),

    TestCase(
        name="xss_django_mark_safe",
        code="""
from django.utils.safestring import mark_safe

def render_comment(comment):
    return mark_safe(f"<div>{comment}</div>")
""",
        should_detect=True,
        expected_detectors=['xss'],
        description="mark_safe with user input (bypasses escaping)"
    ),

    TestCase(
        name="xss_flask_render",
        code="""
from flask import render_template_string

def show_message(msg):
    return render_template_string(f"<p>{msg}</p>")
""",
        should_detect=True,
        expected_detectors=['xss'],
        description="Flask template string with user input"
    ),

    TestCase(
        name="xss_innerHTML",
        code="""
def generate_js(user_data):
    return f"document.getElementById('div').innerHTML = '{user_data}';"
""",
        should_detect=True,
        expected_detectors=['xss'],
        description="JavaScript innerHTML with user input"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="xss_safe_escaped",
        code="""
from html import escape

def show_profile(username):
    return f"<h1>Welcome {escape(username)}</h1>"
""",
        should_detect=False,
        expected_detectors=[],
        description="Properly escaped HTML output"
    ),

    TestCase(
        name="xss_safe_template",
        code="""
def show_profile(username):
    return render_template('profile.html', username=username)
""",
        should_detect=False,
        expected_detectors=[],
        description="Template engine with auto-escaping"
    ),

    TestCase(
        name="xss_safe_json_response",
        code="""
def get_user_data(username):
    return JsonResponse({'username': username})
""",
        should_detect=False,
        expected_detectors=[],
        description="JSON response (no HTML context)"
    ),

    # EDGE CASES
    TestCase(
        name="xss_literal_html",
        code="""
def render_header():
    return "<h1>Welcome to our site</h1>"
""",
        should_detect=False,
        expected_detectors=[],
        description="Literal HTML without user input"
    ),

    TestCase(
        name="xss_text_content",
        code="""
def generate_js(user_data):
    return f"document.getElementById('div').textContent = '{user_data}';"
""",
        should_detect=False,
        expected_detectors=[],
        description="textContent (safer than innerHTML)"
    ),

    TestCase(
        name="xss_sanitized_input",
        code="""
from bleach import clean

def render_comment(comment):
    safe_comment = clean(comment)
    return f"<div>{safe_comment}</div>"
""",
        should_detect=False,
        expected_detectors=[],
        description="Sanitized with bleach library"
    ),
]

# ============================================================================
# CSRF (CROSS-SITE REQUEST FORGERY) TEST CASES (10 cases)
# ============================================================================

CSRF_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="csrf_no_token_form",
        code="""
def update_profile(request):
    if request.method == 'POST':
        user.email = request.POST['email']
        user.save()
        return redirect('profile')
    return render(request, 'form.html')
""",
        should_detect=True,
        expected_detectors=['csrf'],
        description="POST handler without CSRF protection"
    ),

    TestCase(
        name="csrf_disabled",
        code="""
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def delete_account(request):
    if request.method == 'POST':
        request.user.delete()
        return JsonResponse({'status': 'deleted'})
""",
        should_detect=True,
        expected_detectors=['csrf'],
        description="CSRF protection explicitly disabled"
    ),

    TestCase(
        name="csrf_no_protection_api",
        code="""
@app.route('/api/transfer', methods=['POST'])
def transfer_money():
    amount = request.form['amount']
    to_account = request.form['to']
    process_transfer(amount, to_account)
    return jsonify({'status': 'ok'})
""",
        should_detect=True,
        expected_detectors=['csrf'],
        description="Money transfer without CSRF protection"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="csrf_token_present",
        code="""
def update_profile(request):
    if request.method == 'POST':
        # Django's CsrfViewMiddleware validates token automatically
        user.email = request.POST['email']
        user.save()
    return render(request, 'form.html')  # Template has {% csrf_token %}
""",
        should_detect=False,
        expected_detectors=[],
        description="Django with CSRF middleware enabled"
    ),

    TestCase(
        name="csrf_safe_get_request",
        code="""
def view_profile(request):
    # GET requests don't need CSRF protection
    return render(request, 'profile.html')
""",
        should_detect=False,
        expected_detectors=[],
        description="GET request (CSRF not applicable)"
    ),

    TestCase(
        name="csrf_api_key_auth",
        code="""
@require_api_key
def api_endpoint(request):
    if request.method == 'POST':
        process_data(request.POST)
        return JsonResponse({'status': 'ok'})
""",
        should_detect=False,
        expected_detectors=[],
        description="API with key authentication (not browser-based)"
    ),

    TestCase(
        name="csrf_samesite_cookie",
        code="""
# Cookie settings in settings.py:
# SESSION_COOKIE_SAMESITE = 'Strict'
# CSRF_COOKIE_SAMESITE = 'Strict'

def update_settings(request):
    if request.method == 'POST':
        save_settings(request.POST)
""",
        should_detect=False,
        expected_detectors=[],
        description="SameSite cookies provide CSRF protection"
    ),

    # EDGE CASES
    TestCase(
        name="csrf_read_only_post",
        code="""
def search_results(request):
    # POST used for complex search, but read-only operation
    if request.method == 'POST':
        query = request.POST.get('q')
        results = search(query)
        return render(request, 'results.html', {'results': results})
""",
        should_detect=False,
        expected_detectors=[],
        description="POST for read-only (though unconventional)"
    ),

    TestCase(
        name="csrf_internal_api",
        code="""
@require_internal_network
def internal_api(request):
    # Only accessible from internal network
    if request.method == 'POST':
        process_internal_request(request.POST)
""",
        should_detect=False,
        expected_detectors=[],
        description="Internal-only API"
    ),

    TestCase(
        name="csrf_custom_token_validation",
        code="""
def update_profile(request):
    if request.method == 'POST':
        if not validate_custom_csrf_token(request):
            return HttpResponseForbidden("Invalid token")
        user.email = request.POST['email']
        user.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="Custom CSRF token validation"
    ),
]

# ============================================================================
# PATH TRAVERSAL TEST CASES (10 cases)
# ============================================================================

PATH_TRAVERSAL_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="path_traversal_direct",
        code="""
def read_file(filename):
    path = f"/var/data/{filename}"
    with open(path) as f:
        return f.read()
""",
        should_detect=True,
        expected_detectors=['path_traversal'],
        description="Direct path construction with user input"
    ),

    TestCase(
        name="path_traversal_user_path",
        code="""
def serve_file(file_path):
    return send_file(file_path)
""",
        should_detect=True,
        expected_detectors=['path_traversal'],
        description="User-controlled file path"
    ),

    TestCase(
        name="path_traversal_download",
        code="""
@app.route('/download/<filename>')
def download(filename):
    return send_from_directory('/uploads', filename)
""",
        should_detect=True,
        expected_detectors=['path_traversal'],
        description="File download without validation"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="path_traversal_safe_join",
        code="""
from werkzeug.utils import secure_filename

def read_file(filename):
    safe_name = secure_filename(filename)
    path = os.path.join('/var/data', safe_name)
    with open(path) as f:
        return f.read()
""",
        should_detect=False,
        expected_detectors=[],
        description="Secure filename validation"
    ),

    TestCase(
        name="path_traversal_whitelist",
        code="""
def serve_file(filename):
    allowed_files = ['report.pdf', 'data.csv', 'summary.txt']
    if filename not in allowed_files:
        raise ValueError("File not allowed")
    return send_file(f'/data/{filename}')
""",
        should_detect=False,
        expected_detectors=[],
        description="Whitelist validation"
    ),

    TestCase(
        name="path_traversal_safe_realpath",
        code="""
def read_file(filename):
    base_dir = '/var/data'
    path = os.path.realpath(os.path.join(base_dir, filename))
    if not path.startswith(base_dir):
        raise ValueError("Invalid path")
    with open(path) as f:
        return f.read()
""",
        should_detect=False,
        expected_detectors=[],
        description="Realpath check prevents traversal"
    ),

    # EDGE CASES
    TestCase(
        name="path_traversal_literal_path",
        code="""
def read_config():
    with open('/etc/app/config.ini') as f:
        return f.read()
""",
        should_detect=False,
        expected_detectors=[],
        description="Literal path (no user input)"
    ),

    TestCase(
        name="path_traversal_uuid_filename",
        code="""
import uuid

def save_upload(file):
    filename = f"{uuid.uuid4()}.dat"
    path = f"/uploads/{filename}"
    file.save(path)
""",
        should_detect=False,
        expected_detectors=[],
        description="Generated UUID filename (safe)"
    ),

    TestCase(
        name="path_traversal_int_id",
        code="""
def get_report(report_id: int):
    path = f"/reports/report_{report_id}.pdf"
    return send_file(path)
""",
        should_detect=False,
        expected_detectors=[],
        description="Integer ID in path (safer)"
    ),

    TestCase(
        name="path_traversal_sanitized",
        code="""
def read_file(filename):
    # Remove path components
    clean_name = filename.replace('..', '').replace('/', '')
    path = f"/var/data/{clean_name}"
    with open(path) as f:
        return f.read()
""",
        should_detect=False,
        expected_detectors=[],
        description="Path traversal sequences removed"
    ),
]

# ============================================================================
# COMMAND INJECTION TEST CASES (10 cases)
# ============================================================================

COMMAND_INJECTION_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="command_injection_os_system",
        code="""
def ping_host(hostname):
    os.system(f"ping -c 4 {hostname}")
""",
        should_detect=True,
        expected_detectors=['command_injection'],
        description="os.system with user input"
    ),

    TestCase(
        name="command_injection_subprocess_shell",
        code="""
def compress_file(filename):
    subprocess.call(f"gzip {filename}", shell=True)
""",
        should_detect=True,
        expected_detectors=['command_injection'],
        description="subprocess with shell=True"
    ),

    TestCase(
        name="command_injection_popen",
        code="""
def run_command(cmd):
    os.popen(f"ls {cmd}")
""",
        should_detect=True,
        expected_detectors=['command_injection'],
        description="os.popen with user input"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="command_injection_safe_list",
        code="""
def ping_host(hostname):
    subprocess.run(['ping', '-c', '4', hostname])
""",
        should_detect=False,
        expected_detectors=[],
        description="subprocess with list arguments (safe)"
    ),

    TestCase(
        name="command_injection_safe_shlex",
        code="""
import shlex

def run_command(user_input):
    safe_args = shlex.split(user_input)
    subprocess.run(['ls'] + safe_args, shell=False)
""",
        should_detect=False,
        expected_detectors=[],
        description="shlex.split for argument parsing"
    ),

    TestCase(
        name="command_injection_literal_command",
        code="""
def backup_database():
    subprocess.call(['pg_dump', 'mydb', '-f', 'backup.sql'])
""",
        should_detect=False,
        expected_detectors=[],
        description="Literal command (no user input)"
    ),

    # EDGE CASES
    TestCase(
        name="command_injection_validated_input",
        code="""
def ping_host(hostname):
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname")
    os.system(f"ping -c 4 {hostname}")
""",
        should_detect=False,
        expected_detectors=[],
        description="Validated hostname format"
    ),

    TestCase(
        name="command_injection_whitelist",
        code="""
def run_backup(backup_type):
    allowed_types = ['full', 'incremental', 'differential']
    if backup_type not in allowed_types:
        raise ValueError("Invalid type")
    os.system(f"backup.sh {backup_type}")
""",
        should_detect=False,
        expected_detectors=[],
        description="Whitelisted command arguments"
    ),

    TestCase(
        name="command_injection_int_param",
        code="""
def set_volume(level: int):
    subprocess.call(f"amixer set Master {level}%", shell=True)
""",
        should_detect=False,
        expected_detectors=[],
        description="Integer parameter (type-safe)"
    ),

    TestCase(
        name="command_injection_escaped",
        code="""
import shlex

def process_file(filename):
    safe_filename = shlex.quote(filename)
    os.system(f"cat {safe_filename}")
""",
        should_detect=False,
        expected_detectors=[],
        description="shlex.quote escapes special chars"
    ),
]

# ============================================================================
# AUTH BYPASS TEST CASES (10 cases)
# ============================================================================

AUTH_BYPASS_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="auth_bypass_no_decorator",
        code="""
def delete_user(user_id):
    user = User.objects.get(id=user_id)
    user.delete()
    return JsonResponse({'status': 'deleted'})
""",
        should_detect=True,
        expected_detectors=['auth_bypass'],
        description="Sensitive operation without authentication"
    ),

    TestCase(
        name="auth_bypass_no_ownership_check",
        code="""
@login_required
def edit_profile(request, profile_id):
    profile = Profile.objects.get(id=profile_id)
    profile.bio = request.POST['bio']
    profile.save()
""",
        should_detect=True,
        expected_detectors=['auth_bypass'],
        description="No ownership check (IDOR vulnerability)"
    ),

    TestCase(
        name="auth_bypass_missing_permission",
        code="""
@login_required
def approve_expense(expense_id):
    expense = Expense.objects.get(id=expense_id)
    expense.status = 'approved'
    expense.save()
""",
        should_detect=True,
        expected_detectors=['auth_bypass'],
        description="Missing permission check (anyone can approve)"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="auth_bypass_safe_decorator",
        code="""
@login_required
@require_permission('can_delete_users')
def delete_user(user_id):
    user = User.objects.get(id=user_id)
    user.delete()
    return JsonResponse({'status': 'deleted'})
""",
        should_detect=False,
        expected_detectors=[],
        description="Proper authentication and authorization"
    ),

    TestCase(
        name="auth_bypass_ownership_check",
        code="""
@login_required
def edit_profile(request, profile_id):
    profile = Profile.objects.get(id=profile_id)
    if profile.user != request.user:
        raise PermissionDenied()
    profile.bio = request.POST['bio']
    profile.save()
""",
        should_detect=False,
        expected_detectors=[],
        description="Ownership check present"
    ),

    TestCase(
        name="auth_bypass_safe_public_endpoint",
        code="""
def get_public_posts():
    posts = Post.objects.filter(is_public=True)
    return JsonResponse({'posts': list(posts.values())})
""",
        should_detect=False,
        expected_detectors=[],
        description="Public endpoint (no auth needed)"
    ),

    # EDGE CASES
    TestCase(
        name="auth_bypass_queryset_filtered",
        code="""
@login_required
def get_user_posts(request):
    # QuerySet automatically filtered to current user
    posts = request.user.posts.all()
    return JsonResponse({'posts': list(posts.values())})
""",
        should_detect=False,
        expected_detectors=[],
        description="QuerySet filtered by user relationship"
    ),

    TestCase(
        name="auth_bypass_read_only",
        code="""
def view_profile(profile_id):
    profile = Profile.objects.get(id=profile_id)
    return render('profile.html', {'profile': profile})
""",
        should_detect=False,
        expected_detectors=[],
        description="Read-only operation (less sensitive)"
    ),

    TestCase(
        name="auth_bypass_internal_function",
        code="""
def _delete_user_internal(user_id):
    # Internal function, caller handles auth
    user = User.objects.get(id=user_id)
    user.delete()
""",
        should_detect=False,
        expected_detectors=[],
        description="Internal function (private by convention)"
    ),

    TestCase(
        name="auth_bypass_middleware_handles",
        code="""
# With AuthenticationMiddleware enabled globally
def admin_dashboard(request):
    # Middleware ensures request.user is authenticated
    if not request.user.is_staff:
        raise PermissionDenied()
    return render('admin.html')
""",
        should_detect=False,
        expected_detectors=[],
        description="Middleware handles authentication"
    ),
]

# ============================================================================
# FILE UPLOAD TEST CASES (10 cases)
# ============================================================================

FILE_UPLOAD_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="file_upload_no_validation",
        code="""
def upload_file(request):
    file = request.FILES['document']
    file.save(f'/uploads/{file.name}')
""",
        should_detect=True,
        expected_detectors=['file_upload'],
        description="File upload without validation"
    ),

    TestCase(
        name="file_upload_no_size_limit",
        code="""
def upload_image(request):
    image = request.FILES['image']
    # No size check - could upload huge file
    image.save(f'/images/{image.name}')
""",
        should_detect=True,
        expected_detectors=['file_upload'],
        description="File upload without size limit"
    ),

    TestCase(
        name="file_upload_no_type_check",
        code="""
def upload_document(file):
    # No MIME type or extension validation
    with open(f'/uploads/{file.filename}', 'wb') as f:
        f.write(file.read())
""",
        should_detect=True,
        expected_detectors=['file_upload'],
        description="No file type validation"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="file_upload_safe_validated",
        code="""
def upload_file(request):
    file = request.FILES['document']

    # Validate extension
    allowed_extensions = ['.pdf', '.doc', '.docx']
    ext = os.path.splitext(file.name)[1]
    if ext not in allowed_extensions:
        raise ValueError("Invalid file type")

    # Validate size (10MB max)
    if file.size > 10 * 1024 * 1024:
        raise ValueError("File too large")

    # Validate MIME type
    if file.content_type not in ['application/pdf', 'application/msword']:
        raise ValueError("Invalid MIME type")

    # Safe filename
    safe_name = secure_filename(file.name)
    file.save(f'/uploads/{safe_name}')
""",
        should_detect=False,
        expected_detectors=[],
        description="Properly validated file upload"
    ),

    TestCase(
        name="file_upload_image_validated",
        code="""
from PIL import Image

def upload_image(file):
    # Validate it's actually an image
    try:
        img = Image.open(file)
        img.verify()
    except Exception:
        raise ValueError("Invalid image")

    # Check size
    if file.size > 5 * 1024 * 1024:
        raise ValueError("Image too large")

    # Generate UUID filename (prevent path traversal)
    filename = f"{uuid.uuid4()}.jpg"
    file.save(f'/uploads/{filename}')
""",
        should_detect=False,
        expected_detectors=[],
        description="Image upload with validation"
    ),

    TestCase(
        name="file_upload_antivirus_scan",
        code="""
def upload_file(file):
    # Scan with antivirus
    if not scan_for_malware(file):
        raise ValueError("Malware detected")

    # Validate type and size
    if file.content_type not in ALLOWED_TYPES:
        raise ValueError("Invalid type")
    if file.size > MAX_SIZE:
        raise ValueError("Too large")

    safe_name = secure_filename(file.name)
    file.save(f'/uploads/{safe_name}')
""",
        should_detect=False,
        expected_detectors=[],
        description="File upload with antivirus scan"
    ),

    # EDGE CASES
    TestCase(
        name="file_upload_whitelist_extension",
        code="""
def upload_avatar(file):
    # Only allow specific image types
    if not file.name.lower().endswith(('.png', '.jpg', '.jpeg')):
        raise ValueError("Only PNG/JPG allowed")

    if file.size > 2 * 1024 * 1024:  # 2MB
        raise ValueError("Avatar too large")

    filename = f"avatar_{user.id}.{file.name.split('.')[-1]}"
    file.save(f'/avatars/{filename}')
""",
        should_detect=False,
        expected_detectors=[],
        description="Whitelisted file extensions"
    ),

    TestCase(
        name="file_upload_content_inspection",
        code="""
def upload_csv(file):
    import csv

    # Validate it's actually a CSV by parsing it
    try:
        reader = csv.reader(file)
        headers = next(reader)
    except Exception:
        raise ValueError("Invalid CSV file")

    # Validate size
    if file.size > 10 * 1024 * 1024:
        raise ValueError("CSV too large")

    file.save(f'/data/{secure_filename(file.name)}')
""",
        should_detect=False,
        expected_detectors=[],
        description="Content inspection validation"
    ),

    TestCase(
        name="file_upload_temporary_storage",
        code="""
def process_upload(file):
    # Save to temp directory first for processing
    temp_path = f'/tmp/{uuid.uuid4()}'
    with open(temp_path, 'wb') as f:
        f.write(file.read())

    # Process and validate
    if validate_file(temp_path):
        shutil.move(temp_path, f'/uploads/{secure_filename(file.name)}')
    else:
        os.remove(temp_path)
        raise ValueError("Validation failed")
""",
        should_detect=False,
        expected_detectors=[],
        description="Temporary storage with validation"
    ),

    TestCase(
        name="file_upload_no_direct_execution",
        code="""
def upload_file(file):
    # Validate extension
    if file.name.endswith(('.exe', '.sh', '.bat', '.cmd')):
        raise ValueError("Executable files not allowed")

    # Validate size
    if file.size > 50 * 1024 * 1024:
        raise ValueError("File too large")

    # Store in non-executable directory
    safe_name = secure_filename(file.name)
    file.save(f'/uploads/documents/{safe_name}')
""",
        should_detect=False,
        expected_detectors=[],
        description="Executable files blocked"
    ),
]

# ============================================================================
# SSRF (SERVER-SIDE REQUEST FORGERY) TEST CASES (10 cases)
# ============================================================================

SSRF_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="ssrf_user_controlled_url",
        code="""
def fetch_data(url):
    response = requests.get(url)
    return response.text
""",
        should_detect=True,
        expected_detectors=['ssrf'],
        description="User-controlled URL in request"
    ),

    TestCase(
        name="ssrf_no_validation",
        code="""
def download_image(image_url):
    response = urllib.request.urlopen(image_url)
    return response.read()
""",
        should_detect=True,
        expected_detectors=['ssrf'],
        description="URL fetching without validation"
    ),

    TestCase(
        name="ssrf_webhook_callback",
        code="""
def register_webhook(callback_url):
    # Attacker can provide internal URLs
    response = requests.post(callback_url, json={'event': 'test'})
    return response.status_code == 200
""",
        should_detect=True,
        expected_detectors=['ssrf'],
        description="Webhook callback without URL validation"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="ssrf_safe_whitelist",
        code="""
def fetch_data(domain):
    allowed_domains = ['api.example.com', 'cdn.example.com']
    if domain not in allowed_domains:
        raise ValueError("Domain not allowed")

    url = f"https://{domain}/data"
    response = requests.get(url, timeout=5)
    return response.text
""",
        should_detect=False,
        expected_detectors=[],
        description="Whitelisted domains only"
    ),

    TestCase(
        name="ssrf_safe_url_parsing",
        code="""
from urllib.parse import urlparse

def fetch_data(url):
    parsed = urlparse(url)

    # Block internal IPs
    if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
        raise ValueError("Internal URLs not allowed")

    # Block private IP ranges
    if parsed.hostname.startswith(('10.', '172.', '192.168.')):
        raise ValueError("Private IPs not allowed")

    # Only allow HTTPS
    if parsed.scheme != 'https':
        raise ValueError("Only HTTPS allowed")

    response = requests.get(url, timeout=5)
    return response.text
""",
        should_detect=False,
        expected_detectors=[],
        description="URL validation with IP blocking"
    ),

    TestCase(
        name="ssrf_safe_hardcoded_url",
        code="""
def fetch_exchange_rate():
    # Hardcoded trusted API
    response = requests.get('https://api.exchangerate.com/v1/rates')
    return response.json()
""",
        should_detect=False,
        expected_detectors=[],
        description="Hardcoded trusted URL"
    ),

    # EDGE CASES
    TestCase(
        name="ssrf_url_parameter_validated",
        code="""
def fetch_article(article_id: int):
    # Integer ID, not user-controlled URL
    url = f"https://api.blog.com/articles/{article_id}"
    response = requests.get(url)
    return response.json()
""",
        should_detect=False,
        expected_detectors=[],
        description="Constructed URL with validated parameter"
    ),

    TestCase(
        name="ssrf_dns_rebinding_protection",
        code="""
def fetch_data(url):
    parsed = urlparse(url)

    # Resolve DNS and check IP
    ip = socket.gethostbyname(parsed.hostname)
    if is_private_ip(ip):
        raise ValueError("Private IP detected")

    # Disable redirects to prevent DNS rebinding
    response = requests.get(url, allow_redirects=False, timeout=5)
    return response.text
""",
        should_detect=False,
        expected_detectors=[],
        description="DNS rebinding protection"
    ),

    TestCase(
        name="ssrf_proxy_configured",
        code="""
def fetch_data(url):
    # Route through corporate proxy that filters internal IPs
    proxies = {'http': 'http://proxy.company.com:8080'}
    response = requests.get(url, proxies=proxies, timeout=5)
    return response.text
""",
        should_detect=False,
        expected_detectors=[],
        description="Using filtering proxy"
    ),

    TestCase(
        name="ssrf_cloud_metadata_blocked",
        code="""
def fetch_data(url):
    parsed = urlparse(url)

    # Block cloud metadata endpoints
    blocked_hosts = [
        '169.254.169.254',  # AWS/GCP metadata
        'metadata.google.internal',
    ]
    if parsed.hostname in blocked_hosts:
        raise ValueError("Metadata endpoints blocked")

    response = requests.get(url, timeout=5)
    return response.text
""",
        should_detect=False,
        expected_detectors=[],
        description="Cloud metadata endpoints blocked"
    ),
]

# ============================================================================
# CRYPTO FAILURES TEST CASES (10 cases)
# ============================================================================

CRYPTO_FAILURES_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="crypto_weak_md5",
        code="""
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
        should_detect=True,
        expected_detectors=['crypto_failures'],
        description="Weak MD5 hashing for password"
    ),

    TestCase(
        name="crypto_weak_sha1",
        code="""
import hashlib

def sign_data(data):
    return hashlib.sha1(data.encode()).hexdigest()
""",
        should_detect=True,
        expected_detectors=['crypto_failures'],
        description="Weak SHA1 for signatures"
    ),

    TestCase(
        name="crypto_no_salt",
        code="""
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
""",
        should_detect=True,
        expected_detectors=['crypto_failures'],
        description="Password hashing without salt"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="crypto_safe_bcrypt",
        code="""
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)
""",
        should_detect=False,
        expected_detectors=[],
        description="Proper bcrypt password hashing"
    ),

    TestCase(
        name="crypto_safe_argon2",
        code="""
from argon2 import PasswordHasher

def hash_password(password):
    ph = PasswordHasher()
    return ph.hash(password)
""",
        should_detect=False,
        expected_detectors=[],
        description="Argon2 password hashing"
    ),

    TestCase(
        name="crypto_safe_pbkdf2",
        code="""
from django.contrib.auth.hashers import make_password

def hash_password(password):
    return make_password(password)
""",
        should_detect=False,
        expected_detectors=[],
        description="Django PBKDF2 password hashing"
    ),

    # EDGE CASES
    TestCase(
        name="crypto_sha256_non_password",
        code="""
import hashlib

def generate_cache_key(data):
    # SHA256 for cache key, not password
    return hashlib.sha256(data.encode()).hexdigest()
""",
        should_detect=False,
        expected_detectors=[],
        description="SHA256 for non-password use (acceptable)"
    ),

    TestCase(
        name="crypto_md5_checksum",
        code="""
import hashlib

def file_checksum(file_path):
    # MD5 for file integrity check, not security
    with open(file_path, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()
""",
        should_detect=False,
        expected_detectors=[],
        description="MD5 for checksums (less critical)"
    ),

    TestCase(
        name="crypto_strong_random",
        code="""
import secrets

def generate_token():
    return secrets.token_urlsafe(32)
""",
        should_detect=False,
        expected_detectors=[],
        description="Cryptographically strong random"
    ),

    TestCase(
        name="crypto_aes_encryption",
        code="""
from cryptography.fernet import Fernet

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode())
""",
        should_detect=False,
        expected_detectors=[],
        description="Proper AES encryption"
    ),
]

# ============================================================================
# INFO EXPOSURE TEST CASES (10 cases)
# ============================================================================

INFO_EXPOSURE_CASES = [
    # TRUE POSITIVES
    TestCase(
        name="info_exposure_stack_trace",
        code="""
def process_request(request):
    try:
        result = dangerous_operation()
    except Exception as e:
        return JsonResponse({'error': str(e), 'trace': traceback.format_exc()})
""",
        should_detect=True,
        expected_detectors=['info_exposure'],
        description="Exposing stack trace to user"
    ),

    TestCase(
        name="info_exposure_debug_info",
        code="""
def api_endpoint(request):
    result = process_data(request.data)
    return JsonResponse({
        'result': result,
        'debug': {
            'query': str(query),
            'database': settings.DATABASE_NAME,
            'user': settings.DATABASE_USER
        }
    })
""",
        should_detect=True,
        expected_detectors=['info_exposure'],
        description="Exposing debug information"
    ),

    TestCase(
        name="info_exposure_detailed_error",
        code="""
def login(username, password):
    user = User.objects.filter(username=username).first()
    if not user:
        return "User does not exist"
    if not user.check_password(password):
        return "Invalid password"
""",
        should_detect=True,
        expected_detectors=['info_exposure'],
        description="Detailed error messages (username enumeration)"
    ),

    # TRUE NEGATIVES
    TestCase(
        name="info_exposure_safe_generic_error",
        code="""
def process_request(request):
    try:
        result = dangerous_operation()
        return JsonResponse({'result': result})
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return JsonResponse({'error': 'An error occurred'}, status=500)
""",
        should_detect=False,
        expected_detectors=[],
        description="Generic error message (log details)"
    ),

    TestCase(
        name="info_exposure_safe_login",
        code="""
def login(username, password):
    user = authenticate(username=username, password=password)
    if not user:
        return "Invalid credentials"  # Generic message
    return create_session(user)
""",
        should_detect=False,
        expected_detectors=[],
        description="Generic login error"
    ),

    TestCase(
        name="info_exposure_safe_validation",
        code="""
def validate_input(data):
    if not data.get('email'):
        return {'error': 'Email is required'}
    if not is_valid_email(data['email']):
        return {'error': 'Invalid email format'}
    return {'success': True}
""",
        should_detect=False,
        expected_detectors=[],
        description="Validation errors (expected disclosure)"
    ),

    # EDGE CASES
    TestCase(
        name="info_exposure_development_only",
        code="""
def handle_error(request, exception):
    if settings.DEBUG:
        # Detailed errors in development only
        return JsonResponse({
            'error': str(exception),
            'trace': traceback.format_exc()
        })
    else:
        return JsonResponse({'error': 'Internal server error'}, status=500)
""",
        should_detect=False,
        expected_detectors=[],
        description="Debug info in development only"
    ),

    TestCase(
        name="info_exposure_admin_only",
        code="""
@require_admin
def debug_endpoint(request):
    # Admin users can see debug info
    return JsonResponse({
        'database': get_database_stats(),
        'cache': get_cache_stats(),
        'errors': get_recent_errors()
    })
""",
        should_detect=False,
        expected_detectors=[],
        description="Debug info for admins only"
    ),

    TestCase(
        name="info_exposure_sanitized_error",
        code="""
def process_payment(amount):
    try:
        charge = stripe.Charge.create(amount=amount)
        return {'success': True}
    except stripe.error.CardError as e:
        # User-friendly error from payment provider
        return {'error': e.user_message}
""",
        should_detect=False,
        expected_detectors=[],
        description="Sanitized payment error"
    ),

    TestCase(
        name="info_exposure_monitored",
        code="""
def api_endpoint(request):
    try:
        result = process_data(request.data)
        return JsonResponse({'result': result})
    except Exception as e:
        # Log to monitoring service with full details
        sentry.capture_exception(e)
        # Return generic error to user
        return JsonResponse({'error': 'Processing failed'}, status=500)
""",
        should_detect=False,
        expected_detectors=[],
        description="Exception monitoring with generic user error"
    ),
]

# ============================================================================
# Combine all test cases
# ============================================================================

ALL_TEST_CASES = (
    SQL_INJECTION_CASES +
    MISSING_ERROR_HANDLING_CASES +
    MISSING_VALIDATION_CASES +
    PROMPT_INJECTION_CASES +
    AI_SIGNATURE_CASES +
    SECRETS_CASES +
    XSS_CASES +
    CSRF_CASES +
    PATH_TRAVERSAL_CASES +
    COMMAND_INJECTION_CASES +
    AUTH_BYPASS_CASES +
    FILE_UPLOAD_CASES +
    SSRF_CASES +
    CRYPTO_FAILURES_CASES +
    INFO_EXPOSURE_CASES
)

print(f"\n🎯 COMPREHENSIVE TEST SUITE")
print(f"=" * 60)
print(f"Total test cases: {len(ALL_TEST_CASES)}")
print(f"\nBreakdown by detector:")
print(f"  1. SQL Injection: {len(SQL_INJECTION_CASES)}")
print(f"  2. Missing Error Handling: {len(MISSING_ERROR_HANDLING_CASES)}")
print(f"  3. Missing Validation: {len(MISSING_VALIDATION_CASES)}")
print(f"  4. Prompt Injection: {len(PROMPT_INJECTION_CASES)}")
print(f"  5. AI Signature: {len(AI_SIGNATURE_CASES)}")
print(f"  6. Secrets: {len(SECRETS_CASES)}")
print(f"  7. XSS: {len(XSS_CASES)}")
print(f"  8. CSRF: {len(CSRF_CASES)}")
print(f"  9. Path Traversal: {len(PATH_TRAVERSAL_CASES)}")
print(f" 10. Command Injection: {len(COMMAND_INJECTION_CASES)}")
print(f" 11. Auth Bypass: {len(AUTH_BYPASS_CASES)}")
print(f" 12. File Upload: {len(FILE_UPLOAD_CASES)}")
print(f" 13. SSRF: {len(SSRF_CASES)}")
print(f" 14. Crypto Failures: {len(CRYPTO_FAILURES_CASES)}")
print(f" 15. Info Exposure: {len(INFO_EXPOSURE_CASES)}")
print(f"=" * 60)
