"""
Module: security_analyzer.py
Author: Claude AI + Human Reviewer (Bogdan)
Purpose: Detect security vulnerabilities in code (SQL injection, XSS, secrets, etc.)
"""

import os
import re
import json
import subprocess
from typing import List, Dict
from pathlib import Path


class SecurityAnalyzer:
    """
    Analyzes code for security vulnerabilities using Bandit and custom rules.
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.issues = []

    def analyze(self) -> List[Dict]:
        """
        Run all security analyses and return list of issues.
        """
        print(f"Running security analysis on {self.repo_path}")

        # Run Bandit for Python files
        self._run_bandit()

        # Check for hardcoded secrets
        self._scan_for_secrets()

        # Check for SQL injection patterns
        self._check_sql_injection()

        # Check for XSS vulnerabilities
        self._check_xss_vulnerabilities()

        # Check for missing authentication
        self._check_missing_auth()

        return self.issues

    def _run_bandit(self):
        """
        Run Bandit security scanner for Python files.
        """
        try:
            python_files = list(Path(self.repo_path).rglob("*.py"))

            if not python_files:
                return

            # Run bandit on the repository
            result = subprocess.run(
                ["bandit", "-r", self.repo_path, "-f", "json"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                bandit_results = json.loads(result.stdout)

                for result_item in bandit_results.get("results", []):
                    self.issues.append({
                        "id": f"sec-{len(self.issues)}",
                        "type": "security",
                        "severity": self._map_bandit_severity(result_item.get("issue_severity")),
                        "title": result_item.get("issue_text", "Security Issue"),
                        "description": result_item.get("issue_text", ""),
                        "location": {
                            "file": result_item.get("filename", ""),
                            "line": result_item.get("line_number", 0),
                            "column": 0
                        },
                        "auto_fix_available": True,
                        "why_ai_did_this": "AI tools often prioritize functionality over security in initial code generation.",
                        "why_its_wrong": result_item.get("issue_text", ""),
                        "how_to_prevent": "Add security constraints to your AI prompts and use security linting tools."
                    })

        except Exception as e:
            print(f"Bandit analysis failed: {e}")

    def _scan_for_secrets(self):
        """
        Scan for hardcoded secrets, API keys, passwords.
        """
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
            (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
            (r'secret[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded secret key"),
            (r'token\s*=\s*["\'][^"\']+["\']', "Hardcoded token"),
            (r'aws[_-]?access[_-]?key', "AWS access key"),
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key pattern"),
        ]

        for file_path in Path(self.repo_path).rglob("*"):
            if file_path.is_file() and not self._should_ignore(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            for pattern, description in secret_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    self.issues.append({
                                        "id": f"sec-{len(self.issues)}",
                                        "type": "security",
                                        "severity": "critical",
                                        "title": f"{description} detected",
                                        "description": f"Found potential {description.lower()} in code. Secrets should be in environment variables.",
                                        "location": {
                                            "file": str(file_path),
                                            "line": line_num,
                                            "column": 0
                                        },
                                        "auto_fix_available": True,
                                        "why_ai_did_this": "AI generates working code quickly and may include example credentials.",
                                        "why_its_wrong": "Hardcoded secrets can be exposed in version control and cause security breaches.",
                                        "how_to_prevent": "Use environment variables and .env files. Never commit secrets to git."
                                    })
                except Exception as e:
                    pass

    def _check_sql_injection(self):
        """
        Check for SQL injection vulnerabilities.
        """
        sql_patterns = [
            (r'\.raw\([^)]*f["\']', "String interpolation in raw SQL query"),
            (r'execute\([^)]*%\s*[^)]*\)', "String formatting in SQL execute"),
            (r'SELECT.*\+.*WHERE', "String concatenation in SQL query"),
        ]

        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern, description in sql_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.issues.append({
                                    "id": f"sec-{len(self.issues)}",
                                    "type": "security",
                                    "severity": "critical",
                                    "title": "SQL Injection Vulnerability",
                                    "description": f"{description}. Use parameterized queries instead.",
                                    "location": {
                                        "file": str(file_path),
                                        "line": line_num,
                                        "column": 0
                                    },
                                    "auto_fix_available": True,
                                    "why_ai_did_this": "String interpolation is the quickest way to show SQL in examples.",
                                    "why_its_wrong": "Attackers can inject malicious SQL to access or delete data.",
                                    "how_to_prevent": "Always use ORM or parameterized queries. Validate all user input."
                                })
            except Exception as e:
                pass

    def _check_xss_vulnerabilities(self):
        """
        Check for potential XSS vulnerabilities in templates/frontend.
        """
        xss_patterns = [
            (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML usage"),
            (r'\.html\([^)]*\)', "jQuery .html() with user input"),
            (r'innerHTML\s*=', "Direct innerHTML assignment"),
        ]

        for file_path in Path(self.repo_path).rglob("*"):
            if file_path.suffix in ['.jsx', '.tsx', '.js', '.ts', '.html']:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line_num, line in enumerate(f, 1):
                            for pattern, description in xss_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    self.issues.append({
                                        "id": f"sec-{len(self.issues)}",
                                        "type": "security",
                                        "severity": "high",
                                        "title": "Potential XSS Vulnerability",
                                        "description": f"{description}. Ensure user input is sanitized.",
                                        "location": {
                                            "file": str(file_path),
                                            "line": line_num,
                                            "column": 0
                                        },
                                        "auto_fix_available": True,
                                        "why_ai_did_this": "AI focuses on functionality and may skip input sanitization.",
                                        "why_its_wrong": "Unsanitized user input can execute malicious JavaScript in browsers.",
                                        "how_to_prevent": "Sanitize all user input. Use framework-provided safe rendering methods."
                                    })
                except Exception as e:
                    pass

    def _check_missing_auth(self):
        """
        Check for API routes without authentication.
        """
        # This is a simplified check - would be more sophisticated in production
        api_route_patterns = [
            (r'@app\.route\([^)]+\)', "Flask route without auth decorator"),
            (r'@api\.get\(|@api\.post\(', "FastAPI route without auth dependency"),
        ]

        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        for pattern, description in api_route_patterns:
                            if re.search(pattern, line):
                                # Check if there's an auth decorator in previous lines
                                has_auth = False
                                for prev_line in lines[max(0, line_num-5):line_num]:
                                    if re.search(r'@require_auth|@login_required|@Depends.*auth', prev_line):
                                        has_auth = True
                                        break

                                if not has_auth:
                                    self.issues.append({
                                        "id": f"sec-{len(self.issues)}",
                                        "type": "security",
                                        "severity": "high",
                                        "title": "Missing Authentication",
                                        "description": "API route without authentication check.",
                                        "location": {
                                            "file": str(file_path),
                                            "line": line_num,
                                            "column": 0
                                        },
                                        "auto_fix_available": True,
                                        "why_ai_did_this": "AI generates basic working endpoints without security layers.",
                                        "why_its_wrong": "Unauthenticated routes expose sensitive data and operations.",
                                        "how_to_prevent": "Add authentication decorators to all protected routes."
                                    })
            except Exception as e:
                pass

    def _should_ignore(self, file_path: Path) -> bool:
        """
        Check if file should be ignored during scanning.
        """
        ignore_patterns = [
            'node_modules', '.git', '__pycache__', 'venv', '.env',
            'dist', 'build', '.next', 'coverage'
        ]

        return any(pattern in str(file_path) for pattern in ignore_patterns)

    def _map_bandit_severity(self, severity: str) -> str:
        """
        Map Bandit severity levels to our severity levels.
        """
        mapping = {
            "HIGH": "critical",
            "MEDIUM": "high",
            "LOW": "medium"
        }
        return mapping.get(severity, "medium")
