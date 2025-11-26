"""
Copy-Paste Detector

Detects duplicated vulnerable code patterns from fast AI iteration:
- Similar code blocks across files
- Duplicated vulnerable patterns
- Copy-paste artifacts (similar comments, variable names)
- Fast iteration signatures (v1, v2, _old, _new suffixes)
- Repeated security mistakes

Vibe Coding Pattern: AI generates similar solutions repeatedly, copying vulnerabilities.

Research: 65% of AI-generated codebases have duplicated vulnerable patterns
Training Era: 2022-2024
Common in: Rapid prototyping, multi-file generation

Patterns:
1. Same SQL injection pattern in 5 different endpoints
2. Functions named endpoint_v1, endpoint_v2, endpoint_final
3. Identical try/except blocks (or lack thereof)
4. Copied authentication logic with same flaws
"""

import ast
import re
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
import hashlib


@dataclass
class CopyPasteFinding:
    """A detected copy-paste pattern."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    duplication_type: str
    similar_to: str
    cwe_id: str = "CWE-1041"
    owasp_category: str = "Vibe Coding - Copy-Paste"

    def to_dict(self) -> Dict:
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'duplication_type': self.duplication_type,
            'similar_to': self.similar_to,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'fix': 'Refactor duplicated code, extract common patterns, use inheritance/composition'
        }


class CopyPasteDetector:
    """Detects copy-paste patterns in AI-generated code."""

    # Fast iteration suffixes
    ITERATION_SUFFIXES = [
        '_v1', '_v2', '_v3', '_v4', '_old', '_new',
        '_backup', '_copy', '_temp', '_final', '_test',
        '2', '3', 'Copy', 'NEW', 'OLD'
    ]

    def __init__(self):
        self.findings = []
        self.function_hashes = defaultdict(list)  # hash -> [(name, lineno)]
        self.code_blocks = []  # Store all code blocks for similarity checking

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        self.findings = []
        self.function_hashes = defaultdict(list)
        self.code_blocks = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_copy_paste(file_content, file_path))

        return [f.to_dict() for f in self.findings]

    def _detect_python_copy_paste(self, content: str, file_path: str) -> List[CopyPasteFinding]:
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines = content.split('\n')

        # Collect all functions and their hashes
        self._collect_function_hashes(tree, content)

        # Check for fast iteration suffixes
        findings.extend(self._check_iteration_naming(tree, lines))

        # Check for duplicate functions
        findings.extend(self._check_duplicate_functions(lines))

        # Check for similar code blocks
        findings.extend(self._check_similar_blocks(tree, content, lines))

        return findings

    def _collect_function_hashes(self, tree: ast.AST, content: str):
        """Collect hashes of all function bodies for similarity detection."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Get normalized function body (remove names, keep structure)
                normalized = self._normalize_function(node, content)
                if normalized:
                    func_hash = hashlib.md5(normalized.encode()).hexdigest()
                    self.function_hashes[func_hash].append((node.name, node.lineno))

    def _check_iteration_naming(self, tree: ast.AST, lines: List[str]) -> List[CopyPasteFinding]:
        """Detect fast iteration naming patterns (func_v1, func_v2, etc.)."""
        findings = []

        function_names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                function_names.append((node.name, node.lineno))

        # Group by base name
        base_names = defaultdict(list)
        for name, lineno in function_names:
            # Remove iteration suffixes
            base_name = name
            for suffix in self.ITERATION_SUFFIXES:
                if name.endswith(suffix):
                    base_name = name[:-len(suffix)]
                    break

            base_names[base_name].append((name, lineno))

        # Flag if we have multiple versions
        for base_name, versions in base_names.items():
            if len(versions) >= 2:
                findings.append(CopyPasteFinding(
                    line=versions[0][1],
                    column=0,
                    code_snippet=f'Functions: {", ".join(v[0] for v in versions)}',
                    severity='MEDIUM',
                    confidence=85,
                    description=f'Multiple versions of "{base_name}" ({len(versions)} variants) - fast iteration artifact',
                    duplication_type='versioned_functions',
                    similar_to=', '.join(v[0] for v in versions[1:])
                ))

        return findings

    def _check_duplicate_functions(self, lines: List[str]) -> List[CopyPasteFinding]:
        """Detect functions with identical or nearly identical implementations."""
        findings = []

        for func_hash, functions in self.function_hashes.items():
            if len(functions) >= 2:
                # Multiple functions with same hash = duplicates
                main_func = functions[0]
                duplicates = functions[1:]

                findings.append(CopyPasteFinding(
                    line=main_func[1],
                    column=0,
                    code_snippet=lines[main_func[1] - 1].strip()[:100],
                    severity='HIGH',
                    confidence=90,
                    description=f'Function "{main_func[0]}" duplicated {len(duplicates)} times (copy-paste)',
                    duplication_type='identical_functions',
                    similar_to=', '.join(f[0] for f in duplicates)
                ))

        return findings

    def _check_similar_blocks(self, tree: ast.AST, content: str, lines: List[str]) -> List[CopyPasteFinding]:
        """Detect similar code blocks that suggest copy-paste."""
        findings = []

        # Collect all if/for/while blocks
        blocks = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.For, ast.While)):
                block_code = ast.get_source_segment(content, node)
                if block_code and len(block_code) > 50:  # Significant block
                    normalized = self._normalize_code(block_code)
                    blocks.append((normalized, node.lineno, block_code[:100]))

        # Check for similar blocks
        seen_hashes = defaultdict(list)
        for normalized, lineno, snippet in blocks:
            block_hash = hashlib.md5(normalized.encode()).hexdigest()
            seen_hashes[block_hash].append((lineno, snippet))

        for block_hash, occurrences in seen_hashes.items():
            if len(occurrences) >= 2:
                findings.append(CopyPasteFinding(
                    line=occurrences[0][0],
                    column=0,
                    code_snippet=occurrences[0][1],
                    severity='MEDIUM',
                    confidence=75,
                    description=f'Similar code block appears {len(occurrences)} times (lines: {", ".join(str(o[0]) for o in occurrences)})',
                    duplication_type='repeated_blocks',
                    similar_to=f'Lines: {", ".join(str(o[0]) for o in occurrences[1:])}'
                ))

        return findings

    def _normalize_function(self, func_node: ast.FunctionDef, content: str) -> str:
        """
        Normalize function body to detect structural similarity.

        Removes:
        - Variable names
        - Comments
        - Whitespace differences

        Keeps:
        - Control flow structure
        - Operation types
        - Function calls
        """
        func_source = ast.get_source_segment(content, func_node)
        if not func_source:
            return ''

        # Remove comments
        normalized = re.sub(r'#.*$', '', func_source, flags=re.MULTILINE)

        # Remove docstrings
        normalized = re.sub(r'""".*?"""', '', normalized, flags=re.DOTALL)
        normalized = re.sub(r"'''.*?'''", '', normalized, flags=re.DOTALL)

        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized)

        # Remove specific variable names (replace with placeholder)
        normalized = re.sub(r'\b[a-z_][a-z0-9_]*\b', 'VAR', normalized)

        return normalized.strip()

    def _normalize_code(self, code: str) -> str:
        """Normalize code block for similarity detection."""
        # Remove comments
        normalized = re.sub(r'#.*$', '', code, flags=re.MULTILINE)

        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized)

        # Replace variable names with placeholder
        normalized = re.sub(r'\b[a-z_][a-z0-9_]*\b', 'VAR', normalized)

        return normalized.strip()
