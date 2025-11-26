"""
Module: architecture_analyzer.py
Author: Claude AI + Human Reviewer (Bogdan)
Purpose: Detect architecture violations and anti-patterns
"""

import os
import re
import ast
from typing import List, Dict, Set
from pathlib import Path
from collections import defaultdict


class ArchitectureAnalyzer:
    """
    Analyzes code architecture for violations and anti-patterns.
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.issues = []
        self.dependency_graph = defaultdict(set)

    def analyze(self) -> List[Dict]:
        """
        Run architecture analysis.
        """
        print(f"Running architecture analysis on {self.repo_path}")

        self._build_dependency_graph()
        self._check_circular_dependencies()
        self._check_layer_violations()
        self._check_code_duplication()

        return self.issues

    def _build_dependency_graph(self):
        """
        Build a graph of module dependencies.
        """
        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)

                    for node in ast.walk(tree):
                        if isinstance(node, (ast.Import, ast.ImportFrom)):
                            if isinstance(node, ast.Import):
                                for alias in node.names:
                                    self.dependency_graph[str(file_path)].add(alias.name)
                            elif isinstance(node, ast.ImportFrom) and node.module:
                                self.dependency_graph[str(file_path)].add(node.module)

                except SyntaxError:
                    pass

            except Exception as e:
                pass

    def _check_circular_dependencies(self):
        """
        Detect circular dependencies between modules.
        """
        visited = set()
        rec_stack = set()

        def has_cycle(node, path):
            visited.add(node)
            rec_stack.add(node)

            for neighbor in self.dependency_graph.get(node, []):
                if neighbor not in visited:
                    if has_cycle(neighbor, path + [neighbor]):
                        return True
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor) if neighbor in path else 0
                    cycle = path[cycle_start:] + [neighbor]

                    self.issues.append({
                        "id": f"arch-{len(self.issues)}",
                        "type": "architecture",
                        "severity": "high",
                        "title": "Circular dependency detected",
                        "description": f"Circular import chain: {' -> '.join([p.split('/')[-1] for p in cycle])}",
                        "location": {
                            "file": node,
                            "line": 1,
                            "column": 0
                        },
                        "auto_fix_available": False,
                        "why_ai_did_this": "AI generates code file-by-file without considering overall architecture.",
                        "why_its_wrong": "Circular dependencies make code fragile and hard to refactor.",
                        "how_to_prevent": "Design your architecture first. Use dependency injection."
                    })
                    return True

            rec_stack.remove(node)
            return False

        for node in self.dependency_graph:
            if node not in visited:
                has_cycle(node, [node])

    def _check_layer_violations(self):
        """
        Check for architectural layer violations.
        E.g., views importing from views, skipping service layer
        """
        layer_rules = {
            'views': ['services', 'models', 'utils'],  # views can import from services, models, utils
            'services': ['models', 'repositories', 'utils'],  # services can import from models, repos
            'models': ['utils'],  # models should be independent
        }

        for file_path in Path(self.repo_path).rglob("*.py"):
            file_str = str(file_path)

            # Determine layer
            current_layer = None
            for layer in layer_rules.keys():
                if f'/{layer}/' in file_str or file_str.endswith(f'{layer}.py'):
                    current_layer = layer
                    break

            if not current_layer:
                continue

            # Check imports
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)

                    for node in ast.walk(tree):
                        if isinstance(node, ast.ImportFrom) and node.module:
                            # Check if import violates layer rules
                            imported_layer = None
                            for layer in layer_rules.keys():
                                if layer in node.module:
                                    imported_layer = layer
                                    break

                            if imported_layer and imported_layer not in layer_rules[current_layer]:
                                self.issues.append({
                                    "id": f"arch-{len(self.issues)}",
                                    "type": "architecture",
                                    "severity": "medium",
                                    "title": f"Layer violation: {current_layer} importing from {imported_layer}",
                                    "description": f"Breaks clean architecture. {current_layer} should not directly import from {imported_layer}.",
                                    "location": {
                                        "file": str(file_path),
                                        "line": node.lineno,
                                        "column": node.col_offset
                                    },
                                    "auto_fix_available": False,
                                    "why_ai_did_this": "AI takes the shortest path to make code work.",
                                    "why_its_wrong": "Layer violations create tight coupling and make testing difficult.",
                                    "how_to_prevent": "Define clear architectural boundaries and enforce them."
                                })

                except SyntaxError:
                    pass

            except Exception as e:
                pass

    def _check_code_duplication(self):
        """
        Simple check for potential code duplication.
        """
        function_signatures = defaultdict(list)

        for file_path in Path(self.repo_path).rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                try:
                    tree = ast.parse(content)

                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef):
                            # Create simple signature
                            signature = f"{node.name}_{len(node.args.args)}"
                            function_signatures[signature].append({
                                'file': str(file_path),
                                'line': node.lineno,
                                'name': node.name
                            })

                except SyntaxError:
                    pass

            except Exception as e:
                pass

        # Report duplicates
        for signature, locations in function_signatures.items():
            if len(locations) > 1:
                self.issues.append({
                    "id": f"arch-{len(self.issues)}",
                    "type": "architecture",
                    "severity": "low",
                    "title": f"Potential duplicate function: {locations[0]['name']}",
                    "description": f"Function with same name and arity exists in {len(locations)} files.",
                    "location": {
                        "file": locations[0]['file'],
                        "line": locations[0]['line'],
                        "column": 0
                    },
                    "auto_fix_available": False,
                    "why_ai_did_this": "AI regenerates similar code instead of reusing existing functions.",
                    "why_its_wrong": "Duplicated code increases maintenance burden and bug surface.",
                    "how_to_prevent": "Extract common functionality into shared modules."
                })
