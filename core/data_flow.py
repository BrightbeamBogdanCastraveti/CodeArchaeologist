"""
Module: data_flow.py
Author: Code Archaeologist Team
Purpose: Track data flow through code to detect taint propagation.

This module performs data flow analysis to track:
- User input sources (request parameters, form data, etc.)
- How data flows through the application
- Where untrusted data is used in sensitive operations
"""

import ast
import logging
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from enum import Enum


logger = logging.getLogger(__name__)


class TaintLevel(Enum):
    """Levels of data taint"""
    UNTRUSTED = "untrusted"  # Direct user input
    PARTIALLY_VALIDATED = "partially_validated"  # Some validation applied
    SANITIZED = "sanitized"  # Properly sanitized
    TRUSTED = "trusted"  # From trusted source


class DataSource(Enum):
    """Sources of data"""
    USER_INPUT = "user_input"  # HTTP request, form, query params
    DATABASE = "database"  # Database query result
    FILE_SYSTEM = "file_system"  # File read
    EXTERNAL_API = "external_api"  # External API call
    ENVIRONMENT = "environment"  # Environment variables
    HARDCODED = "hardcoded"  # Hardcoded in source


@dataclass
class TaintedData:
    """
    Represents tainted (potentially unsafe) data.

    Attributes:
        variable_name: Name of the variable
        taint_level: Level of taint
        source: Where the data came from
        source_location: Code location where it was introduced
        flow_path: Path the data took through the code
        operations: Operations performed on the data
        sinks: Where the data is used (DB query, template, etc.)
    """
    variable_name: str
    taint_level: TaintLevel
    source: DataSource
    source_location: Dict[str, any]
    flow_path: List[str] = field(default_factory=list)
    operations: List[str] = field(default_factory=list)
    sinks: List[Dict[str, any]] = field(default_factory=list)


class DataFlowAnalyzer:
    """
    Analyzes data flow through code to track tainted data.

    This is crucial for detecting vulnerabilities where user input
    flows to dangerous sinks (SQL queries, templates, command execution).
    """

    # Taint sources (where untrusted data comes from)
    TAINT_SOURCES = {
        # Django
        "request.GET": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
        "request.POST": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
        "request.body": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
        "request.FILES": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
        "request.META": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
        # Flask
        "request.args": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
        "request.form": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
        "request.json": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
        # FastAPI
        "Request": (DataSource.USER_INPUT, TaintLevel.UNTRUSTED),
    }

    # Dangerous sinks (where tainted data causes vulnerabilities)
    DANGEROUS_SINKS = {
        # SQL execution
        "execute": "sql_injection",
        "raw": "sql_injection",
        "executemany": "sql_injection",
        # Command execution
        "system": "command_injection",
        "popen": "command_injection",
        "exec": "code_injection",
        "eval": "code_injection",
        # File operations
        "open": "path_traversal",
        "read": "path_traversal",
        # Template rendering
        "mark_safe": "xss",
        "dangerouslySetInnerHTML": "xss",
    }

    # Sanitization functions
    SANITIZERS = {
        "escape": TaintLevel.SANITIZED,
        "escapejs": TaintLevel.SANITIZED,
        "bleach.clean": TaintLevel.SANITIZED,
        "DOMPurify.sanitize": TaintLevel.SANITIZED,
        "int": TaintLevel.PARTIALLY_VALIDATED,
        "float": TaintLevel.PARTIALLY_VALIDATED,
        "str.isdigit": TaintLevel.PARTIALLY_VALIDATED,
    }

    def __init__(self):
        """Initialize data flow analyzer"""
        self.tainted_variables: Dict[str, TaintedData] = {}
        self.flow_graph: Dict[str, List[str]] = {}

    def analyze_file(self, file_path: str, source_code: str) -> List[Dict]:
        """
        Analyze data flow in a source file.

        Args:
            file_path: Path to the file
            source_code: Source code content

        Returns:
            List of data flow issues detected
        """
        try:
            tree = ast.parse(source_code)
            visitor = DataFlowVisitor(self)
            visitor.visit(tree)

            # Find dangerous data flows
            issues = self._find_dangerous_flows()

            return issues

        except SyntaxError as e:
            logger.error(f"Syntax error in {file_path}: {e}")
            return []

    def track_tainted_variable(
        self,
        var_name: str,
        source: DataSource,
        taint_level: TaintLevel,
        location: Dict,
    ):
        """
        Track a tainted variable.

        Args:
            var_name: Variable name
            source: Data source
            taint_level: Taint level
            location: Code location
        """
        self.tainted_variables[var_name] = TaintedData(
            variable_name=var_name,
            taint_level=taint_level,
            source=source,
            source_location=location,
        )

    def propagate_taint(self, from_var: str, to_var: str, operation: str):
        """
        Propagate taint from one variable to another.

        Args:
            from_var: Source variable
            to_var: Destination variable
            operation: Operation performed
        """
        if from_var in self.tainted_variables:
            tainted = self.tainted_variables[from_var]

            # Create new tainted variable
            self.tainted_variables[to_var] = TaintedData(
                variable_name=to_var,
                taint_level=tainted.taint_level,
                source=tainted.source,
                source_location=tainted.source_location,
                flow_path=tainted.flow_path + [from_var],
                operations=tainted.operations + [operation],
            )

    def apply_sanitization(self, var_name: str, sanitizer: str):
        """
        Apply sanitization to a variable.

        Args:
            var_name: Variable name
            sanitizer: Sanitization function used
        """
        if var_name in self.tainted_variables:
            new_taint_level = self.SANITIZERS.get(sanitizer, TaintLevel.PARTIALLY_VALIDATED)
            self.tainted_variables[var_name].taint_level = new_taint_level
            self.tainted_variables[var_name].operations.append(f"sanitized:{sanitizer}")

    def record_sink_usage(self, var_name: str, sink: str, location: Dict):
        """
        Record use of tainted variable in a dangerous sink.

        Args:
            var_name: Variable name
            sink: Sink function/operation
            location: Code location
        """
        if var_name in self.tainted_variables:
            self.tainted_variables[var_name].sinks.append({
                "sink": sink,
                "location": location,
            })

    def _find_dangerous_flows(self) -> List[Dict]:
        """
        Find dangerous data flows (untrusted data to dangerous sinks).

        Returns:
            List of dangerous flow issues
        """
        issues = []

        for var_name, tainted in self.tainted_variables.items():
            # Only report if data is still tainted and used in a sink
            if tainted.taint_level in [TaintLevel.UNTRUSTED, TaintLevel.PARTIALLY_VALIDATED]:
                for sink_usage in tainted.sinks:
                    sink = sink_usage["sink"]
                    vulnerability_type = self.DANGEROUS_SINKS.get(sink)

                    if vulnerability_type:
                        issues.append({
                            "type": vulnerability_type,
                            "variable": var_name,
                            "source": tainted.source.value,
                            "taint_level": tainted.taint_level.value,
                            "sink": sink,
                            "flow_path": tainted.flow_path,
                            "operations": tainted.operations,
                            "location": sink_usage["location"],
                            "source_location": tainted.source_location,
                        })

        return issues


class DataFlowVisitor(ast.NodeVisitor):
    """AST visitor for tracking data flow"""

    def __init__(self, analyzer: DataFlowAnalyzer):
        """
        Initialize visitor.

        Args:
            analyzer: DataFlowAnalyzer instance
        """
        self.analyzer = analyzer

    def visit_Assign(self, node: ast.Assign):
        """Visit assignment nodes"""
        # Check if right side is a taint source
        if isinstance(node.value, ast.Attribute):
            attr_name = self._get_full_attribute_name(node.value)

            if attr_name in self.analyzer.TAINT_SOURCES:
                source, taint_level = self.analyzer.TAINT_SOURCES[attr_name]

                # Track all targets of this assignment
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.analyzer.track_tainted_variable(
                            var_name=target.id,
                            source=source,
                            taint_level=taint_level,
                            location={
                                "line": node.lineno,
                                "col": node.col_offset,
                            },
                        )

        # Check for taint propagation
        if isinstance(node.value, ast.Name):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.analyzer.propagate_taint(
                        from_var=node.value.id,
                        to_var=target.id,
                        operation="assignment",
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Visit function call nodes"""
        func_name = self._get_function_name(node.func)

        # Check for dangerous sinks
        if func_name in self.analyzer.DANGEROUS_SINKS:
            # Check if any arguments are tainted
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    self.analyzer.record_sink_usage(
                        var_name=arg.id,
                        sink=func_name,
                        location={
                            "line": node.lineno,
                            "col": node.col_offset,
                        },
                    )

        # Check for sanitization
        if func_name in self.analyzer.SANITIZERS:
            if node.args and isinstance(node.args[0], ast.Name):
                self.analyzer.apply_sanitization(
                    var_name=node.args[0].id,
                    sanitizer=func_name,
                )

        self.generic_visit(node)

    def _get_full_attribute_name(self, node: ast.Attribute) -> str:
        """Get full dotted attribute name"""
        parts = []
        current = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        return ".".join(reversed(parts))

    def _get_function_name(self, node) -> str:
        """Get function name from call node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""
