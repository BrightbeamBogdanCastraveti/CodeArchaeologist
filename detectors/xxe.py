"""
XML External Entity (XXE) Detector (CWE-611)

Detects XXE vulnerabilities in document parsing (DOCX, PDF, XML).

OWASP: A05:2021 - Security Misconfiguration
Zero Trust Reference: Section IV.C "XXE in Document Parsing"
Research: "Zero Trust Email Ingestion Blueprint" (2025)

Attack Vector:
    Attacker uploads CV with malicious XML:
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    Result: Server reads local files and returns in error message

HBOSS Impact: CV parsing vulnerable to:
- Local file disclosure (/etc/passwd, database.yml)
- SSRF to internal services
- Denial of Service
"""

import ast
import re
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class XXEFinding:
    """A detected XXE vulnerability."""
    line: int
    column: int
    code_snippet: str
    severity: str
    confidence: int
    description: str
    parser_type: str
    cwe_id: str = "CWE-611"
    owasp_category: str = "A05:2021 - Security Misconfiguration"

    def to_dict(self) -> Dict:
        """Convert to dictionary format for scanner."""
        return {
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'severity': self.severity,
            'confidence': self.confidence,
            'message': self.description,
            'parser_type': self.parser_type,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'hboss_impact': 'CV parsing vulnerable to file disclosure and SSRF',
            'fix': self._get_fix_example()
        }

    def _get_fix_example(self) -> str:
        return """
SECURE IMPLEMENTATION:
```python
# Use defusedxml instead of standard library
from defusedxml import ElementTree as ET

def parse_cv_xml_secure(xml_file):
    # defusedxml automatically disables XXE
    tree = ET.parse(xml_file)
    return tree.getroot()

# For lxml (if you must use it):
from lxml import etree

def parse_with_lxml_secure(xml_file):
    parser = etree.XMLParser(
        resolve_entities=False,  # Disable entity resolution
        no_network=True,         # Disable network access
        dtd_validation=False,    # Disable DTD validation
        load_dtd=False           # Don't load DTD
    )
    tree = etree.parse(xml_file, parser)
    return tree

# For DOCX parsing:
def parse_docx_secure(docx_file):
    import zipfile
    from defusedxml import ElementTree as ET

    with zipfile.ZipFile(docx_file) as zf:
        # Extract and parse with defusedxml
        xml_content = zf.read('word/document.xml')
        tree = ET.fromstring(xml_content)
    return tree
```
Reference: Zero Trust Email Ingestion Blueprint, Section IV.C
        """


class XXEDetector:
    """
    Detects XML External Entity (XXE) vulnerabilities.

    Per "Zero Trust Email Ingestion Blueprint":
    "XML parsers must be configured to disable external entity resolution
    and DTD processing. Use defusedxml for Python."
    """

    # Vulnerable XML parsing functions
    VULNERABLE_PARSERS = {
        # Python standard library (vulnerable by default)
        'xml.etree.ElementTree': ['parse', 'fromstring', 'XML'],
        'xml.dom.minidom': ['parse', 'parseString'],
        'xml.sax': ['parse', 'parseString'],
        'lxml.etree': ['parse', 'fromstring', 'XML', 'XMLParser'],

        # Document libraries that parse XML internally
        'python-docx': ['Document'],  # DOCX files contain XML
        'PyPDF2': ['PdfFileReader', 'PdfReader'],
        'openpyxl': ['load_workbook'],
    }

    # Safe alternatives
    SAFE_PARSERS = [
        'defusedxml',
        'defusedxml.ElementTree',
        'defusedxml.minidom',
    ]

    def __init__(self):
        self.findings = []

    def detect(self, file_content: str, file_path: str) -> List[Dict]:
        """
        Main detection method.

        Checks for:
        1. Use of unsafe XML parsers (AST analysis)
        2. Missing XXE protections (pattern matching)
        3. Document parsing without defusedxml
        """
        self.findings = []

        if file_path.endswith('.py'):
            self.findings.extend(self._detect_python_xxe(file_content, file_path))

        # Generic pattern detection
        self.findings.extend(self._detect_generic_patterns(file_content, file_path))

        # Convert findings to dict format
        return [f.to_dict() for f in self.findings]

    def _detect_python_xxe(self, content: str, file_path: str) -> List[XXEFinding]:
        """
        AST-based detection for Python code.

        Looks for:
        - xml.etree.ElementTree.parse() without XXE protection
        - lxml without secure parser configuration
        - Document parsing (DOCX, PDF) without defusedxml
        """
        findings = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        # Track imports
        unsafe_imports = self._find_unsafe_imports(tree)

        # Check for unsafe XML parsing calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_xml_parser_call(node, content, unsafe_imports)
                if finding:
                    findings.append(finding)

        return findings

    def _find_unsafe_imports(self, tree: ast.AST) -> Dict[str, str]:
        """
        Find all unsafe XML parser imports.

        Returns dict mapping: {alias: full_module_path}
        """
        unsafe_imports = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
                    name = alias.asname if alias.asname else alias.name

                    # Check if this is a vulnerable parser
                    for vuln_module in self.VULNERABLE_PARSERS.keys():
                        if module.startswith(vuln_module):
                            unsafe_imports[name] = module

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for vuln_module in self.VULNERABLE_PARSERS.keys():
                        if node.module.startswith(vuln_module):
                            for alias in node.names:
                                name = alias.asname if alias.asname else alias.name
                                unsafe_imports[name] = f"{node.module}.{alias.name}"

        return unsafe_imports

    def _check_xml_parser_call(self, node: ast.Call, content: str,
                               unsafe_imports: Dict) -> XXEFinding:
        """
        Check if this call uses an unsafe XML parser.
        """
        # Check direct calls to known vulnerable functions
        if isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr

            # Check if this is a vulnerable parser method
            for parser_module, methods in self.VULNERABLE_PARSERS.items():
                if attr_name in methods:
                    # Check if the object is from an unsafe import
                    if isinstance(node.func.value, ast.Name):
                        obj_name = node.func.value.id
                        if obj_name in unsafe_imports:
                            return XXEFinding(
                                line=node.lineno,
                                column=node.col_offset,
                                code_snippet=ast.get_source_segment(content, node) or '',
                                severity='HIGH',
                                confidence=90,
                                description=f'XXE vulnerability: Using unsafe XML parser {parser_module}.{attr_name}()',
                                parser_type=parser_module
                            )

        # Check direct function calls like parse() if imported directly
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in unsafe_imports:
                module = unsafe_imports[func_name]
                return XXEFinding(
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=ast.get_source_segment(content, node) or '',
                    severity='HIGH',
                    confidence=85,
                    description=f'XXE vulnerability: Using unsafe parser {module}',
                    parser_type=module
                )

        return None

    def _detect_generic_patterns(self, content: str, file_path: str) -> List[XXEFinding]:
        """
        Pattern-based detection that works across languages.

        Detects:
        - XML parsing without defusedxml
        - Document parsing (DOCX, PDF, XLSX) without protection
        - Missing XXE protection configurations
        """
        findings = []
        lines = content.split('\n')

        # Pattern 1: Unsafe XML parsing
        unsafe_xml_parse = re.compile(
            r'(ElementTree|etree|minidom|xml\.dom)\.(parse|fromstring|XML)\(',
            re.IGNORECASE
        )

        # Pattern 2: Document parsing that might contain XML
        unsafe_doc_parse = re.compile(
            r'(Document\(|PdfFileReader\(|load_workbook\()',
            re.IGNORECASE
        )

        # Pattern 3: Check if defusedxml is imported
        has_defusedxml = re.search(r'from defusedxml|import defusedxml', content)

        for i, line in enumerate(lines, 1):
            # Check for unsafe XML parsing
            if unsafe_xml_parse.search(line):
                # Check if this line has XXE protection
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if not self._has_xxe_protection(context):
                    findings.append(XXEFinding(
                        line=i,
                        column=0,
                        code_snippet=line.strip(),
                        severity='HIGH',
                        confidence=85,
                        description='XXE vulnerability: XML parsing without defusedxml or XXE protection',
                        parser_type='xml_parser'
                    ))

            # Check for document parsing without defusedxml
            if unsafe_doc_parse.search(line) and not has_defusedxml:
                findings.append(XXEFinding(
                    line=i,
                    column=0,
                    code_snippet=line.strip(),
                    severity='MEDIUM',
                    confidence=75,
                    description='Potential XXE: Document parsing without defusedxml (DOCX/PDF contain XML)',
                    parser_type='document_parser'
                ))

        return findings

    def _has_xxe_protection(self, code_context: str) -> bool:
        """
        Check if code has XXE protection.

        Looks for:
        - defusedxml import
        - resolve_entities=False
        - XMLParser configuration
        """
        protection_patterns = [
            r'defusedxml',
            r'resolve_entities\s*=\s*False',
            r'no_network\s*=\s*True',
            r'load_dtd\s*=\s*False',
            r'XMLParser\([^)]*resolve_entities\s*=\s*False',
        ]

        for pattern in protection_patterns:
            if re.search(pattern, code_context, re.IGNORECASE):
                return True

        return False
