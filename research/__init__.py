"""
Code Archaeologist - Academic Research Validation

This module contains academic research that validates the core thesis:
AI-generated code systematically reproduces legacy security vulnerabilities
from training data (2008-2024).

Source: "The Generative Code Security Crisis: Mapping Legacy OWASP
Vulnerabilities (2015-2025) Inherited by Large Language Models"
"""

__version__ = "1.0.0"

from .academic_validation import (
    ACADEMIC_VALIDATION,
    LLM_TRAINING_PARADOX,
    HIGH_FREQUENCY_CWES,
    OWASP_EVOLUTION,
    TRAINING_ERAS,
    VELOCITY_MISMATCH,
    get_cwe_research,
    get_training_era,
    explain_why_ai_generates
)

__all__ = [
    'ACADEMIC_VALIDATION',
    'LLM_TRAINING_PARADOX',
    'HIGH_FREQUENCY_CWES',
    'OWASP_EVOLUTION',
    'TRAINING_ERAS',
    'VELOCITY_MISMATCH',
    'get_cwe_research',
    'get_training_era',
    'explain_why_ai_generates'
]
