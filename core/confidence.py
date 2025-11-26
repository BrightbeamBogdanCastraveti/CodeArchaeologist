"""
Module: confidence.py
Author: Code Archaeologist Team
Purpose: Confidence scoring system for vulnerability detections.

Every finding must have a confidence score (0-100) to help developers
prioritize and understand the reliability of the detection.
"""

import logging
from typing import Dict, List
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class ConfidenceFactors:
    """
    Factors that influence confidence scoring.

    Attributes:
        base_score: Base confidence from pattern
        context_bonus: Bonus from surrounding code context
        false_positive_penalty: Penalty if FP indicators present
        framework_match_bonus: Bonus if framework matches
        multiple_indicators_bonus: Bonus if multiple patterns match
    """
    base_score: int
    context_bonus: int = 0
    false_positive_penalty: int = 0
    framework_match_bonus: int = 0
    multiple_indicators_bonus: int = 0

    def calculate_final_score(self) -> int:
        """Calculate final confidence score (0-100)"""
        score = (
            self.base_score
            + self.context_bonus
            + self.framework_match_bonus
            + self.multiple_indicators_bonus
            - self.false_positive_penalty
        )
        return max(0, min(100, score))  # Clamp to 0-100


class ConfidenceScorer:
    """
    Calculates confidence scores for vulnerability detections.

    Confidence scoring helps users understand:
    - How sure we are about the finding
    - Whether it's worth investigating
    - Priority for fixing
    """

    # Confidence thresholds
    HIGH_CONFIDENCE = 80  # Very likely a real issue
    MEDIUM_CONFIDENCE = 60  # Probably an issue
    LOW_CONFIDENCE = 40  # Might be an issue

    def __init__(self):
        """Initialize the confidence scorer"""
        self.scoring_rules = self._initialize_scoring_rules()

    def _initialize_scoring_rules(self) -> Dict:
        """Initialize confidence scoring rules"""
        return {
            "context_indicators": {
                "has_test": -10,  # Less likely to be real issue if tested
                "in_comment": -20,  # Likely example code
                "in_docstring": -25,  # Definitely example code
                "has_validation": +15,  # Validation attempt (but might be broken)
                "user_input_source": +20,  # Direct user input increases risk
                "framework_specific": +10,  # Framework-specific patterns more reliable
            },
            "false_positive_indicators": {
                "test_file": -30,  # Test files often have deliberate vulns
                "example_comment": -20,  # Commented examples
                "todo_fixme": +5,  # Developer knows it's an issue
                "security_comment": +10,  # Security-related comment
            },
        }

    def calculate_confidence(
        self,
        base_score: int,
        context: Dict,
        has_false_positive_indicators: bool = False,
    ) -> ConfidenceFactors:
        """
        Calculate confidence score for a finding.

        Args:
            base_score: Base confidence from pattern
            context: Context information about the code
            has_false_positive_indicators: Whether FP indicators are present

        Returns:
            ConfidenceFactors with detailed scoring breakdown
        """
        factors = ConfidenceFactors(base_score=base_score)

        # Analyze context
        factors.context_bonus = self._calculate_context_bonus(context)

        # Check for false positive indicators
        if has_false_positive_indicators:
            factors.false_positive_penalty = 20

        # Framework match bonus
        if context.get("framework_detected"):
            factors.framework_match_bonus = 10

        # Multiple indicators
        if context.get("multiple_patterns_matched", 0) > 1:
            factors.multiple_indicators_bonus = 5 * min(
                context.get("multiple_patterns_matched", 0), 3
            )

        logger.debug(f"Confidence calculation: {factors}")

        return factors

    def _calculate_context_bonus(self, context: Dict) -> int:
        """
        Calculate bonus/penalty from code context.

        Args:
            context: Context dictionary

        Returns:
            int: Bonus or penalty value
        """
        bonus = 0
        rules = self.scoring_rules["context_indicators"]

        for indicator, value in rules.items():
            if context.get(indicator, False):
                bonus += value

        return bonus

    def get_confidence_level(self, score: int) -> str:
        """
        Get confidence level from score.

        Args:
            score: Confidence score (0-100)

        Returns:
            str: "high", "medium", or "low"
        """
        if score >= self.HIGH_CONFIDENCE:
            return "high"
        elif score >= self.MEDIUM_CONFIDENCE:
            return "medium"
        else:
            return "low"

    def should_report(self, score: int) -> bool:
        """
        Determine if a finding should be reported based on confidence.

        Args:
            score: Confidence score

        Returns:
            bool: True if should be reported
        """
        # Report anything above low confidence
        # Even low confidence issues are worth showing with proper labeling
        return score >= 30
