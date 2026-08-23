"""
Combines the ML Analyzer's raw risk_score with the Policy Engine's own
rule-based behavioral score to produce a final, explainable risk score.

Design rationale (see spec section 3 - "do NOT rely only on the score"):
    final_score = max(ml_risk_score, rule_based_score)

Taking the max means a low ML score cannot mask a set of behaviors that
independently look like ransomware, while a high ML score is never
diluted by a quiet rule engine. Every contributing rule is still
reported to keep the decision explainable.
"""
from __future__ import annotations

from typing import Tuple, List
from .models import BehavioralSignal
from .rules import evaluate_rules


def compute_final_score(sig: BehavioralSignal) -> Tuple[int, List[str], dict]:
    rule_points, reasons, breakdown = evaluate_rules(sig)

    # Rule points are additive "evidence" points, not a 0-100 score by
    # themselves; cap at 100 for display/combination purposes.
    rule_based_score = min(rule_points, 100)

    ml_score = max(0, min(100, sig.risk_score))

    final_score = max(ml_score, rule_based_score)

    score_breakdown = {
        "ml_analyzer_score": ml_score,
        "rule_based_score": rule_based_score,
        "final_score": final_score,
        "rule_contributions": breakdown,
    }

    if not reasons:
        reasons = ["No significant behavioral indicators detected"]

    return final_score, reasons, score_breakdown
