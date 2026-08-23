"""
Service layer for RiskAnalyser ML evaluation.
"""

import os
import json
import joblib
import logging
from pathlib import Path
from typing import Callable, List, Optional

from watcher.models import EventData
from watcher.hardware_telemetry import global_telemetry_collector
from RiskAnalyser.models import RiskResult

logger = logging.getLogger("riskanalyser.service")

class RiskAnalyserService:
    def __init__(self, model_path: str = None, threshold: float = 44.0, telemetry_collector=None):
        if model_path is None:
            model_path = str(Path(__file__).parent / "models" / "trinetra_riskanalyser_model.pkl")
            
        self.model_path = Path(model_path)
        self.threshold = threshold
        self.model = None
        self.telemetry_collector = telemetry_collector or global_telemetry_collector
        self.callbacks = []
        self._load_model()

    def _load_model(self):
        if self.model_path.exists():
            try:
                import sklearn
                self.model = joblib.load(self.model_path)
                logger.info("Successfully loaded ML model from %s", self.model_path)
                
                # Load feature names
                features_json_path = self.model_path.parent / "trinetra_riskanalyser_features.json"
                if features_json_path.exists():
                    with open(features_json_path, "r") as f:
                        meta = json.load(f)
                        self.feature_names = meta.get("features", [])
                else:
                    self.feature_names = []
            except Exception as e:
                logger.error("Failed to load model: %s", e)
        else:
            logger.warning("ML model not found at %s. Inference will return 0.", self.model_path)

    def add_callback(self, cb: Callable[[RiskResult], None]):
        self.callbacks.append(cb)

    def evaluate_event(self, event: EventData) -> RiskResult:
        # Obtain current model-compatible behavioral telemetry for the last 10 seconds
        features = self.telemetry_collector.get_feature_vector(window_duration=10.0)
        
        prob = 0.0
        if self.model is not None:
            try:
                # Reshape to DataFrame if we have feature names to satisfy scikit-learn
                if getattr(self, "feature_names", None):
                    import pandas as pd
                    features_df = pd.DataFrame([features], columns=self.feature_names)
                    probas = self.model.predict_proba(features_df)
                else:
                    probas = self.model.predict_proba([features])
                # Assuming class 1 represents ransomware
                if len(probas[0]) > 1:
                    prob = float(probas[0][1])
                else:
                    prob = float(probas[0][0])
            except Exception as e:
                logger.error("Error during ML predict_proba: %s", e)
                prob = 0.0
                
        risk_score = prob * 100.0
        threshold_met = risk_score >= self.threshold
        
        gatekeeper_ctx = event.metadata.get("gatekeeper_screening", {})
        
        result = RiskResult(
            event_id=event.event_id,
            timestamp=event.timestamp,
            ransomware_probability=prob,
            risk_score=risk_score,
            threshold_met=threshold_met,
            gatekeeper_context=gatekeeper_ctx,
            watchdog_context=event.to_dict(),
            features=features
        )
        
        for cb in self.callbacks:
            try:
                cb(result)
            except Exception as e:
                logger.error("Error in RiskResult callback: %s", e)
                
        return result
