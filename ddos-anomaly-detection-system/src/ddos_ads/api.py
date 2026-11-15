"""FastAPI inference service with lazy model loading and 503 fallback guards."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel, Field

from ddos_ads.config import Config, load_config
from ddos_ads.features import load_selected_features
from ddos_ads.pcap_to_flows import align_flow_dataframe
from ddos_ads.utils import check_models_exist, setup_logger

logger = setup_logger("ddos_ads.api")


class FlowBatchRequest(BaseModel):
    """Batch of network flows to score."""
    model: str = Field(default="rf", description="Inference model to use: rf, knn, or lstm")
    threshold: Optional[float] = Field(default=None, description="Optional custom decision threshold")
    flows: List[Dict[str, Any]] = Field(..., description="List of raw or mapped flow dictionaries")


class FlowPrediction(BaseModel):
    """Individual flow scoring prediction result."""
    flow_index: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    anomaly_score: float
    is_anomaly: bool
    prediction_label: str


class ScoreResponse(BaseModel):
    """Response containing flow batch predictions and inference latency."""
    model_used: str
    threshold_applied: float
    total_flows: int
    anomalies_detected: int
    latency_ms: float
    predictions: List[FlowPrediction]


class ModelRegistry:
    """Manages lazy loading and caching of trained classifiers."""

    def __init__(self, models_dir: Path) -> None:
        self.models_dir = models_dir
        self.scaler = None
        self.features: Optional[List[str]] = None
        self.models: Dict[str, Any] = {}

    def ensure_ready(self, model_name: str) -> None:
        """Verify model files exist on disk, or raise HTTP 503."""
        required = ["features.json", "scaler.joblib"]
        target_file = f"{model_name}.joblib" if model_name in ("rf", "knn") else "lstm.pt"
        required.append(target_file)

        if not check_models_exist(self.models_dir, required):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Models not found. Run: make train",
            )

        if self.features is None:
            self.features = load_selected_features(self.models_dir / "features.json")
        if self.scaler is None:
            self.scaler = joblib.load(self.models_dir / "scaler.joblib")

        if model_name not in self.models:
            model_path = self.models_dir / target_file
            if model_name in ("rf", "knn"):
                self.models[model_name] = joblib.load(model_path)
            elif model_name == "lstm":
                import torch
                from ddos_ads.train_lstm import LSTMAnomalyClassifier
                checkpoint = torch.load(model_path, map_location="cpu")
                net = LSTMAnomalyClassifier(
                    input_dim=checkpoint["input_dim"],
                    hidden_dim=checkpoint["hidden_dim"],
                    num_layers=checkpoint.get("num_layers", 2),
                    dropout=0.0,
                )
                net.load_state_dict(checkpoint["model_state_dict"])
                net.eval()
                self.models[model_name] = net


def create_app(config_path: Optional[str] = None) -> FastAPI:
    """FastAPI application factory."""
    config = load_config(config_path)
    models_dir = config.get_path("models_dir")
    logs_dir = config.get_path("logs_dir")
    registry = ModelRegistry(models_dir)

    app = FastAPI(
        title="DDoS Anomaly Detection System API",
        version="0.1.0",
        description="RESTful microservice for real-time network flow anomaly scoring and alerting.",
    )

    @app.get("/health", summary="System Health & Model Status")
    def health_check() -> Dict[str, Any]:
        has_models = check_models_exist(models_dir, ["features.json", "scaler.joblib"])
        return {
            "status": "healthy",
            "models_ready": has_models,
            "models_directory": str(models_dir),
            "cached_models": list(registry.models.keys()),
            "timestamp": time.time(),
        }

    @app.post("/score", response_model=ScoreResponse, summary="Score Batch of Network Flows")
    def score_flows(req: FlowBatchRequest) -> ScoreResponse:
        model_name = req.model.lower()
        if model_name not in ("rf", "knn", "lstm"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported model: {req.model}. Choose from: rf, knn, lstm.",
            )

        # Lazy loading with 503 protection
        registry.ensure_ready(model_name)

        if not req.flows:
            return ScoreResponse(
                model_used=model_name,
                threshold_applied=0.5,
                total_flows=0,
                anomalies_detected=0,
                latency_ms=0.0,
                predictions=[],
            )

        t0 = time.perf_counter()
        raw_df = pd.DataFrame(req.flows)

        # Feature alignment and zero-filling
        features_df, meta_df = align_flow_dataframe(raw_df, registry.features)
        X_mat = features_df[registry.features].to_numpy()
        X_scaled = registry.scaler.transform(X_mat)

        # Ingestion & scoring
        thresh = req.threshold if req.threshold is not None else config.get("live_detection.threshold", 0.50)

        if model_name in ("rf", "knn"):
            scores = registry.models[model_name].predict_proba(X_scaled)[:, 1]
        elif model_name == "lstm":
            import torch
            seq_len = 10
            if len(X_scaled) < seq_len:
                padded = np.pad(X_scaled, ((0, seq_len - len(X_scaled)), (0, 0)), mode="edge")
                tensor_x = torch.from_numpy(padded[np.newaxis, :, :]).float()
            else:
                tensor_x = torch.from_numpy(X_scaled[-seq_len:][np.newaxis, :, :]).float()
            with torch.no_grad():
                prob = torch.sigmoid(registry.models[model_name](tensor_x)).numpy()
            scores = np.full((len(X_scaled),), float(prob.flat[0]))

        latency = (time.perf_counter() - t0) * 1000.0

        predictions: List[FlowPrediction] = []
        n_anomalies = 0

        for i, score in enumerate(scores):
            score_val = float(score)
            is_anom = score_val >= thresh
            if is_anom:
                n_anomalies += 1
            predictions.append(FlowPrediction(
                flow_index=i,
                src_ip=str(meta_df["Source IP"].iloc[i]) if "Source IP" in meta_df.columns else None,
                dst_ip=str(meta_df["Destination IP"].iloc[i]) if "Destination IP" in meta_df.columns else None,
                anomaly_score=round(score_val, 4),
                is_anomaly=is_anom,
                prediction_label="ATTACK" if is_anom else "BENIGN",
            ))

        return ScoreResponse(
            model_used=model_name,
            threshold_applied=thresh,
            total_flows=len(predictions),
            anomalies_detected=n_anomalies,
            latency_ms=round(latency, 2),
            predictions=predictions,
        )

    @app.get("/alerts", summary="Retrieve Recent Detection Events")
    def get_recent_alerts(limit: int = Query(default=100, ge=1, le=1000)) -> List[Dict[str, Any]]:
        db_path = logs_dir / "detections.db"
        if not db_path.is_file():
            return []

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(
                "SELECT * FROM detections ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = [dict(r) for r in cursor.fetchall()]
            return rows
        finally:
            conn.close()

    return app


app = create_app()


def main() -> None:
    import uvicorn
    config = load_config()
    host = config.get("api.host", "0.0.0.0")
    port = config.get("api.port", 8000)
    logger.info(f"Starting API server on {host}:{port}...")
    uvicorn.run("ddos_ads.api:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
