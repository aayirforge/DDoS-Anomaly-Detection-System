"""Live network packet detector and anomaly mitigation engine."""

from __future__ import annotations

import argparse
from pathlib import Path
import signal
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
import pandas as pd

from ddos_ads.config import Config, load_config
from ddos_ads.features import load_selected_features
from ddos_ads.mitigation import MitigationManager
from ddos_ads.pcap_to_flows import align_flow_dataframe, capture_pcap, convert_pcap_to_flows
from ddos_ads.utils import ensure_models_available, setup_logger

logger = setup_logger("ddos_ads.live_detector")

ETHICS_BANNER = """
================================================================================
               DDoS ANOMALY DETECTION SYSTEM (LIVE MONITOR)
   WARNING: FOR USE ONLY ON NETWORKS AND SYSTEMS YOU OWN OR HAVE EXPLICIT
   LEGAL AUTHORIZATION TO MONITOR. UNAUTHORIZED INTERCEPTION OR FILTERING
   OF TRAFFIC ON PUBLIC OR THIRD-PARTY NETWORKS IS STRICTLY PROHIBITED.
================================================================================
"""


def init_sqlite_db(db_path: Path) -> sqlite3.Connection:
    """Initialize SQLite database schema for detection events."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                model_used TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                is_anomaly INTEGER NOT NULL,
                consecutive_count INTEGER NOT NULL,
                action TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON detections(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON detections(src_ip);")
    return conn


def log_detection(
    conn: sqlite3.Connection,
    csv_path: Path,
    event: Dict[str, Any],
) -> None:
    """Record detection event to both SQLite database and detections.csv."""
    # Write to SQLite
    with conn:
        conn.execute("""
            INSERT INTO detections (
                timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                model_used, anomaly_score, is_anomaly, consecutive_count, action, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["timestamp"],
            event["src_ip"],
            event["dst_ip"],
            event["src_port"],
            event["dst_port"],
            event["protocol"],
            event["model"],
            event["score"],
            int(event["is_anomaly"]),
            event["consecutive_count"],
            event["action"],
            event["reason"],
        ))

    # Append to CSV
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not csv_path.is_file()
    df = pd.DataFrame([event])
    df.to_csv(csv_path, mode="a", header=write_header, index=False)


class DestinationAggregator:
    """
    Destination-aggregated anomaly decision rule.
    Monitors the fraction of flows targeting a specific destination IP within a configurable
    time bin, triggering alerts when the fraction exceeds a threshold over consecutive windows.
    Default mode: strictly alert-only.
    """

    def __init__(
        self,
        time_bin_sec: float = 30.0,
        anomaly_fraction_threshold: float = 0.50,
        min_flows_per_bin: int = 10,
        consecutive_windows: int = 2,
        alert_only: bool = True,
    ) -> None:
        self.time_bin_sec = time_bin_sec
        self.anomaly_fraction_threshold = anomaly_fraction_threshold
        self.min_flows_per_bin = min_flows_per_bin
        self.consecutive_windows = consecutive_windows
        self.alert_only = alert_only
        self.flow_history: Dict[str, List[Tuple[float, bool]]] = {}
        self.consecutive_counts: Dict[str, int] = {}

    def record_flow(self, dst_ip: str, is_anomaly: bool, timestamp: float) -> None:
        """Record flow classification for a destination IP."""
        clean_dst = str(dst_ip).strip()
        if not clean_dst or clean_dst.lower() in ("unknown", "none", "nan", "0.0.0.0"):
            return
        if clean_dst not in self.flow_history:
            self.flow_history[clean_dst] = []
        self.flow_history[clean_dst].append((timestamp, is_anomaly))

    def evaluate_destination(self, dst_ip: str, current_time: float) -> Optional[Dict[str, Any]]:
        """Evaluate a specific destination against anomaly fraction and consecutive-window thresholds."""
        clean_dst = str(dst_ip).strip()
        history = self.flow_history.get(clean_dst, [])
        cutoff = current_time - self.time_bin_sec
        active = [(t, a) for t, a in history if t >= cutoff]
        self.flow_history[clean_dst] = active

        if len(active) < self.min_flows_per_bin:
            return None

        total_flows = len(active)
        anomaly_flows = sum(1 for _, is_anom in active if is_anom)
        fraction = anomaly_flows / total_flows

        if fraction >= self.anomaly_fraction_threshold:
            self.consecutive_counts[clean_dst] = self.consecutive_counts.get(clean_dst, 0) + 1
        else:
            self.consecutive_counts[clean_dst] = max(0, self.consecutive_counts.get(clean_dst, 0) - 1)

        count = self.consecutive_counts.get(clean_dst, 0)
        if count >= self.consecutive_windows:
            action = "DEST_ALERT"
            reason = (
                f"destination_ddos_surge: {fraction * 100:.1f}% anomalous flows "
                f"({anomaly_flows}/{total_flows} in {int(self.time_bin_sec)}s bin) across "
                f"{count}/{self.consecutive_windows} consecutive windows"
            )
            return {
                "dst_ip": clean_dst,
                "total_flows": total_flows,
                "anomaly_flows": anomaly_flows,
                "anomaly_fraction": round(fraction, 4),
                "consecutive_count": count,
                "action": action,
                "reason": reason,
                "alert_only": self.alert_only,
            }
        return None

    def evaluate_all(self, current_time: float) -> List[Dict[str, Any]]:
        """Evaluate all tracked destinations."""
        alerts = []
        for dst_ip in list(self.flow_history.keys()):
            alert = self.evaluate_destination(dst_ip, current_time)
            if alert:
                alerts.append(alert)
        return alerts


class LiveDetector:
    """Live traffic capture, flow processing, and anomaly inference engine."""

    def __init__(
        self,
        config: Config,
        model_name: str = "rf",
        threshold: Optional[float] = None,
        enable_blocking: bool = False,
        dry_run: bool = False,
    ) -> None:
        self.config = config
        self.model_name = model_name
        self.threshold = threshold or config.get("live_detection.threshold", 0.50)
        self.running = False

        models_dir = config.get_path("models_dir")
        ensure_models_available(models_dir, ["features.json", "scaler.joblib"])

        self.features = load_selected_features(models_dir / "features.json")
        self.scaler = joblib.load(models_dir / "scaler.joblib")

        self.model = self._load_inference_model(models_dir, model_name)
        self.mitigation = MitigationManager(config, enable_blocking=enable_blocking, dry_run=dry_run)

        self.db_path = config.get_path("logs_dir") / "detections.db"
        self.csv_path = config.get_path("logs_dir") / "detections.csv"
        self.db_conn = init_sqlite_db(self.db_path)

        # Destination-aggregated decision rule (alert-only by default)
        time_bin = config.get("live_detection.dest_aggregation_time_bin_sec", 30)
        frac_th = config.get("live_detection.dest_anomaly_fraction_threshold", 0.50)
        min_flows = config.get("live_detection.dest_min_flows_per_bin", 10)
        consec_win = config.get("live_detection.dest_consecutive_windows", 2)
        alert_only = config.get("live_detection.dest_alert_only", True)

        self.dest_aggregator = DestinationAggregator(
            time_bin_sec=time_bin,
            anomaly_fraction_threshold=frac_th,
            min_flows_per_bin=min_flows,
            consecutive_windows=consec_win,
            alert_only=alert_only,
        )

    def _load_inference_model(self, models_dir: Path, name: str) -> Any:
        """Load requested model with clear fallback handling."""
        if name == "rf":
            rf_path = models_dir / "rf.joblib"
            if not rf_path.is_file():
                ensure_models_available(models_dir, ["rf.joblib"])
            return joblib.load(rf_path)
        elif name == "knn":
            knn_path = models_dir / "knn.joblib"
            if not knn_path.is_file():
                ensure_models_available(models_dir, ["knn.joblib"])
            return joblib.load(knn_path)
        elif name == "lstm":
            lstm_path = models_dir / "lstm.pt"
            if not lstm_path.is_file():
                ensure_models_available(models_dir, ["lstm.pt"])
            import torch
            from ddos_ads.train_lstm import LSTMAnomalyClassifier
            checkpoint = torch.load(lstm_path, map_location="cpu")
            model = LSTMAnomalyClassifier(
                input_dim=checkpoint["input_dim"],
                hidden_dim=checkpoint["hidden_dim"],
                num_layers=checkpoint.get("num_layers", 2),
                dropout=0.0,
            )
            model.load_state_dict(checkpoint["model_state_dict"])
            model.eval()
            return model
        else:
            raise ValueError(f"Unknown model name: {name}")

    def score_flows(self, X_scaled: np.ndarray) -> np.ndarray:
        """Compute anomaly probability scores using the active model."""
        if len(X_scaled) == 0:
            return np.empty((0,), dtype=np.float32)

        if self.model_name in ("rf", "knn"):
            return self.model.predict_proba(X_scaled)[:, 1]
        elif self.model_name == "lstm":
            import torch
            # For tabular stream in live mode, pad or tile to window shape (1, seq_len, feats)
            seq_len = 10
            if len(X_scaled) < seq_len:
                padded = np.pad(X_scaled, ((0, seq_len - len(X_scaled)), (0, 0)), mode="edge")
                tensor_x = torch.from_numpy(padded[np.newaxis, :, :]).float()
            else:
                tensor_x = torch.from_numpy(X_scaled[-seq_len:][np.newaxis, :, :]).float()
            with torch.no_grad():
                prob = torch.sigmoid(self.model(tensor_x)).numpy()
            return np.full((len(X_scaled),), float(prob.flat[0]))
        return np.zeros((len(X_scaled),))

    def process_capture_chunk(self, raw_flows_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Align, scale, infer anomaly scores, and evaluate mitigation for a batch of flows."""
        if raw_flows_df.empty:
            return []

        features_df, meta_df = align_flow_dataframe(raw_flows_df, self.features)
        X_mat = features_df[self.features].to_numpy()
        X_scaled = self.scaler.transform(X_mat)

        scores = self.score_flows(X_scaled)
        events = []
        chunk_time = time.time()

        for idx in range(len(raw_flows_df)):
            score = float(scores[idx])
            is_anomaly = score >= self.threshold
            src_ip = str(meta_df["Source IP"].iloc[idx])
            dst_ip = str(meta_df["Destination IP"].iloc[idx])
            ts_val = meta_df["Timestamp"].iloc[idx]
            ts_str = ts_val.isoformat() if hasattr(ts_val, "isoformat") else str(ts_val)

            # Record flow into destination aggregator
            self.dest_aggregator.record_flow(dst_ip, is_anomaly, chunk_time)

            decision = self.mitigation.evaluate_flow(
                ip_str=src_ip,
                is_anomaly=is_anomaly,
                anomaly_score=score,
            )

            event = {
                "timestamp": ts_str,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(meta_df["Source Port"].iloc[idx]) if str(meta_df["Source Port"].iloc[idx]).isdigit() else 0,
                "dst_port": int(meta_df["Destination Port"].iloc[idx]) if str(meta_df["Destination Port"].iloc[idx]).isdigit() else 0,
                "protocol": str(meta_df["Protocol"].iloc[idx]),
                "model": self.model_name,
                "score": score,
                "is_anomaly": is_anomaly,
                "consecutive_count": decision["consecutive_count"],
                "action": decision["action"],
                "reason": decision["reason"],
            }

            if decision["logged"]:
                log_detection(self.db_conn, self.csv_path, event)
                logger.warning(
                    f"[{decision['action']}] IP: {src_ip} -> Score: {score:.4f} | Reason: {decision['reason']}"
                )

            events.append(event)

        # Evaluate destination-aggregated decision rule (alert-only by default)
        dest_alerts = self.dest_aggregator.evaluate_all(chunk_time)
        for d_alert in dest_alerts:
            dst_ip = d_alert["dst_ip"]
            dest_event = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(chunk_time)),
                "src_ip": "AGGREGATED",
                "dst_ip": dst_ip,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "ANY",
                "model": self.model_name,
                "score": d_alert["anomaly_fraction"],
                "is_anomaly": True,
                "consecutive_count": d_alert["consecutive_count"],
                "action": d_alert["action"],
                "reason": d_alert["reason"],
            }
            log_detection(self.db_conn, self.csv_path, dest_event)
            logger.warning(
                f"[{d_alert['action']}] Destination: {dst_ip} -> {d_alert['anomaly_fraction']*100:.1f}% anomalous "
                f"({d_alert['anomaly_flows']}/{d_alert['total_flows']} flows) | Reason: {d_alert['reason']}"
            )
            events.append(dest_event)

        return events

    def run_live_loop(
        self,
        interface: str = "any",
        chunk_duration_sec: int = 5,
        single_shot: bool = False,
    ) -> None:
        """Main detection loop with clean SIGINT handling."""
        print(ETHICS_BANNER)
        logger.info(
            f"Starting Live Detector on interface '{interface}' (chunk duration: {chunk_duration_sec}s)\n"
            f"Active Model: {self.model_name} | Decision Threshold: {self.threshold}\n"
            f"Mitigation Mode: {'ACTIVE BLOCKING' if self.mitigation.enable_blocking else 'ALERT-ONLY'}\n"
        )

        self.running = True
        temp_dir = self.config.get_path("capture_dir") / "temp_stream"
        temp_dir.mkdir(parents=True, exist_ok=True)

        def sigint_handler(signum, frame):
            logger.info("\nSIGINT received. Initiating clean system shutdown...")
            self.running = False
            self.mitigation.cleanup_rules()
            self.db_conn.close()
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)

        iteration = 0
        while self.running:
            iteration += 1
            chunk_ts = int(time.time())
            pcap_file = temp_dir / f"live_{chunk_ts}.pcap"
            flow_out_dir = temp_dir / f"flows_{chunk_ts}"

            try:
                # 1. Packet capture
                capture_pcap(interface, chunk_duration_sec, pcap_file)

                # 2. Flow extraction
                csv_files = convert_pcap_to_flows(pcap_file, flow_out_dir)

                # 3. Process each flow file
                for csv_f in csv_files:
                    raw_df = pd.read_csv(csv_f)
                    self.process_capture_chunk(raw_df)

            except Exception as e:
                logger.error(f"Error during detection cycle {iteration}: {e}")
            finally:
                # Cleanup temporary capture artifacts
                if pcap_file.is_file():
                    pcap_file.unlink(missing_ok=True)
                if flow_out_dir.is_dir():
                    shutil.rmtree(flow_out_dir, ignore_errors=True)

            if single_shot:
                logger.info("Single-shot execution completed.")
                break


def main() -> None:
    parser = argparse.ArgumentParser(description="Live DDoS detection engine.")
    parser.add_argument("--interface", "-i", type=str, default="any", help="Network interface.")
    parser.add_argument("--model", "-m", choices=["rf", "knn", "lstm"], default="rf", help="Inference model.")
    parser.add_argument("--threshold", "-t", type=float, default=None, help="Anomaly decision threshold.")
    parser.add_argument("--duration", "-d", type=int, default=5, help="Capture chunk duration in seconds.")
    parser.add_argument("--enable-blocking", action="store_true", help="OPT-IN: Enable active packet dropping via nftables.")
    parser.add_argument("--dry-run", action="store_true", help="Simulate mitigation commands without executing.")
    parser.add_argument("--single-shot", action="store_true", help="Run a single capture chunk and exit.")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml.")
    args = parser.parse_args()

    config = load_config(args.config)
    detector = LiveDetector(
        config=config,
        model_name=args.model,
        threshold=args.threshold,
        enable_blocking=args.enable_blocking,
        dry_run=args.dry_run,
    )
    detector.run_live_loop(
        interface=args.interface,
        chunk_duration_sec=args.duration,
        single_shot=args.single_shot,
    )


if __name__ == "__main__":
    main()
