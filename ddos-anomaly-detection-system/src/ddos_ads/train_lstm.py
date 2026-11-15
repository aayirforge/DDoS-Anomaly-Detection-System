"""PyTorch LSTM Sequence Classifier for DDoS anomaly detection with early stopping and smoke test."""

from __future__ import annotations

import argparse
from pathlib import Path
import tempfile
from typing import Dict, List, Optional, Tuple
import matplotlib.pyplot as plt
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import f1_score, roc_auc_score

from ddos_ads.config import load_config
from ddos_ads.features import load_selected_features
from ddos_ads.utils import record_train_log, set_seeds, setup_logger, timer

logger = setup_logger("ddos_ads.train_lstm")


class LSTMAnomalyClassifier(nn.Module):
    """LSTM sequence model for temporal traffic flow window classification."""

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 64,
        num_layers: int = 2,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: (batch_size, seq_len, input_dim)
        lstm_out, (hn, _) = self.lstm(x)
        # hn[-1] shape: (batch_size, hidden_dim)
        logits = self.classifier(hn[-1])
        return logits.squeeze(-1)


def plot_loss_curves(
    train_losses: List[float],
    val_losses: List[float],
    output_path: Path,
) -> None:
    """Plot and save training and validation loss curves."""
    plt.figure(figsize=(8, 5))
    epochs = range(1, len(train_losses) + 1)
    plt.plot(epochs, train_losses, "b-o", label="Training Loss")
    plt.plot(epochs, val_losses, "r-s", label="Validation Loss")
    plt.xlabel("Epoch")
    plt.ylabel("BCE Loss")
    plt.title("LSTM Training & Validation Loss Curves")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150)
    plt.close()
    logger.info(f"Loss curves saved to {output_path}")


def run_smoke_test() -> None:
    """Execute isolated LSTM smoke test in a temporary directory."""
    logger.info("=== Running LSTM Smoke Test in Isolated Temp Directory ===")
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        temp_models = temp_dir / "models"
        temp_results = temp_dir / "results"
        temp_models.mkdir()
        temp_results.mkdir()

        # Generate tiny synthetic sequences: 30 windows, seq_len 5, 4 features
        rng = np.random.RandomState(42)
        n_windows, seq_len, n_feats = 30, 5, 4
        X_data = rng.randn(n_windows, seq_len, n_feats).astype(np.float32)
        y_data = rng.choice([0.0, 1.0], size=n_windows, p=[0.7, 0.3]).astype(np.float32)

        dataset = TensorDataset(torch.from_numpy(X_data), torch.from_numpy(y_data))
        loader = DataLoader(dataset, batch_size=8, shuffle=True)

        model = LSTMAnomalyClassifier(input_dim=n_feats, hidden_dim=16, num_layers=1, dropout=0.0)
        criterion = nn.BCEWithLogitsLoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

        model.train()
        train_losses = []
        for epoch in range(2):
            epoch_loss = 0.0
            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                out = model(batch_x)
                loss = criterion(out, batch_y)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
            train_losses.append(epoch_loss / len(loader))

        # Save checkpoint
        checkpoint_path = temp_models / "lstm.pt"
        torch.save({
            "model_state_dict": model.state_dict(),
            "input_dim": n_feats,
            "hidden_dim": 16,
            "num_layers": 1,
            "seq_len": seq_len,
        }, checkpoint_path)
        assert checkpoint_path.is_file() and checkpoint_path.stat().st_size > 0

        # Plot curves
        plot_path = temp_results / "lstm_training_curve.png"
        plot_loss_curves(train_losses, train_losses, plot_path)
        assert plot_path.is_file()

        record_train_log(
            results_dir=temp_results,
            model_name="lstm",
            elapsed_sec=0.1,
            model_size_bytes=checkpoint_path.stat().st_size,
            metrics={"smoke_test": True},
        )
        assert (temp_results / "train_log.json").is_file()

    logger.info("LSTM smoke test completed successfully with 0 disk leaks.")


def train_lstm(
    config_path: Optional[str] = None,
    epochs: Optional[int] = None,
    batch_size: Optional[int] = None,
    lr: Optional[float] = None,
    hidden_dim: Optional[int] = None,
    seeds: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Train PyTorch LSTM model on processed window sequence dataset with multi-seed evaluation."""
    import json
    config = load_config(config_path)
    processed_dir = config.get_path("processed_data_dir")
    models_dir = config.get_path("models_dir")
    results_dir = config.get_path("results_dir")

    train_npz = processed_dir / "lstm_train.npz"
    val_npz = processed_dir / "lstm_val.npz"

    if not train_npz.is_file() or not val_npz.is_file():
        raise FileNotFoundError(
            f"LSTM sequence data not found at {processed_dir}. Run 'make preprocess' first."
        )

    target_seeds = seeds if seeds is not None else [42, 43, 44]
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device for LSTM training: {device}")

    logger.info(f"Loading sequence windows from {train_npz} and {val_npz}...")
    train_data = np.load(train_npz)
    val_data = np.load(val_npz)

    X_train, y_train = train_data["X"], train_data["y"]
    X_val, y_val = val_data["X"], val_data["y"]

    n_windows, seq_len, input_dim = X_train.shape
    logger.info(f"Train data: {n_windows} windows, sequence length: {seq_len}, features: {input_dim}")

    # Compute pos_weight directly from training set: num_negatives / num_positives
    n_neg = float((y_train == 0).sum())
    n_pos = float((y_train == 1).sum())
    pos_weight_val = n_neg / max(1.0, n_pos)
    logger.info(f"Computed pos_weight from train set: {pos_weight_val:.4f} ({int(n_neg)} benign / {int(n_pos)} attacks)")

    bs = batch_size or config.get("models.lstm.batch_size", 256)
    h_dim = hidden_dim or config.get("models.lstm.hidden_dim", 64)
    n_layers = config.get("models.lstm.num_layers", 2)
    dropout = config.get("models.lstm.dropout", 0.2)
    learning_rate = lr or config.get("models.lstm.learning_rate", 0.002)
    weight_decay = config.get("models.lstm.weight_decay", 1e-5)
    max_epochs = epochs or config.get("models.lstm.epochs", 10)
    patience = config.get("models.lstm.patience", 3)

    pos_weight = torch.tensor([pos_weight_val], dtype=torch.float32, device=device)

    seed_results: List[Dict[str, Any]] = []
    global_best_val_loss = float("inf")
    global_best_weights = None
    best_train_losses: List[float] = []
    best_val_losses: List[float] = []

    for seed_idx, current_seed in enumerate(target_seeds):
        logger.info(f"\n--- Training LSTM Seed {current_seed} ({seed_idx + 1}/{len(target_seeds)}) ---")
        set_seeds(current_seed)

        train_loader = DataLoader(
            TensorDataset(torch.from_numpy(X_train), torch.from_numpy(y_train)),
            batch_size=bs,
            shuffle=True,
        )
        val_loader = DataLoader(
            TensorDataset(torch.from_numpy(X_val), torch.from_numpy(y_val)),
            batch_size=bs * 2,
            shuffle=False,
        )

        model = LSTMAnomalyClassifier(
            input_dim=input_dim,
            hidden_dim=h_dim,
            num_layers=n_layers,
            dropout=dropout,
        ).to(device)

        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=weight_decay)

        best_val_loss = float("inf")
        best_weights = None
        patience_counter = 0
        train_losses: List[float] = []
        val_losses: List[float] = []
        final_val_f1 = 0.0
        final_val_auc = 0.0

        with timer(f"LSTM Seed {current_seed}", logger) as t:
            for epoch in range(1, max_epochs + 1):
                # Training
                model.train()
                running_train_loss = 0.0
                for batch_x, batch_y in train_loader:
                    batch_x = batch_x.to(device)
                    batch_y = batch_y.to(device)

                    optimizer.zero_grad()
                    logits = model(batch_x)
                    loss = criterion(logits, batch_y)
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
                    optimizer.step()

                    running_train_loss += loss.item() * len(batch_x)

                epoch_train_loss = running_train_loss / len(X_train)
                train_losses.append(epoch_train_loss)

                # Validation
                model.eval()
                running_val_loss = 0.0
                all_val_probs = []
                all_val_targets = []
                with torch.no_grad():
                    for batch_x, batch_y in val_loader:
                        batch_x = batch_x.to(device)
                        batch_y = batch_y.to(device)

                        logits = model(batch_x)
                        loss = criterion(logits, batch_y)
                        running_val_loss += loss.item() * len(batch_x)

                        probs = torch.sigmoid(logits).cpu().numpy()
                        all_val_probs.extend(probs)
                        all_val_targets.extend(batch_y.cpu().numpy())

                epoch_val_loss = running_val_loss / len(X_val)
                val_losses.append(epoch_val_loss)

                val_targets_arr = np.array(all_val_targets)
                val_probs_arr = np.array(all_val_probs)
                val_preds = (val_probs_arr >= 0.5).astype(int)
                val_f1 = float(f1_score(val_targets_arr, val_preds, zero_division=0))
                val_auc = float(roc_auc_score(val_targets_arr, val_probs_arr))

                logger.info(
                    f"Seed {current_seed} | Epoch {epoch:02d}/{max_epochs:02d} - "
                    f"Train Loss: {epoch_train_loss:.4f} | Val Loss: {epoch_val_loss:.6f} | Val F1: {val_f1:.4f} | Val AUC: {val_auc:.4f}"
                )

                # Early stopping check
                if epoch_val_loss < best_val_loss:
                    best_val_loss = epoch_val_loss
                    best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                    patience_counter = 0
                    final_val_f1 = val_f1
                    final_val_auc = val_auc
                else:
                    patience_counter += 1
                    if patience_counter >= patience:
                        logger.info(f"Early stopping triggered for seed {current_seed} at epoch {epoch}.")
                        break

            seed_stat = {
                "seed": current_seed,
                "best_val_loss": float(best_val_loss),
                "val_f1": float(final_val_f1),
                "val_roc_auc": float(final_val_auc),
                "epochs_trained": len(train_losses),
                "elapsed_sec": float(t["elapsed_sec"]),
            }
            seed_results.append(seed_stat)

            if best_val_loss < global_best_val_loss:
                global_best_val_loss = best_val_loss
                global_best_weights = best_weights
                best_train_losses = train_losses
                best_val_losses = val_losses

    # Compute mean and spread across seeds
    val_losses_all = [s["best_val_loss"] for s in seed_results]
    val_f1s_all = [s["val_f1"] for s in seed_results]
    val_aucs_all = [s["val_roc_auc"] for s in seed_results]

    multi_seed_summary = {
        "seeds": target_seeds,
        "seed_runs": seed_results,
        "val_loss_mean": float(np.mean(val_losses_all)),
        "val_loss_std": float(np.std(val_losses_all)),
        "val_loss_spread": [float(np.min(val_losses_all)), float(np.max(val_losses_all))],
        "val_f1_mean": float(np.mean(val_f1s_all)),
        "val_f1_std": float(np.std(val_f1s_all)),
        "val_f1_spread": [float(np.min(val_f1s_all)), float(np.max(val_f1s_all))],
        "val_auc_mean": float(np.mean(val_aucs_all)),
        "val_auc_std": float(np.std(val_aucs_all)),
        "val_auc_spread": [float(np.min(val_aucs_all)), float(np.max(val_aucs_all))],
    }

    logger.info("\n" + "=" * 80)
    logger.info("                          LSTM MULTI-SEED SUMMARY RESULTS")
    logger.info("=" * 80)
    for s in seed_results:
        logger.info(f"Seed {s['seed']:<4} | Best Val Loss: {s['best_val_loss']:.6f} | Val F1: {s['val_f1']:.4f} | Val AUC: {s['val_roc_auc']:.4f} | Epochs: {s['epochs_trained']}")
    logger.info("-" * 80)
    logger.info(
        f"Val Loss Mean: {multi_seed_summary['val_loss_mean']:.6f} (spread: [{multi_seed_summary['val_loss_spread'][0]:.6f}, {multi_seed_summary['val_loss_spread'][1]:.6f}], std: {multi_seed_summary['val_loss_std']:.6f})"
    )
    logger.info(
        f"Val F1   Mean: {multi_seed_summary['val_f1_mean']:.4f} (spread: [{multi_seed_summary['val_f1_spread'][0]:.4f}, {multi_seed_summary['val_f1_spread'][1]:.4f}], std: {multi_seed_summary['val_f1_std']:.4f})"
    )
    logger.info(
        f"Val AUC  Mean: {multi_seed_summary['val_auc_mean']:.4f} (spread: [{multi_seed_summary['val_auc_spread'][0]:.4f}, {multi_seed_summary['val_auc_spread'][1]:.4f}], std: {multi_seed_summary['val_auc_std']:.4f})"
    )
    logger.info("=" * 80 + "\n")

    # Save best checkpoint
    model_path = models_dir / "lstm.pt"
    torch.save({
        "model_state_dict": global_best_weights,
        "input_dim": input_dim,
        "hidden_dim": h_dim,
        "num_layers": n_layers,
        "dropout": dropout,
        "seq_len": seq_len,
        "pos_weight": pos_weight_val,
        "multi_seed_summary": multi_seed_summary,
    }, model_path)
    model_size = model_path.stat().st_size
    logger.info(f"Saved primary LSTM checkpoint to {model_path} ({model_size / (1024*1024):.2f} MB)")

    # Save seeds summary json
    results_dir.mkdir(parents=True, exist_ok=True)
    seeds_json_path = results_dir / "lstm_seeds.json"
    with open(seeds_json_path, "w", encoding="utf-8") as f:
        json.dump(multi_seed_summary, f, indent=2)

    # Plot training curve of the best seed
    curve_path = results_dir / "lstm_training_curve.png"
    plot_loss_curves(best_train_losses, best_val_losses, curve_path)

    record_train_log(
        results_dir=results_dir,
        model_name="lstm",
        elapsed_sec=sum(s["elapsed_sec"] for s in seed_results),
        model_size_bytes=model_size,
        metrics=multi_seed_summary,
    )
    return multi_seed_summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Train PyTorch LSTM anomaly classifier.")
    parser.add_argument("--smoke-test", action="store_true", help="Run synthetic smoke test in isolated temp dir.")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml.")
    parser.add_argument("--epochs", type=int, default=None, help="Number of training epochs.")
    parser.add_argument("--batch-size", type=int, default=None, help="Batch size.")
    parser.add_argument("--lr", type=float, default=None, help="Learning rate.")
    parser.add_argument("--hidden-dim", type=int, default=None, help="LSTM hidden layer dimension.")
    parser.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44], help="List of random seeds to train.")
    args = parser.parse_args()

    if args.smoke_test:
        run_smoke_test()
    else:
        train_lstm(
            config_path=args.config,
            epochs=args.epochs,
            batch_size=args.batch_size,
            lr=args.lr,
            hidden_dim=args.hidden_dim,
            seeds=args.seeds,
        )


if __name__ == "__main__":
    main()
