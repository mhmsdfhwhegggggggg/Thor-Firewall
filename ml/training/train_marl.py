"""
Thor Firewall — MARL Training Entry Point
==========================================
تدريب نموذج PPO Actor-Critic على CICIDS2017/2018.

الاستخدام:
    python -m ml.training.train_marl \
        --data-dir ./data/CICIDS2017 \
        --epochs 50 \
        --device cuda \
        --mlflow-uri http://localhost:5000

مراحل التدريب:
  Phase 1: Supervised pretraining (30 epochs) على CICIDS labels
  Phase 2: PPO RL fine-tuning (20 epochs) مع reward shaping

النتيجة النهائية:
  models/thor_marl_best.pt   — PyTorch checkpoint
  models/thor_actor.onnx     — ONNX للإنتاج
  models/thor_scaler.pkl     — RobustScaler
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)-28s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("thor.training.main")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Train Thor Firewall MARL threat classifier"
    )
    p.add_argument("--data-dir",      default="./data",     help="CICIDS dataset directory")
    p.add_argument("--dataset",       default="CICIDS2017", choices=["CICIDS2017", "CICIDS2018", "NSL-KDD", "UNSW-NB15"])
    p.add_argument("--output-dir",    default="./models",   help="Where to save checkpoints")
    p.add_argument("--device",        default="auto",       choices=["auto", "cpu", "cuda", "mps"])
    p.add_argument("--hidden-dim",    type=int, default=256)
    p.add_argument("--pretrain-epochs", type=int, default=30)
    p.add_argument("--ppo-epochs",    type=int, default=20)
    p.add_argument("--batch-size",    type=int, default=512)
    p.add_argument("--lr",            type=float, default=3e-4)
    p.add_argument("--mlflow-uri",    default=None,         help="MLflow tracking URI")
    p.add_argument("--experiment",    default="thor-marl",  help="MLflow experiment name")
    p.add_argument("--seed",          type=int, default=42)
    p.add_argument("--resume",        default=None,         help="Resume from checkpoint")
    p.add_argument("--export-onnx",   action="store_true",  help="Export ONNX after training")
    p.add_argument("--dry-run",       action="store_true",  help="Quick smoke test")
    return p.parse_args()


def set_seed(seed: int):
    import random
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def evaluate(trainer, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """Full evaluation: accuracy, F1 per class, confusion matrix."""
    import torch
    from sklearn.metrics import (
        accuracy_score, f1_score,
        classification_report, confusion_matrix,
    )
    from .train_marl import logger
    from ..data.dataset_loader import CLASS_NAMES

    trainer.actor.eval()
    device = trainer.device
    X_t = torch.from_numpy(X_test).float().to(device)
    
    with torch.no_grad():
        all_preds = []
        batch_size = 4096
        for i in range(0, len(X_t), batch_size):
            out  = trainer.actor(X_t[i:i+batch_size])
            preds = out["logits"].argmax(1).cpu().numpy()
            all_preds.append(preds)
    
    y_pred = np.concatenate(all_preds)
    acc    = accuracy_score(y_test, y_pred)
    f1_mac = f1_score(y_test, y_pred, average="macro",    zero_division=0)
    f1_wei = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    
    report = classification_report(
        y_test, y_pred,
        target_names=CLASS_NAMES,
        zero_division=0,
        output_dict=True,
    )
    
    logger.info("Test accuracy: %.4f  |  F1 macro: %.4f  |  F1 weighted: %.4f",
                acc, f1_mac, f1_wei)
    for cls_name in CLASS_NAMES:
        if cls_name in report:
            r = report[cls_name]
            logger.info("  %-15s  P=%.3f  R=%.3f  F1=%.3f  support=%d",
                        cls_name, r["precision"], r["recall"], r["f1-score"], int(r["support"]))
    
    return {"accuracy": acc, "f1_macro": f1_mac, "f1_weighted": f1_wei, "report": report}


def main():
    args = parse_args()
    set_seed(args.seed)

    try:
        import torch
    except ImportError:
        logger.error("PyTorch not installed! Run: pip install torch torchvision")
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── MLflow setup ─────────────────────────────────────────────────────────
    mlflow_run = None
    if args.mlflow_uri:
        try:
            import mlflow
            mlflow.set_tracking_uri(args.mlflow_uri)
            mlflow.set_experiment(args.experiment)
            mlflow_run = mlflow.start_run(run_name=f"thor-marl-{time.strftime('%Y%m%d-%H%M%S')}")
            mlflow.log_params({
                "dataset":        args.dataset,
                "hidden_dim":     args.hidden_dim,
                "pretrain_epochs": args.pretrain_epochs,
                "ppo_epochs":     args.ppo_epochs,
                "batch_size":     args.batch_size,
                "lr":             args.lr,
                "seed":           args.seed,
            })
            logger.info("MLflow tracking: %s", args.mlflow_uri)
        except Exception as e:
            logger.warning("MLflow unavailable: %s", e)

    # ── Load dataset ──────────────────────────────────────────────────────────
    from ..data.dataset_loader import DatasetLoader, INPUT_DIM

    logger.info("Loading dataset: %s from %s", args.dataset, args.data_dir)
    loader = DatasetLoader(
        data_dir     = args.data_dir,
        dataset      = args.dataset,
        val_ratio    = 0.1,
        test_ratio   = 0.1,
        random_state = args.seed,
    )

    if args.dry_run:
        # Quick smoke test with synthetic data
        logger.info("DRY RUN: using synthetic data")
        n_train, n_val, n_test = 10000, 1000, 1000
        X_train = np.random.randn(n_train, INPUT_DIM).astype(np.float32)
        y_train = np.random.randint(0, 8, n_train)
        X_val   = np.random.randn(n_val, INPUT_DIM).astype(np.float32)
        y_val   = np.random.randint(0, 8, n_val)
        X_test  = np.random.randn(n_test, INPUT_DIM).astype(np.float32)
        y_test  = np.random.randint(0, 8, n_test)
        scaler  = None
    else:
        X_train, X_val, X_test, y_train, y_val, y_test = loader.load_split()
        scaler = loader.scaler

    logger.info("Train: %d  Val: %d  Test: %d", len(X_train), len(X_val), len(X_test))

    # ── Build trainer ─────────────────────────────────────────────────────────
    from ..marl.brain.ppo import PPOTrainer, PPOConfig

    cfg = PPOConfig(
        input_dim        = X_train.shape[1],
        hidden_dim       = args.hidden_dim,
        pretrain_epochs  = args.pretrain_epochs,
        pretrain_lr      = args.lr,
        pretrain_batch   = args.batch_size,
    )
    trainer = PPOTrainer(config=cfg, device=args.device)

    if args.resume:
        logger.info("Resuming from %s", args.resume)
        trainer.load(args.resume)

    # ── Phase 1: Supervised pretraining ──────────────────────────────────────
    logger.info("=" * 60)
    logger.info("PHASE 1: Supervised Pretraining on %s", args.dataset)
    logger.info("=" * 60)

    pretrain_metrics = trainer.pretrain_supervised(
        X_train, y_train, X_val, y_val, mlflow_run=mlflow_run
    )

    # Save after pretraining
    pt_path = output_dir / "thor_marl_pretrain.pt"
    trainer.save(str(pt_path))

    # ── Phase 2: Evaluate pretrained model ────────────────────────────────────
    logger.info("\nEvaluating pretrained model on test set...")
    test_metrics = evaluate(trainer, X_test, y_test)

    if mlflow_run:
        try:
            import mlflow
            mlflow.log_metrics({
                "test/accuracy":    test_metrics["accuracy"],
                "test/f1_macro":    test_metrics["f1_macro"],
                "test/f1_weighted": test_metrics["f1_weighted"],
            })
        except Exception:
            pass

    # Save best model
    best_path = output_dir / "thor_marl_best.pt"
    trainer.save(str(best_path))
    logger.info("Best model saved: %s", best_path)

    # ── Save scaler ───────────────────────────────────────────────────────────
    if scaler is not None:
        scaler_path = output_dir / "thor_scaler.pkl"
        with open(scaler_path, "wb") as f:
            pickle.dump(scaler, f)
        logger.info("Scaler saved: %s", scaler_path)

    # ── Export ONNX ───────────────────────────────────────────────────────────
    if args.export_onnx:
        try:
            onnx_path = output_dir / "thor_actor.onnx"
            trainer.export_onnx(str(onnx_path))
            logger.info("ONNX exported: %s", onnx_path)
        except Exception as e:
            logger.warning("ONNX export failed: %s", e)

    # ── Save metrics ──────────────────────────────────────────────────────────
    metrics_path = output_dir / "training_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump({
            "pretrain": {
                "best_val_acc":  pretrain_metrics.get("best_val_acc", 0),
                "final_val_loss": pretrain_metrics["val_loss"][-1] if pretrain_metrics.get("val_loss") else 0,
            },
            "test": {
                "accuracy":    test_metrics["accuracy"],
                "f1_macro":    test_metrics["f1_macro"],
                "f1_weighted": test_metrics["f1_weighted"],
            },
            "dataset":     args.dataset,
            "input_dim":   X_train.shape[1],
            "n_classes":   8,
            "train_size":  len(X_train),
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, f, indent=2)

    if mlflow_run:
        try:
            import mlflow
            mlflow.log_artifact(str(metrics_path))
            mlflow.log_artifact(str(best_path))
            mlflow.end_run()
        except Exception:
            pass

    logger.info("\n✅ Training complete!")
    logger.info("   Model:   %s", best_path)
    logger.info("   Acc:     %.4f", test_metrics["accuracy"])
    logger.info("   F1 mac:  %.4f", test_metrics["f1_macro"])


if __name__ == "__main__":
    main()
