"""
Thor Firewall — Hyperparameter Optimization with Optuna
تحسين المعاملات الفائقة باستخدام Optuna + MLflow

يبحث عن أفضل hyperparameters للـ MARL models.
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import logging, time
from typing import Dict

logger = logging.getLogger("thor.training.hyperopt")

try:
    import optuna
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False
    logger.warning("Optuna not installed — hyperopt disabled")

try:
    import mlflow
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False


def objective(trial, data_dir: str = "../data/processed") -> float:
    """Optuna objective function — تُعيد validation accuracy"""
    import torch, numpy as np
    from torch.utils.data import DataLoader, TensorDataset
    import torch.nn as nn

    # Hyperparameter space
    hidden_dim  = trial.suggest_categorical("hidden_dim", [128, 256, 512])
    n_layers    = trial.suggest_int("n_layers", 2, 6)
    dropout     = trial.suggest_float("dropout", 0.05, 0.3)
    lr          = trial.suggest_float("lr", 1e-4, 1e-2, log=True)
    batch_size  = trial.suggest_categorical("batch_size", [128, 256, 512])

    # Load data
    try:
        X_train = np.load(f"{data_dir}/X_train.npy")[:50_000]
        y_train = np.load(f"{data_dir}/y_train.npy")[:50_000]
        X_val   = np.load(f"{data_dir}/X_val.npy")[:10_000]
        y_val   = np.load(f"{data_dir}/y_val.npy")[:10_000]
    except FileNotFoundError:
        # Synthetic fallback
        rng = np.random.default_rng(trial.number)
        n_classes = 8
        X_train = rng.standard_normal((5000, 50)).astype(np.float32)
        y_train = rng.integers(0, n_classes, 5000)
        X_val   = rng.standard_normal((1000, 50)).astype(np.float32)
        y_val   = rng.integers(0, n_classes, 1000)

    n_classes = int(y_train.max()) + 1

    # Build model
    layers = [nn.Linear(50, hidden_dim), nn.BatchNorm1d(hidden_dim), nn.GELU(), nn.Dropout(dropout)]
    for _ in range(n_layers - 1):
        layers += [nn.Linear(hidden_dim, hidden_dim), nn.GELU(), nn.Dropout(dropout)]
    layers.append(nn.Linear(hidden_dim, n_classes))
    model = nn.Sequential(*layers)

    loader = DataLoader(
        TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train)),
        batch_size=batch_size, shuffle=True
    )

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()

    # Quick 10-epoch training for HPO
    for epoch in range(10):
        model.train()
        for X_b, y_b in loader:
            logits = model(X_b)
            loss = criterion(logits, y_b)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        # Pruning
        model.eval()
        with torch.no_grad():
            val_logits = model(torch.FloatTensor(X_val))
            val_acc = (val_logits.argmax(1) == torch.LongTensor(y_val)).float().mean().item()
        trial.report(val_acc, epoch)
        if trial.should_prune():
            raise optuna.exceptions.TrialPruned()

    return val_acc


def run_hyperopt(
    n_trials: int = 50,
    data_dir: str = "../data/processed",
    mlflow_uri: str = "http://mlflow:5000",
    experiment: str = "thor-hyperopt-v1",
) -> Dict:
    """تشغيل optimization"""
    if not OPTUNA_AVAILABLE:
        logger.error("Optuna required. Install with: pip install optuna")
        return {}

    if MLFLOW_AVAILABLE:
        mlflow.set_tracking_uri(mlflow_uri)
        mlflow.set_experiment(experiment)

    logger.info("Starting hyperparameter optimization (%d trials)...", n_trials)

    study = optuna.create_study(
        direction="maximize",
        pruner=optuna.pruners.MedianPruner(n_startup_trials=5, n_warmup_steps=3),
        study_name="thor-marl-hpo",
    )

    study.optimize(
        lambda trial: objective(trial, data_dir),
        n_trials=n_trials,
        n_jobs=1,
        show_progress_bar=True,
    )

    best = study.best_trial
    logger.info("Best trial: val_acc=%.4f | params=%s", best.value, best.params)

    if MLFLOW_AVAILABLE:
        with mlflow.start_run(run_name=f"hyperopt_best_{int(time.time())}"):
            mlflow.log_params(best.params)
            mlflow.log_metric("best_val_accuracy", best.value)

    return {"best_value": best.value, "best_params": best.params}


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO)
    p = argparse.ArgumentParser()
    p.add_argument("--trials", type=int, default=50)
    p.add_argument("--data-dir", default="../data/processed")
    p.add_argument("--mlflow-uri", default="http://mlflow:5000")
    args = p.parse_args()
    result = run_hyperopt(args.trials, args.data_dir, args.mlflow_uri)
    print("Best params:", result.get("best_params"))
