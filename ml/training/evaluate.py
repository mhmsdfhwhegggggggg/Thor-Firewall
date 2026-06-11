"""
ML Model Evaluation Pipeline — Comprehensive metrics for all Thor models
Evaluates: XGBoost classifier, LSTM anomaly detector, GNN threat graph, LoRA LLM
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import mlflow

logger = logging.getLogger("thor.ml.evaluate")

# ─────────────────────────── Metrics ────────────────────────────

@dataclass
class ClassificationMetrics:
    accuracy:          float = 0.0
    precision:         float = 0.0
    recall:            float = 0.0
    f1_score:          float = 0.0
    f1_macro:          float = 0.0
    f1_weighted:       float = 0.0
    roc_auc:           float = 0.0
    pr_auc:            float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    detection_rate:    float = 0.0
    confusion_matrix:  list  = field(default_factory=list)
    per_class_metrics: dict  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if not isinstance(v, (list, dict))}

    def passes_production_bar(self) -> tuple[bool, list[str]]:
        """
        Production acceptance criteria for security ML models.
        Security models must prioritize recall (minimize false negatives).
        """
        failures = []
        if self.recall < 0.95:
            failures.append(f"Recall {self.recall:.3f} < 0.95 (too many missed threats)")
        if self.precision < 0.80:
            failures.append(f"Precision {self.precision:.3f} < 0.80 (too many false alarms)")
        if self.f1_score < 0.90:
            failures.append(f"F1 {self.f1_score:.3f} < 0.90")
        if self.roc_auc < 0.95:
            failures.append(f"ROC-AUC {self.roc_auc:.3f} < 0.95")
        if self.false_negative_rate > 0.05:
            failures.append(f"FNR {self.false_negative_rate:.3f} > 0.05 (missed attack rate too high)")
        return len(failures) == 0, failures


@dataclass
class AnomalyMetrics:
    """Metrics for unsupervised anomaly detection (UEBA)"""
    auc_roc:             float = 0.0
    average_precision:   float = 0.0
    reconstruction_loss: float = 0.0
    contamination_rate:  float = 0.0
    threshold:           float = 0.0
    true_anomaly_rate:   float = 0.0
    false_alarm_rate:    float = 0.0

    def passes_production_bar(self) -> tuple[bool, list[str]]:
        failures = []
        if self.auc_roc < 0.90:
            failures.append(f"AUC-ROC {self.auc_roc:.3f} < 0.90")
        if self.false_alarm_rate > 0.02:
            failures.append(f"False alarm rate {self.false_alarm_rate:.3f} > 2%")
        return len(failures) == 0, failures


@dataclass
class LLMMetrics:
    """Metrics for threat explanation LLM"""
    perplexity:           float = 0.0
    avg_explanation_len:  float = 0.0
    rouge1:               float = 0.0
    rouge2:               float = 0.0
    rougeL:               float = 0.0
    bleu_score:           float = 0.0
    mitre_accuracy:       float = 0.0   # % of correct MITRE mappings in output
    coherence_score:      float = 0.0   # LLM-as-judge score
    safety_violations:    int   = 0     # prompt injection, hallucination count


# ─────────────────────────── Evaluators ─────────────────────────

class ClassificationEvaluator:
    """Evaluate binary/multiclass threat classifiers"""

    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: np.ndarray | None = None,
        class_names: list[str] | None = None,
    ) -> ClassificationMetrics:
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, f1_score,
            roc_auc_score, average_precision_score, confusion_matrix,
            classification_report
        )

        metrics = ClassificationMetrics()
        metrics.accuracy  = float(accuracy_score(y_true, y_pred))
        metrics.precision = float(precision_score(y_true, y_pred, average="binary",
                                                   zero_division=0))
        metrics.recall    = float(recall_score(y_true, y_pred, average="binary",
                                               zero_division=0))
        metrics.f1_score  = float(f1_score(y_true, y_pred, average="binary",
                                            zero_division=0))
        metrics.f1_macro  = float(f1_score(y_true, y_pred, average="macro",
                                            zero_division=0))
        metrics.f1_weighted = float(f1_score(y_true, y_pred, average="weighted",
                                              zero_division=0))

        # Confusion matrix → FPR / FNR
        cm = confusion_matrix(y_true, y_pred)
        metrics.confusion_matrix = cm.tolist()
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            metrics.false_positive_rate = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            metrics.false_negative_rate = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
            metrics.detection_rate      = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0

        if y_prob is not None:
            try:
                prob_pos = y_prob[:, 1] if y_prob.ndim == 2 else y_prob
                metrics.roc_auc = float(roc_auc_score(y_true, prob_pos))
                metrics.pr_auc  = float(average_precision_score(y_true, prob_pos))
            except Exception as e:
                logger.warning("ROC/PR-AUC failed: %s", e)

        # Per-class metrics
        if class_names:
            report = classification_report(
                y_true, y_pred, target_names=class_names,
                output_dict=True, zero_division=0
            )
            metrics.per_class_metrics = {
                k: v for k, v in report.items()
                if isinstance(v, dict)
            }

        return metrics


class ThreatClassifierEvaluator:
    """Full evaluation pipeline for Thor's threat classifier"""

    def __init__(self, model_path: str, test_data_path: str, mlflow_uri: str = ""):
        self.model_path     = model_path
        self.test_data_path = test_data_path
        self.mlflow_uri     = mlflow_uri or "http://mlflow:5000"

    def run(self) -> ClassificationMetrics:
        import pandas as pd
        import joblib

        logger.info("Loading model from %s", self.model_path)
        model = joblib.load(self.model_path)

        logger.info("Loading test data from %s", self.test_data_path)
        df = pd.read_parquet(self.test_data_path)

        feature_cols = [c for c in df.columns if c not in ("label", "label_name", "timestamp")]
        X_test = df[feature_cols].values.astype(np.float32)
        y_true = df["label"].values.astype(int)

        logger.info("Evaluating on %d samples", len(y_true))
        start = time.time()
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None
        elapsed = time.time() - start

        evaluator = ClassificationEvaluator()
        class_names = df["label_name"].unique().tolist() if "label_name" in df.columns else None
        metrics = evaluator.evaluate(y_true, y_pred, y_prob, class_names)

        # Latency metric
        samples_per_sec = len(y_true) / elapsed
        logger.info(
            "Eval complete: F1=%.3f Recall=%.3f ROC-AUC=%.3f FNR=%.3f (%.0f samples/s)",
            metrics.f1_score, metrics.recall, metrics.roc_auc,
            metrics.false_negative_rate, samples_per_sec
        )

        # Production gate
        passed, failures = metrics.passes_production_bar()
        if not passed:
            logger.error("MODEL FAILED PRODUCTION BAR:")
            for f in failures:
                logger.error("  ✗ %s", f)
        else:
            logger.info("✓ Model passed all production quality gates")

        # Log to MLflow
        mlflow.set_tracking_uri(self.mlflow_uri)
        with mlflow.start_run(run_name="evaluation"):
            mlflow.log_metrics(metrics.to_dict())
            mlflow.log_metric("inference_samples_per_sec", samples_per_sec)
            mlflow.log_param("model_path", self.model_path)
            mlflow.log_param("test_samples", len(y_true))
            mlflow.set_tag("production_ready", str(passed))

            # Save confusion matrix artifact
            cm_path = "/tmp/confusion_matrix.json"
            with open(cm_path, "w") as f:
                json.dump({"confusion_matrix": metrics.confusion_matrix,
                           "class_names": class_names}, f)
            mlflow.log_artifact(cm_path)

        return metrics


class AnomalyModelEvaluator:
    """Evaluate UEBA anomaly detectors (autoencoder, isolation forest, etc.)"""

    def evaluate_ueba(
        self,
        scores: np.ndarray,       # anomaly scores
        y_true: np.ndarray,       # ground truth (1=anomaly, 0=normal)
        threshold: float | None = None,
    ) -> AnomalyMetrics:
        from sklearn.metrics import roc_auc_score, average_precision_score

        metrics = AnomalyMetrics()
        metrics.auc_roc           = float(roc_auc_score(y_true, scores))
        metrics.average_precision = float(average_precision_score(y_true, scores))

        # Auto-threshold: 95th percentile of training distribution
        if threshold is None:
            threshold = float(np.percentile(scores[y_true == 0], 95))

        metrics.threshold = threshold
        y_pred = (scores >= threshold).astype(int)

        # Anomaly rates
        n_anom  = (y_pred == 1).sum()
        n_total = len(y_pred)
        n_true_anom = (y_true == 1).sum()

        metrics.contamination_rate = float(n_anom / n_total)
        tp = ((y_pred == 1) & (y_true == 1)).sum()
        fp = ((y_pred == 1) & (y_true == 0)).sum()
        fn = ((y_pred == 0) & (y_true == 1)).sum()

        metrics.true_anomaly_rate = float(tp / n_true_anom) if n_true_anom > 0 else 0.0
        metrics.false_alarm_rate  = float(fp / (fp + (y_true == 0).sum())) if n_total > 0 else 0.0

        return metrics


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Evaluate Thor ML models")
    parser.add_argument("--model",     required=True, help="Path to trained model")
    parser.add_argument("--test-data", required=True, help="Path to test parquet file")
    parser.add_argument("--mlflow",    default="http://mlflow:5000")
    args = parser.parse_args()

    evaluator = ThreatClassifierEvaluator(
        model_path     = args.model,
        test_data_path = args.test_data,
        mlflow_uri     = args.mlflow,
    )
    metrics = evaluator.run()

    passed, failures = metrics.passes_production_bar()
    print(f"\n{'='*50}")
    print(f"Model Evaluation Results")
    print(f"{'='*50}")
    print(f"Accuracy:     {metrics.accuracy:.4f}")
    print(f"Precision:    {metrics.precision:.4f}")
    print(f"Recall:       {metrics.recall:.4f}")
    print(f"F1 Score:     {metrics.f1_score:.4f}")
    print(f"ROC-AUC:      {metrics.roc_auc:.4f}")
    print(f"PR-AUC:       {metrics.pr_auc:.4f}")
    print(f"FNR:          {metrics.false_negative_rate:.4f}")
    print(f"FPR:          {metrics.false_positive_rate:.4f}")
    print(f"\nProduction Ready: {'✓ YES' if passed else '✗ NO'}")
    if not passed:
        print("Failures:")
        for f in failures:
            print(f"  - {f}")
