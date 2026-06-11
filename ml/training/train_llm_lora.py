"""
LoRA/QLoRA Fine-tuning for Threat Explanation LLM
Model: Mistral-7B-Instruct-v0.2 quantized to 4-bit with bitsandbytes
Task: Generate human-readable threat explanations from structured alert data
Uses: PEFT LoRA, bitsandbytes NF4 quantization, Hugging Face Transformers
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import torch
from datasets import Dataset, load_dataset
from peft import (
    LoraConfig,
    PeftModel,
    TaskType,
    get_peft_model,
    prepare_model_for_kbit_training,
)
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForSeq2Seq,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
)
import mlflow
import mlflow.pytorch

logger = logging.getLogger("thor.ml.lora_trainer")

# ─────────────────────────── Config ────────────────────────────

@dataclass
class LoraTrainerConfig:
    # Model
    base_model:       str  = "mistralai/Mistral-7B-Instruct-v0.2"
    output_dir:       str  = "/tmp/thor-lora-checkpoints"
    final_model_dir:  str  = "/opt/thor/models/threat-explainer"

    # QLoRA quantization
    load_in_4bit:     bool = True
    bnb_4bit_compute_dtype: str = "float16"
    bnb_4bit_quant_type:    str = "nf4"       # NormalFloat4 — better than FP4
    bnb_4bit_use_double_quant: bool = True     # nested quantization

    # LoRA adapter
    lora_r:           int   = 64      # rank
    lora_alpha:       int   = 16
    lora_dropout:     float = 0.1
    lora_target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])

    # Training
    num_epochs:       int   = 3
    batch_size:       int   = 4
    grad_accumulation:int   = 4
    learning_rate:    float = 2e-4
    warmup_ratio:     float = 0.05
    max_seq_len:      int   = 2048
    eval_steps:       int   = 100
    save_steps:       int   = 100
    logging_steps:    int   = 25
    fp16:             bool  = True
    gradient_checkpointing: bool = True

    # Data
    train_data_path:  str   = "/opt/thor/data/threat_explanations_train.jsonl"
    eval_data_path:   str   = "/opt/thor/data/threat_explanations_eval.jsonl"
    max_train_samples:int   = 10000
    max_eval_samples: int   = 500

    # MLflow
    mlflow_uri:       str   = "http://mlflow:5000"
    experiment_name:  str   = "thor-threat-explainer"


# ─────────────────────────── Prompt Template ───────────────────

SYSTEM_PROMPT = """You are Thor Firewall's AI security analyst. 
Given structured alert data, provide a clear, actionable threat explanation for a SOC analyst.
Include: what happened, why it's suspicious, MITRE ATT&CK mapping, and recommended action."""

def format_prompt(alert: dict) -> str:
    return (
        f"[INST] {SYSTEM_PROMPT}\n\n"
        f"Alert Data:\n{json.dumps(alert, indent=2)}\n\n"
        f"Provide a threat analysis: [/INST]"
    )

def format_training_example(example: dict) -> dict:
    """Format a training example with prompt + completion"""
    prompt    = format_prompt(example["alert"])
    full_text = prompt + example["explanation"] + "</s>"
    return {"text": full_text}


# ─────────────────────────── Trainer ───────────────────────────

class ThorLoraTrainer:
    def __init__(self, config: LoraTrainerConfig):
        self.config = config

    def _bnb_config(self) -> BitsAndBytesConfig:
        return BitsAndBytesConfig(
            load_in_4bit              = self.config.load_in_4bit,
            bnb_4bit_compute_dtype    = getattr(torch, self.config.bnb_4bit_compute_dtype),
            bnb_4bit_quant_type       = self.config.bnb_4bit_quant_type,
            bnb_4bit_use_double_quant = self.config.bnb_4bit_use_double_quant,
        )

    def _lora_config(self) -> LoraConfig:
        return LoraConfig(
            r                = self.config.lora_r,
            lora_alpha       = self.config.lora_alpha,
            target_modules   = self.config.lora_target_modules,
            lora_dropout     = self.config.lora_dropout,
            bias             = "none",
            task_type        = TaskType.CAUSAL_LM,
        )

    def _load_model_and_tokenizer(self):
        logger.info("Loading %s with 4-bit quantization", self.config.base_model)

        tokenizer = AutoTokenizer.from_pretrained(self.config.base_model)
        tokenizer.pad_token     = tokenizer.eos_token
        tokenizer.padding_side  = "right"

        model = AutoModelForCausalLM.from_pretrained(
            self.config.base_model,
            quantization_config = self._bnb_config(),
            device_map          = "auto",
            trust_remote_code   = True,
        )
        model = prepare_model_for_kbit_training(model)
        model = get_peft_model(model, self._lora_config())
        model.print_trainable_parameters()

        if self.config.gradient_checkpointing:
            model.enable_input_require_grads()

        return model, tokenizer

    def _load_dataset(self, tokenizer) -> tuple[Dataset, Dataset]:
        def load_jsonl(path: str, max_samples: int) -> Dataset:
            records = []
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
                        if len(records) >= max_samples:
                            break
            return Dataset.from_list(records)

        train_ds = load_jsonl(self.config.train_data_path,  self.config.max_train_samples)
        eval_ds  = load_jsonl(self.config.eval_data_path,   self.config.max_eval_samples)

        def tokenize(examples):
            formatted = [format_training_example({"alert": a, "explanation": e})["text"]
                         for a, e in zip(examples["alert"], examples["explanation"])]
            result = tokenizer(
                formatted,
                truncation=True,
                max_length=self.config.max_seq_len,
                padding=False,
            )
            result["labels"] = result["input_ids"].copy()
            return result

        train_ds = train_ds.map(tokenize, batched=True, remove_columns=train_ds.column_names)
        eval_ds  = eval_ds.map(tokenize,  batched=True, remove_columns=eval_ds.column_names)

        return train_ds, eval_ds

    def _training_args(self) -> TrainingArguments:
        return TrainingArguments(
            output_dir              = self.config.output_dir,
            num_train_epochs        = self.config.num_epochs,
            per_device_train_batch_size = self.config.batch_size,
            per_device_eval_batch_size  = self.config.batch_size,
            gradient_accumulation_steps = self.config.grad_accumulation,
            learning_rate           = self.config.learning_rate,
            fp16                    = self.config.fp16,
            warmup_ratio            = self.config.warmup_ratio,
            evaluation_strategy     = "steps",
            eval_steps              = self.config.eval_steps,
            save_strategy           = "steps",
            save_steps              = self.config.save_steps,
            logging_steps           = self.config.logging_steps,
            load_best_model_at_end  = True,
            metric_for_best_model   = "eval_loss",
            greater_is_better       = False,
            report_to               = ["mlflow"],
            dataloader_num_workers  = 4,
            remove_unused_columns   = False,
            group_by_length         = True,    # pack similar-length sequences → faster
        )

    def train(self):
        mlflow.set_tracking_uri(self.config.mlflow_uri)
        mlflow.set_experiment(self.config.experiment_name)

        with mlflow.start_run(run_name="lora_finetune"):
            mlflow.log_params({
                "base_model":    self.config.base_model,
                "lora_r":        self.config.lora_r,
                "lora_alpha":    self.config.lora_alpha,
                "num_epochs":    self.config.num_epochs,
                "batch_size":    self.config.batch_size,
                "learning_rate": self.config.learning_rate,
                "quant_type":    self.config.bnb_4bit_quant_type,
            })

            model, tokenizer = self._load_model_and_tokenizer()
            train_ds, eval_ds = self._load_dataset(tokenizer)

            data_collator = DataCollatorForSeq2Seq(
                tokenizer, model=model, padding=True, pad_to_multiple_of=8
            )

            trainer = Trainer(
                model           = model,
                args            = self._training_args(),
                train_dataset   = train_ds,
                eval_dataset    = eval_ds,
                data_collator   = data_collator,
                callbacks       = [EarlyStoppingCallback(early_stopping_patience=3)],
            )

            logger.info("Starting LoRA fine-tuning")
            train_result = trainer.train()

            # Log metrics
            mlflow.log_metrics({
                "train_loss":          train_result.training_loss,
                "train_runtime_secs":  train_result.metrics.get("train_runtime", 0),
                "train_samples_per_sec": train_result.metrics.get("train_samples_per_second", 0),
            })

            # Save final adapter
            output_path = Path(self.config.final_model_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            trainer.save_model(str(output_path))
            tokenizer.save_pretrained(str(output_path))

            # Log model artifact to MLflow
            mlflow.peft.log_model(model, "thor-lora-adapter")

            logger.info("LoRA training complete. Model saved to %s", output_path)
            return train_result


def generate_training_data_from_alerts(
    alerts: list[dict],
    output_path: str = "/opt/thor/data/threat_explanations_train.jsonl",
    append: bool = False,
):
    """
    Generate LoRA training data from existing alerts + analyst annotations.
    Template-based generation for bootstrapping when annotation data is sparse.
    """
    templates = {
        "T1059": "Command execution via {process} detected. Attacker used scripting interpreter to execute malicious code. Recommend: Kill process, isolate host, check persistence.",
        "T1055": "Process injection into {target} from {source}. Memory manipulation indicates advanced implant. Recommend: Memory dump, host isolation.",
        "T1078": "Valid account {user} used from unusual location {ip}. Potential credential theft. Recommend: Revoke sessions, enable MFA, check for password spray.",
        "T1110": "Brute force detected: {count} failed logins for {user}. Recommend: Lock account, block source IP, alert user.",
        "T1071": "C2 communication via {protocol} to {ip}:{port}. Network beacon pattern matches known APT TTPs. Recommend: Block IP, isolate host.",
        "T1485": "Data destruction: mass file deletion/modification detected. Possible ransomware or sabotage. Recommend: Immediate isolation, snapshot volumes.",
    }

    mode = "a" if append else "w"
    count = 0

    with open(output_path, mode) as f:
        for alert in alerts:
            techniques = alert.get("mitre_techniques", [])
            for tech in techniques:
                template = templates.get(tech[:5])
                if template:
                    explanation = template.format(
                        process = alert.get("actor_process", "unknown"),
                        target  = alert.get("target_resource", "unknown"),
                        source  = alert.get("source_host", "unknown"),
                        user    = alert.get("actor_user", "unknown"),
                        ip      = alert.get("source_ip", "unknown"),
                        port    = alert.get("target_port", 0),
                        count   = alert.get("labels", {}).get("failure_count", "multiple"),
                        protocol= alert.get("labels", {}).get("protocol", "HTTP"),
                    )
                    record = {"alert": alert, "explanation": explanation, "technique": tech}
                    f.write(json.dumps(record) + "\n")
                    count += 1

    logger.info("Generated %d training examples → %s", count, output_path)
    return count


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Thor LoRA Trainer")
    parser.add_argument("--model",          default="mistralai/Mistral-7B-Instruct-v0.2")
    parser.add_argument("--output-dir",     default="/tmp/thor-lora")
    parser.add_argument("--epochs",         type=int, default=3)
    parser.add_argument("--batch-size",     type=int, default=4)
    parser.add_argument("--lora-r",         type=int, default=64)
    parser.add_argument("--train-data",     required=True)
    parser.add_argument("--eval-data",      required=True)
    args = parser.parse_args()

    config = LoraTrainerConfig(
        base_model      = args.model,
        output_dir      = args.output_dir,
        num_epochs      = args.epochs,
        batch_size      = args.batch_size,
        lora_r          = args.lora_r,
        train_data_path = args.train_data,
        eval_data_path  = args.eval_data,
    )
    trainer = ThorLoraTrainer(config)
    trainer.train()
