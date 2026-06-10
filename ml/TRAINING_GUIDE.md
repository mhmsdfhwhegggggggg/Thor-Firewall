# Thor Firewall — ML Training Guide

## Overview

Thor uses a two-phase training pipeline:

```
Phase 1: Supervised Pretraining (CICIDS2017/2018)
  ├── Dataset loader:    ml/data/dataset_loader.py
  ├── Feature pipeline:  ml/data/feature_engineering.py  
  ├── Actor network:     ml/marl/brain/actor.py
  ├── Critic network:    ml/marl/brain/critic.py
  └── PPO trainer:       ml/marl/brain/ppo.py

Phase 2: RL Fine-tuning (Thor Environment)
  ├── MARL environment:  ml/marl/environment.py
  ├── Ray RLlib:         ml/marl/ray_trainer.py
  └── Reward shaping:    ml/marl/agents.py
```

## Step 1 — Download Dataset

```bash
# Option A: Kaggle (easiest)
pip install kaggle
kaggle datasets download -d cicdataset/cicids2017
unzip cicids2017.zip -d ./data/CICIDS2017

# Option B: Manual from UNB
# https://www.unb.ca/cic/datasets/ids-2017.html
```

## Step 2 — Install Dependencies

```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
pip install scikit-learn pandas numpy mlflow
pip install torch-geometric  # for GNN
```

## Step 3 — Run Training

```bash
# Quick smoke test (synthetic data)
python -m ml.training.train_marl --dry-run

# Full training on CICIDS2017
python -m ml.training.train_marl \
    --data-dir ./data/CICIDS2017 \
    --epochs 30 \
    --device cuda \
    --export-onnx \
    --mlflow-uri http://localhost:5000

# Expected output:
# [Pretrain  1/30] loss=1.2341  train_acc=0.612  val_acc=0.589
# ...
# [Pretrain 30/30] loss=0.0823  train_acc=0.974  val_acc=0.971
# Test accuracy: 0.9728  |  F1 macro: 0.9341  |  F1 weighted: 0.9714
```

## Step 4 — Outputs

```
models/
  thor_marl_best.pt    ← PyTorch checkpoint (Actor + Critic)
  thor_marl_pretrain.pt
  thor_actor.onnx      ← ONNX (for production inference, no Python)
  thor_scaler.pkl      ← RobustScaler for feature normalization
  training_metrics.json
```

## Step 5 — Deploy

```bash
# Copy models to inference server
cp models/thor_marl_best.pt /models/
cp models/thor_actor.onnx   /models/
cp models/thor_scaler.pkl   /models/

# Restart inference server
docker compose restart thor-ml
```

## Architecture

| Component | Architecture | Input | Output |
|-----------|-------------|-------|--------|
| Actor     | ResNet + SwiGLU | 82 features | 8 class probs |
| Critic    | MHA + ResNet | 328 global state | V(s) value |
| GNN       | GraphSAGE + GATv2 | Network topology | Node risk scores |
| UEBA      | IsolationForest + LSTM | Behavioral sequence | Anomaly score |

## Dataset Classes (8 total)

```
0: BENIGN       — Normal traffic
1: DoS          — Denial of Service (Hulk, Slowloris, GoldenEye)
2: DDoS         — Distributed DoS
3: PortScan     — Port scanning
4: BruteForce   — FTP/SSH/HTTP brute force
5: WebAttack    — SQLi, XSS, Brute Force web
6: Bot/C2       — Botnet / Command & Control
7: Infiltration — APT / Data exfiltration
```

## Performance Targets

Training on CICIDS2017 should achieve:
- **Accuracy**: > 97%
- **F1 Macro**: > 93%
- **Inference**: < 1ms per flow (CPU batch of 256)
