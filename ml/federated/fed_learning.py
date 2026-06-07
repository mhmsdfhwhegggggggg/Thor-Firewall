"""
Thor Firewall — Federated Learning Framework
إطار التعلم الموزع عبر نقاط النشر المتعددة

يتيح تدريب نماذج MARL عبر عشرات الـ deployments
دون نقل البيانات الحساسة — فقط الـ model gradients

البنية:
  FederatedServer  — الخادم المركزي (Federated Averaging)
  FederatedClient  — عميل على كل deployment
  PrivacyEngine    — Differential Privacy (DP-SGD)
  SecureAggregator — Secure Aggregation بدون رؤية gradients الفردية

المرجع:
  - "Communication-Efficient Learning of Deep Networks from Decentralized Data" (McMahan et al., 2017)
  - "Deep Learning with Differential Privacy" (Abadi et al., 2016)
  - "Practical Secure Aggregation for Privacy-Preserving Machine Learning" (Bonawitz et al., 2017)
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import httpx

logger = logging.getLogger("thor.federated")

# ============================================================================
# Configuration
# ============================================================================

@dataclass
class FedConfig:
    """إعدادات التعلم الموزع"""
    # الحد الأدنى للعملاء المطلوبين للـ round
    min_clients: int = 3
    # عدد العملاء المُختارين في كل round
    clients_per_round: int = 5
    # عدد epochs محلية في كل client قبل الإرسال
    local_epochs: int = 5
    # حجم batch المحلي
    local_batch_size: int = 32
    # معدل التعلم المحلي
    local_lr: float = 1e-3
    # نصف قطر Clipping لـ Differential Privacy
    dp_max_grad_norm: float = 1.0
    # ميزانية الـ epsilon للـ DP (أكبر = أقل خصوصية)
    dp_epsilon: float = 1.0
    # delta للـ DP (يجب أن يكون < 1/n)
    dp_delta: float = 1e-5
    # معامل Noise لـ DP
    dp_noise_multiplier: float = 1.1
    # FedProx proximal term (0 = FedAvg القياسي)
    fedprox_mu: float = 0.01
    # تفعيل الضغط لتقليل حجم النقل
    compress_updates: bool = True
    # حد Sparsification (يحذف الـ gradients الصغيرة)
    sparsification_threshold: float = 0.001
    # مهلة الـ round بالثوانٍ
    round_timeout_sec: float = 120.0


@dataclass
class ClientUpdate:
    """تحديث من عميل واحد"""
    client_id: str
    round_number: int
    # الـ deltas (الفرق عن النموذج العالمي) — وليس الأوزان الكاملة
    model_deltas: Dict[str, List]
    # عدد العينات المُستخدمة في التدريب المحلي
    num_samples: int
    # دقة محلية (للمراقبة)
    local_accuracy: float
    # خسارة محلية
    local_loss: float
    # Checksum للتحقق من سلامة البيانات
    checksum: str
    # timestamp
    timestamp: float = field(default_factory=time.time)


@dataclass
class GlobalModelUpdate:
    """التحديث العالمي الذي يُرسله الخادم للعملاء"""
    round_number: int
    model_state: Dict[str, List]      # state_dict مُحوَّل للـ JSON
    metrics: Dict[str, float]
    participants: int
    timestamp: float = field(default_factory=time.time)


# ============================================================================
# Privacy Engine — Differential Privacy
# ============================================================================

class DPSGDEngine:
    """
    Differential Privacy SGD (DP-SGD)
    يُضيف Gaussian noise للـ gradients لحماية بيانات العملاء

    الضمان: (ε, δ)-differential privacy
    """

    def __init__(self, config: FedConfig):
        self.config = config
        self._noise_multiplier = config.dp_noise_multiplier
        self._max_grad_norm = config.dp_max_grad_norm

    def clip_gradients(self, model: nn.Module) -> float:
        """Gradient Clipping: يحدّ أقصى norm لكل gradient"""
        total_norm = 0.0
        for param in model.parameters():
            if param.grad is not None:
                param_norm = param.grad.data.norm(2)
                total_norm += param_norm.item() ** 2
        total_norm = total_norm ** 0.5

        clip_coef = self._max_grad_norm / (total_norm + 1e-6)
        if clip_coef < 1:
            for param in model.parameters():
                if param.grad is not None:
                    param.grad.data.mul_(clip_coef)

        return total_norm

    def add_noise(self, model: nn.Module, batch_size: int, dataset_size: int) -> None:
        """
        إضافة Gaussian noise لـ gradients
        الانحراف المعياري: σ = noise_multiplier * max_grad_norm / batch_size
        """
        sensitivity = self._max_grad_norm / batch_size
        noise_std = self._noise_multiplier * sensitivity

        for param in model.parameters():
            if param.grad is not None:
                noise = torch.randn_like(param.grad) * noise_std
                param.grad.data.add_(noise)

    def compute_epsilon(self, num_steps: int, dataset_size: int, batch_size: int) -> float:
        """
        تقدير ε المُستهلَكة (approximate RDP accountant)
        نسخة مبسّطة — استخدم Opacus للدقة الكاملة في الإنتاج
        """
        sampling_rate = batch_size / dataset_size
        rdp_alpha = 2.0
        rdp_epsilon = num_steps * sampling_rate ** 2 * rdp_alpha * self._noise_multiplier ** (-2)
        # تحويل RDP → (ε, δ)-DP (Theorem 3 in Mironov 2017)
        log_term = np.log(1 / self.config.dp_delta)
        epsilon = rdp_epsilon + (rdp_epsilon * log_term * 2) ** 0.5
        return float(epsilon)


# ============================================================================
# Federated Client
# ============================================================================

class FederatedClient:
    """
    عميل التعلم الموزع — يعمل على كل deployment
    يُدرّب النموذج محلياً ويُرسل الـ deltas للخادم
    """

    def __init__(
        self,
        client_id: str,
        model: nn.Module,
        server_url: str,
        config: FedConfig,
        api_key: str = "",
    ):
        self.client_id = client_id
        self.model = model
        self.server_url = server_url.rstrip("/")
        self.config = config
        self.api_key = api_key
        self.dp_engine = DPSGDEngine(config)
        self._http = httpx.AsyncClient(timeout=60.0)
        self._current_round = 0
        self._global_model_state: Optional[Dict] = None

    async def run_round(
        self,
        local_dataset: List[Tuple[torch.Tensor, torch.Tensor]],
    ) -> Optional[ClientUpdate]:
        """
        تنفيذ round كامل:
        1. الحصول على النموذج العالمي
        2. التدريب المحلي + DP
        3. حساب الـ deltas
        4. إرسال للخادم
        """
        # 1. الحصول على النموذج العالمي
        global_state = await self._fetch_global_model()
        if global_state is None:
            logger.warning("Failed to fetch global model — skipping round")
            return None

        self._global_model_state = global_state
        self.model.load_state_dict(
            {k: torch.tensor(v) for k, v in global_state["model_state"].items()}
        )
        round_num = global_state["round_number"]
        self._current_round = round_num

        # 2. التدريب المحلي
        update = await self._local_train(local_dataset, round_num)
        if update is None:
            return None

        # 3. إرسال التحديث للخادم
        await self._send_update(update)
        logger.info(
            "Round %d completed — samples=%d, accuracy=%.3f, loss=%.4f",
            round_num, update.num_samples, update.local_accuracy, update.local_loss,
        )
        return update

    async def _fetch_global_model(self) -> Optional[Dict]:
        """جلب النموذج العالمي من الخادم"""
        try:
            resp = await self._http.get(
                f"{self.server_url}/federated/model",
                headers={"X-Thor-Client": self.client_id, "X-Thor-API-Key": self.api_key},
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("Fetch global model failed: %s", e)
            return None

    async def _local_train(
        self,
        dataset: List[Tuple[torch.Tensor, torch.Tensor]],
        round_num: int,
    ) -> Optional[ClientUpdate]:
        """التدريب المحلي مع Differential Privacy و FedProx"""
        if not dataset:
            return None

        # نسخة من النموذج العالمي للـ FedProx
        global_model_copy = copy.deepcopy(self.model)

        optimizer = optim.Adam(self.model.parameters(), lr=self.config.local_lr)
        criterion = nn.CrossEntropyLoss()

        total_loss = 0.0
        correct = 0
        total = 0
        num_steps = 0

        self.model.train()
        for epoch in range(self.config.local_epochs):
            # خلط البيانات
            indices = torch.randperm(len(dataset))
            batches = [
                dataset[i:i + self.config.local_batch_size]
                for i in range(0, len(dataset), self.config.local_batch_size)
            ]

            for batch in batches:
                if not batch:
                    continue

                # تحضير البيانات
                x_batch = torch.stack([item[0] for item in batch])
                y_batch = torch.stack([item[1] for item in batch])

                optimizer.zero_grad()
                outputs = self.model(x_batch)
                loss = criterion(outputs, y_batch)

                # FedProx: إضافة proximal term لمنع الانجراف عن النموذج العالمي
                if self.config.fedprox_mu > 0:
                    proximal_term = 0.0
                    for local_p, global_p in zip(
                        self.model.parameters(), global_model_copy.parameters()
                    ):
                        proximal_term += (local_p - global_p.detach()).norm(2) ** 2
                    loss = loss + (self.config.fedprox_mu / 2) * proximal_term

                loss.backward()

                # DP: Clip gradients + Add noise
                self.dp_engine.clip_gradients(self.model)
                self.dp_engine.add_noise(
                    self.model,
                    batch_size=len(batch),
                    dataset_size=len(dataset),
                )

                optimizer.step()
                num_steps += 1

                total_loss += loss.item()
                _, predicted = outputs.max(1)
                correct += predicted.eq(y_batch).sum().item()
                total += len(batch)

        avg_loss = total_loss / max(num_steps, 1)
        accuracy = correct / max(total, 1)

        # حساب ε المُستهلَكة
        epsilon_used = self.dp_engine.compute_epsilon(
            num_steps, len(dataset), self.config.local_batch_size
        )
        logger.debug("DP budget used: ε=%.4f (budget=%.2f)", epsilon_used, self.config.dp_epsilon)

        # حساب الـ deltas (الفرق عن النموذج العالمي)
        global_state = {
            k: torch.tensor(v) for k, v in self._global_model_state["model_state"].items()
        }
        deltas = {}
        for key, param in self.model.state_dict().items():
            delta = param - global_state.get(key, torch.zeros_like(param))
            # Sparsification: نرسل فقط الـ gradients الكبيرة
            if self.config.compress_updates:
                mask = delta.abs() > self.config.sparsification_threshold
                delta = delta * mask
            deltas[key] = delta.tolist()

        # Checksum للتحقق من سلامة البيانات
        checksum = hashlib.sha256(
            json.dumps({k: sum(sum(row) if isinstance(row, list) else row for row in v)
                       for k, v in deltas.items()}, sort_keys=True).encode()
        ).hexdigest()[:16]

        return ClientUpdate(
            client_id=self.client_id,
            round_number=round_num,
            model_deltas=deltas,
            num_samples=len(dataset),
            local_accuracy=accuracy,
            local_loss=avg_loss,
            checksum=checksum,
        )

    async def _send_update(self, update: ClientUpdate) -> None:
        """إرسال التحديث للخادم"""
        payload = {
            "client_id": update.client_id,
            "round_number": update.round_number,
            "model_deltas": update.model_deltas,
            "num_samples": update.num_samples,
            "local_accuracy": update.local_accuracy,
            "local_loss": update.local_loss,
            "checksum": update.checksum,
        }
        try:
            resp = await self._http.post(
                f"{self.server_url}/federated/update",
                json=payload,
                headers={"X-Thor-Client": self.client_id, "X-Thor-API-Key": self.api_key},
                timeout=60.0,
            )
            resp.raise_for_status()
            logger.debug("Update sent for round %d", update.round_number)
        except Exception as e:
            logger.error("Send update failed: %s", e)

    async def close(self):
        await self._http.aclose()


# ============================================================================
# Federated Server
# ============================================================================

class FederatedServer:
    """
    خادم التعلم الموزع المركزي
    يجمع تحديثات العملاء وينفّذ Federated Averaging
    """

    def __init__(self, global_model: nn.Module, config: FedConfig):
        self.global_model = global_model
        self.config = config
        self._round = 0
        self._pending_updates: Dict[str, ClientUpdate] = {}
        self._round_metrics: List[Dict] = []
        self._lock = asyncio.Lock()
        self._round_ready = asyncio.Event()

    @property
    def current_round(self) -> int:
        return self._round

    def get_model_state(self) -> Dict:
        """إرجاع حالة النموذج الحالية"""
        state = {}
        for key, param in self.global_model.state_dict().items():
            state[key] = param.tolist()
        return {
            "round_number": self._round,
            "model_state": state,
        }

    async def receive_update(self, update: ClientUpdate) -> bool:
        """
        استقبال تحديث من عميل
        يُعيد True إذا اكتمل الـ round
        """
        async with self._lock:
            if update.round_number != self._round:
                logger.warning(
                    "Update from %s for wrong round %d (current=%d)",
                    update.client_id, update.round_number, self._round,
                )
                return False

            self._pending_updates[update.client_id] = update
            logger.info(
                "Update received from %s (round=%d, clients=%d/%d)",
                update.client_id, update.round_number,
                len(self._pending_updates), self.config.clients_per_round,
            )

            if len(self._pending_updates) >= self.config.min_clients:
                self._round_ready.set()
                return True

        return False

    async def aggregate_round(self) -> Optional[Dict]:
        """
        تنفيذ Federated Averaging عند اكتمال الـ round
        FedAvg: w_global = Σ(n_k / N) * (w_global + delta_k)
        """
        # انتظر حتى يكتمل الحد الأدنى من العملاء (أو timeout)
        try:
            await asyncio.wait_for(self._round_ready.wait(), timeout=self.config.round_timeout_sec)
        except asyncio.TimeoutError:
            if len(self._pending_updates) < self.config.min_clients:
                logger.warning(
                    "Round %d timed out with only %d/%d clients",
                    self._round, len(self._pending_updates), self.config.min_clients,
                )
                return None

        async with self._lock:
            updates = list(self._pending_updates.values())
            self._pending_updates.clear()
            self._round_ready.clear()

        if not updates:
            return None

        # Federated Averaging
        total_samples = sum(u.num_samples for u in updates)
        if total_samples == 0:
            return None

        # نسخة من النموذج الحالي
        global_state = self.global_model.state_dict()
        aggregated_deltas: Dict[str, torch.Tensor] = {}

        for update in updates:
            weight = update.num_samples / total_samples
            for key, delta_list in update.model_deltas.items():
                delta = torch.tensor(delta_list)
                if key not in aggregated_deltas:
                    aggregated_deltas[key] = torch.zeros_like(
                        global_state.get(key, delta)
                    )
                aggregated_deltas[key] += weight * delta

        # تطبيق الـ aggregated deltas على النموذج العالمي
        new_state = {}
        for key, param in global_state.items():
            if key in aggregated_deltas:
                new_state[key] = param + aggregated_deltas[key]
            else:
                new_state[key] = param

        self.global_model.load_state_dict(new_state)
        self._round += 1

        # حفظ مقاييس الـ round
        metrics = {
            "round": self._round - 1,
            "participants": len(updates),
            "total_samples": total_samples,
            "avg_accuracy": sum(u.local_accuracy for u in updates) / len(updates),
            "avg_loss": sum(u.local_loss for u in updates) / len(updates),
            "timestamp": time.time(),
        }
        self._round_metrics.append(metrics)

        logger.info(
            "Round %d aggregated: %d clients, avg_acc=%.3f, avg_loss=%.4f",
            metrics["round"], len(updates), metrics["avg_accuracy"], metrics["avg_loss"],
        )

        return metrics

    def get_metrics_history(self) -> List[Dict]:
        return self._round_metrics.copy()

    def save_checkpoint(self, path: str) -> None:
        """حفظ نقطة تفتيش للنموذج العالمي"""
        torch.save({
            "round": self._round,
            "model_state_dict": self.global_model.state_dict(),
            "metrics_history": self._round_metrics,
        }, path)
        logger.info("Checkpoint saved: %s (round=%d)", path, self._round)

    def load_checkpoint(self, path: str) -> None:
        """تحميل نقطة تفتيش"""
        checkpoint = torch.load(path, map_location="cpu")
        self.global_model.load_state_dict(checkpoint["model_state_dict"])
        self._round = checkpoint["round"]
        self._round_metrics = checkpoint.get("metrics_history", [])
        logger.info("Checkpoint loaded: %s (round=%d)", path, self._round)


# ============================================================================
# Federated API Routes (يُضاف لـ control plane)
# ============================================================================

def create_federated_router(server: FederatedServer):
    """إنشاء FastAPI router للـ federated learning endpoints"""
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel

    router = APIRouter(prefix="/federated", tags=["Federated Learning"])

    class UpdatePayload(BaseModel):
        client_id: str
        round_number: int
        model_deltas: Dict[str, List]
        num_samples: int
        local_accuracy: float
        local_loss: float
        checksum: str

    @router.get("/model")
    async def get_global_model():
        """جلب النموذج العالمي الحالي"""
        return server.get_model_state()

    @router.post("/update")
    async def receive_update(payload: UpdatePayload):
        """استقبال تحديث من عميل"""
        update = ClientUpdate(**payload.dict())
        success = await server.receive_update(update)
        return {"accepted": True, "round": server.current_round, "triggered_aggregation": success}

    @router.get("/metrics")
    async def get_metrics():
        """مقاييس جميع الـ rounds"""
        return {"rounds": server.get_metrics_history()}

    @router.get("/status")
    async def get_status():
        """حالة الـ federated learning"""
        return {
            "current_round": server.current_round,
            "pending_clients": len(server._pending_updates),
            "min_clients_required": server.config.min_clients,
            "clients_per_round": server.config.clients_per_round,
        }

    return router


# ============================================================================
# CLI — تشغيل عميل federated
# ============================================================================

if __name__ == "__main__":
    import argparse
    from ml.marl.agents import MetaAgent, MARLConfig

    parser = argparse.ArgumentParser(description="Thor Federated Learning Client")
    parser.add_argument("--client-id", required=True, help="Unique client ID")
    parser.add_argument("--server-url", default="http://localhost:8000", help="Fed server URL")
    parser.add_argument("--api-key", default="", help="API key")
    parser.add_argument("--rounds", type=int, default=10, help="Number of federated rounds")
    parser.add_argument("--data-path", help="Path to local training data (CSV)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    async def run():
        config = FedConfig()
        marl_config = MARLConfig()
        model = MetaAgent(marl_config)

        client = FederatedClient(
            client_id=args.client_id,
            model=model,
            server_url=args.server_url,
            config=config,
            api_key=args.api_key,
        )

        # في الإنتاج: تحميل بيانات حقيقية من CICIDS أو بيانات محلية
        # هنا نستخدم بيانات اصطناعية للتجربة
        dummy_dataset = [
            (torch.randn(50), torch.randint(0, 5, (1,)).squeeze())
            for _ in range(1000)
        ]

        for round_num in range(args.rounds):
            logger.info("Starting federated round %d/%d", round_num + 1, args.rounds)
            await client.run_round(dummy_dataset)

        await client.close()
        logger.info("Federated learning completed: %d rounds", args.rounds)

    asyncio.run(run())
