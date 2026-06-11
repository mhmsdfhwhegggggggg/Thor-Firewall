"""
ML Model Cache — Thread-safe LRU cache for loaded PyTorch/ONNX/HuggingFace models
Avoids redundant model loading, manages GPU memory budgets
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import torch

logger = logging.getLogger("thor.ml.model_cache")


@dataclass
class CachedModel:
    model_id:    str
    model:       Any
    tokenizer:   Any | None
    device:      str
    loaded_at:   float = field(default_factory=time.time)
    last_used:   float = field(default_factory=time.time)
    use_count:   int   = 0
    size_bytes:  int   = 0     # estimated GPU/CPU memory footprint

    def touch(self):
        self.last_used = time.time()
        self.use_count += 1


class ModelCache:
    """
    Thread-safe LRU model cache with GPU memory budget management.
    Automatically evicts least-recently-used models when GPU memory is tight.
    """

    DEFAULT_MAX_MODELS     = 4
    DEFAULT_GPU_BUDGET_MB  = 16_000   # 16GB for A100 or similar
    DEFAULT_CPU_BUDGET_MB  = 32_000

    def __init__(
        self,
        max_models:     int = DEFAULT_MAX_MODELS,
        gpu_budget_mb:  int = DEFAULT_GPU_BUDGET_MB,
        cpu_budget_mb:  int = DEFAULT_CPU_BUDGET_MB,
    ):
        self.max_models    = max_models
        self.gpu_budget_mb = gpu_budget_mb
        self.cpu_budget_mb = cpu_budget_mb
        self._cache: OrderedDict[str, CachedModel] = OrderedDict()
        self._lock  = threading.RLock()
        self._stats = {"hits": 0, "misses": 0, "evictions": 0}

    def get(self, model_id: str) -> CachedModel | None:
        with self._lock:
            if model_id in self._cache:
                entry = self._cache[model_id]
                entry.touch()
                # Move to end (most recently used)
                self._cache.move_to_end(model_id)
                self._stats["hits"] += 1
                return entry
            self._stats["misses"] += 1
            return None

    def put(self, entry: CachedModel):
        with self._lock:
            if entry.model_id in self._cache:
                self._cache.move_to_end(entry.model_id)
                self._cache[entry.model_id] = entry
                return

            # Evict if at capacity
            while len(self._cache) >= self.max_models:
                self._evict_lru()

            # Check memory budget
            if not self._fits_in_budget(entry):
                self._evict_until_fits(entry.size_bytes, entry.device)

            self._cache[entry.model_id] = entry
            logger.info(
                "Cached model: %s device=%s size=%.1fMB total_cached=%d",
                entry.model_id, entry.device,
                entry.size_bytes / 1024 / 1024,
                len(self._cache),
            )

    def evict(self, model_id: str):
        with self._lock:
            if model_id in self._cache:
                entry = self._cache.pop(model_id)
                self._unload(entry)
                logger.info("Evicted model: %s", model_id)

    def _evict_lru(self):
        if not self._cache:
            return
        model_id, entry = next(iter(self._cache.items()))
        self._cache.pop(model_id)
        self._unload(entry)
        self._stats["evictions"] += 1
        logger.info("LRU eviction: %s (used %d times)", model_id, entry.use_count)

    def _evict_until_fits(self, needed_bytes: int, device: str):
        while self._cache:
            used_bytes = self._total_device_bytes(device)
            budget_bytes = (
                self.gpu_budget_mb * 1024 * 1024 if "cuda" in device
                else self.cpu_budget_mb * 1024 * 1024
            )
            if used_bytes + needed_bytes <= budget_bytes:
                break
            self._evict_lru()

    def _fits_in_budget(self, entry: CachedModel) -> bool:
        used = self._total_device_bytes(entry.device)
        budget = (
            self.gpu_budget_mb * 1024 * 1024 if "cuda" in entry.device
            else self.cpu_budget_mb * 1024 * 1024
        )
        return used + entry.size_bytes <= budget

    def _total_device_bytes(self, device: str) -> int:
        return sum(
            e.size_bytes for e in self._cache.values()
            if e.device == device
        )

    def _unload(self, entry: CachedModel):
        """Free model from memory"""
        try:
            if entry.device.startswith("cuda"):
                del entry.model
                if entry.tokenizer:
                    del entry.tokenizer
                torch.cuda.empty_cache()
        except Exception as e:
            logger.warning("Model unload error: %s", e)

    def estimate_model_size(self, model) -> int:
        """Estimate model memory footprint in bytes"""
        try:
            total = 0
            for param in model.parameters():
                total += param.nelement() * param.element_size()
            for buf in model.buffers():
                total += buf.nelement() * buf.element_size()
            return total
        except Exception:
            return 0

    def stats(self) -> dict:
        with self._lock:
            gpu_used = self._total_device_bytes("cuda") // (1024 * 1024)
            cpu_used = sum(
                e.size_bytes for e in self._cache.values()
                if not e.device.startswith("cuda")
            ) // (1024 * 1024)
            return {
                **self._stats,
                "cached_models":  len(self._cache),
                "gpu_used_mb":    gpu_used,
                "cpu_used_mb":    cpu_used,
                "cache_hit_rate": (
                    self._stats["hits"] / max(1, self._stats["hits"] + self._stats["misses"])
                ),
                "models": [
                    {
                        "id":           e.model_id,
                        "device":       e.device,
                        "size_mb":      e.size_bytes // (1024 * 1024),
                        "use_count":    e.use_count,
                        "last_used_s":  int(time.time() - e.last_used),
                    }
                    for e in self._cache.values()
                ],
            }


# ─────────────── Model Loader with Cache Integration ────────────

class ThorModelLoader:
    """
    Load Thor ML models into cache.
    Supports: PyTorch, ONNX Runtime, HuggingFace Transformers, PEFT/LoRA adapters.
    """

    def __init__(self, cache: ModelCache | None = None):
        self.cache = cache or ModelCache()

    def load_classifier(self, model_path: str, device: str = "auto") -> CachedModel:
        """Load XGBoost/sklearn threat classifier"""
        import joblib

        cached = self.cache.get(model_path)
        if cached:
            return cached

        model_id = self._hash_path(model_path)
        device   = self._resolve_device(device)

        logger.info("Loading classifier: %s", model_path)
        model = joblib.load(model_path)

        entry = CachedModel(
            model_id   = model_id,
            model      = model,
            tokenizer  = None,
            device     = device,
            size_bytes = Path(model_path).stat().st_size,
        )
        self.cache.put(entry)
        return entry

    def load_torch_model(
        self,
        model_path: str,
        model_class,
        model_kwargs: dict | None = None,
        device: str = "auto",
    ) -> CachedModel:
        """Load a PyTorch state_dict model"""
        cached = self.cache.get(model_path)
        if cached:
            return cached

        device = self._resolve_device(device)
        logger.info("Loading PyTorch model: %s → %s", model_path, device)

        model = model_class(**(model_kwargs or {}))
        state = torch.load(model_path, map_location=device, weights_only=True)
        model.load_state_dict(state)
        model.eval()
        model.to(device)

        entry = CachedModel(
            model_id   = self._hash_path(model_path),
            model      = model,
            tokenizer  = None,
            device     = device,
            size_bytes = self.cache.estimate_model_size(model),
        )
        self.cache.put(entry)
        return entry

    def load_hf_model(
        self,
        model_name_or_path: str,
        device: str = "auto",
        load_in_4bit: bool = False,
    ) -> CachedModel:
        """Load HuggingFace model + tokenizer (supports LoRA adapters)"""
        cached = self.cache.get(model_name_or_path)
        if cached:
            return cached

        from transformers import AutoModelForCausalLM, AutoTokenizer
        device = self._resolve_device(device)
        logger.info("Loading HF model: %s", model_name_or_path)

        kwargs: dict = {"device_map": "auto" if "cuda" in device else None}
        if load_in_4bit:
            from transformers import BitsAndBytesConfig
            kwargs["quantization_config"] = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_quant_type="nf4",
            )

        model     = AutoModelForCausalLM.from_pretrained(model_name_or_path, **kwargs)
        tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
        model.eval()

        # Check for PEFT adapter
        adapter_config = Path(model_name_or_path) / "adapter_config.json"
        if adapter_config.exists():
            from peft import PeftModel
            base_model_path = json_load(adapter_config).get("base_model_name_or_path", "")
            if base_model_path:
                base = AutoModelForCausalLM.from_pretrained(base_model_path, **kwargs)
                model = PeftModel.from_pretrained(base, model_name_or_path)
                model.eval()

        entry = CachedModel(
            model_id   = model_name_or_path,
            model      = model,
            tokenizer  = tokenizer,
            device     = device,
            size_bytes = self.cache.estimate_model_size(model),
        )
        self.cache.put(entry)
        return entry

    def load_onnx_model(self, onnx_path: str, device: str = "cpu") -> CachedModel:
        """Load ONNX Runtime session for fast CPU/GPU inference"""
        import onnxruntime as ort

        cached = self.cache.get(onnx_path)
        if cached:
            return cached

        logger.info("Loading ONNX: %s", onnx_path)
        providers = ["CUDAExecutionProvider", "CPUExecutionProvider"] if "cuda" in device else ["CPUExecutionProvider"]
        session = ort.InferenceSession(onnx_path, providers=providers)

        entry = CachedModel(
            model_id   = self._hash_path(onnx_path),
            model      = session,
            tokenizer  = None,
            device     = device,
            size_bytes = Path(onnx_path).stat().st_size,
        )
        self.cache.put(entry)
        return entry

    def _resolve_device(self, device: str) -> str:
        if device == "auto":
            return "cuda" if torch.cuda.is_available() else "cpu"
        return device

    def _hash_path(self, path: str) -> str:
        stat = Path(path).stat()
        return hashlib.md5(f"{path}:{stat.st_mtime}:{stat.st_size}".encode()).hexdigest()[:16]


def json_load(path: Path) -> dict:
    import json
    return json.loads(path.read_text())


# Global singleton
_global_cache  = ModelCache()
_global_loader = ThorModelLoader(_global_cache)

def get_model_cache()  -> ModelCache:      return _global_cache
def get_model_loader() -> ThorModelLoader: return _global_loader
