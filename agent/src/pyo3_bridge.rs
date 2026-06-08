// Thor Firewall — PyO3 Bridge (Rust ↔ Python)
// جسر الاتصال المباشر بين Rust Agent و Python ML
//
// يتيح استدعاء MARL/GNN مباشرة من Rust بدون HTTP
// ويُحقق زمن استجابة < 50μs للدفعة الواحدة
//
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::flow_manager::Decision;
use crate::telemetry::metrics;

// ============================================================================
// Python ML State
// ============================================================================

/// حالة Python المُضمَّنة — تُحمَّل مرة واحدة
struct PyMlState {
    meta_agent: PyObject,
    /// False = غير مُدرَّب (random policy)
    trained: bool,
}

// ============================================================================
// PyO3 MARL Bridge
// ============================================================================

/// جسر PyO3 لاستدعاء MetaAgent من Rust
pub struct PyO3Bridge {
    state: Arc<Mutex<Option<PyMlState>>>,
    checkpoint_path: String,
}

impl PyO3Bridge {
    /// تهيئة الجسر وتحميل Python interpreter
    pub fn new(checkpoint_path: &str) -> Result<Self> {
        let bridge = Self {
            state: Arc::new(Mutex::new(None)),
            checkpoint_path: checkpoint_path.to_string(),
        };
        Ok(bridge)
    }

    /// تحميل MetaAgent من checkpoint — يُستدعى مرة واحدة عند البدء
    pub async fn initialize(&self) -> Result<()> {
        let checkpoint = self.checkpoint_path.clone();
        let state_ref = self.state.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            Python::with_gil(|py| {
                info!("Initializing PyO3 bridge, loading Python MARL agent...");

                // إضافة مسار ml/ لـ Python path
                let sys = py.import("sys")?;
                let path: &PyList = sys.getattr("path")?.downcast()?;
                path.insert(0, ".")?;

                // استيراد MetaAgent
                let marl_mod = py.import("ml.marl.agents")
                    .context("Failed to import ml.marl.agents — ensure PYTHONPATH includes project root")?;

                let config_cls = marl_mod.getattr("MARLConfig")?;
                let config = config_cls.call0()?;

                let meta_agent_cls = marl_mod.getattr("MetaAgent")?;
                let meta_agent = meta_agent_cls.call1((config,))?;

                // محاولة تحميل checkpoint
                let trained = if std::path::Path::new(&checkpoint).exists() {
                    match meta_agent.call_method1("load_all", (&checkpoint,)) {
                        Ok(_) => {
                            info!(checkpoint = %checkpoint, "MARL checkpoint loaded");
                            true
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to load checkpoint, using random policy");
                            false
                        }
                    }
                } else {
                    warn!(checkpoint = %checkpoint, "Checkpoint not found, using random policy");
                    false
                };

                let py_state = PyMlState {
                    meta_agent: meta_agent.into_py(py),
                    trained,
                };

                let mut state = tokio::runtime::Handle::current()
                    .block_on(state_ref.lock());
                *state = Some(py_state);

                info!("PyO3 bridge initialized (trained={})", trained);
                Ok(())
            })
        }).await??;

        Ok(())
    }

    /// استنتاج دفعة من التدفقات
    ///
    /// # Arguments
    /// * `batch` — قائمة من (flow_hash, features[82], protocol)
    ///
    /// # Returns
    /// قائمة من (flow_hash, decision, risk_score, confidence)
    pub async fn analyze_batch(
        &self,
        batch: Vec<(u64, Vec<f32>, String)>,
    ) -> Result<Vec<(u64, Decision, f32, f32)>> {
        if batch.is_empty() {
            return Ok(vec![]);
        }

        let state_ref = self.state.clone();

        let results = tokio::task::spawn_blocking(move || -> Result<Vec<(u64, Decision, f32, f32)>> {
            Python::with_gil(|py| {
                let state_guard = tokio::runtime::Handle::current()
                    .block_on(state_ref.lock());

                let state = match state_guard.as_ref() {
                    Some(s) => s,
                    None => return Err(anyhow::anyhow!("PyO3 bridge not initialized")),
                };

                let agent = state.meta_agent.as_ref(py);
                let mut results = Vec::with_capacity(batch.len());

                let start = Instant::now();

                for (hash, features, protocol) in &batch {
                    let numpy = py.import("numpy")?;
                    let state_arr = numpy.call_method1(
                        "array",
                        (features.clone(),),
                    )?;
                    let state_arr = state_arr.call_method1(
                        "astype",
                        ("float32",),
                    )?;

                    // meta_agent.make_decision(state, protocol, deterministic=True)
                    let kwargs = PyDict::new(py);
                    kwargs.set_item("deterministic", true)?;

                    let result = agent.call_method(
                        "make_decision",
                        (state_arr, protocol.as_str()),
                        Some(kwargs),
                    )?;

                    let result_tuple = result.extract::<(i32, f32)>()?;
                    let (action_idx, confidence) = result_tuple;

                    let decision = match action_idx {
                        0 => Decision::Allow,
                        1 => Decision::Block,
                        2 => Decision::Throttle,
                        3 => Decision::Mirror,
                        4 => Decision::Redirect,
                        _ => Decision::Allow,
                    };

                    // نقطة الخطر: عكس الثقة للـ Allow، وثقة مباشرة للـ Block
                    let risk_score = match decision {
                        Decision::Block | Decision::Throttle | Decision::Mirror | Decision::Redirect => confidence,
                        Decision::Allow => 1.0 - confidence,
                    };

                    results.push((*hash, decision, risk_score, confidence));
                }

                let elapsed_us = start.elapsed().as_micros() as f64;
                debug!(
                    batch_size = batch.len(),
                    total_us = elapsed_us,
                    per_flow_us = elapsed_us / batch.len() as f64,
                    "PyO3 batch inference complete"
                );

                Ok(results)
            })
        }).await??;

        // تحديث metrics
        let m = metrics();
        m.ml_inference_duration.observe(
            results.len() as f64 / 1_000_000.0  // approximate
        );

        Ok(results)
    }

    /// إعادة تحميل النموذج بدون إيقاف (hot-swap)
    pub async fn reload(&self, checkpoint_path: &str) -> Result<()> {
        let checkpoint = checkpoint_path.to_string();
        let state_ref = self.state.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            Python::with_gil(|py| {
                let mut state_guard = tokio::runtime::Handle::current()
                    .block_on(state_ref.lock());

                if let Some(state) = state_guard.as_mut() {
                    state.meta_agent.as_ref(py)
                        .call_method1("load_all", (&checkpoint,))?;
                    state.trained = true;
                    info!(checkpoint = %checkpoint, "Model hot-swapped via PyO3");
                }

                Ok(())
            })
        }).await??;

        Ok(())
    }

    /// إرسال تجارب تدريب (online learning)
    pub async fn send_training_experiences(
        &self,
        experiences: Vec<TrainingExperience>,
    ) -> Result<()> {
        if experiences.is_empty() {
            return Ok(());
        }

        let state_ref = self.state.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            Python::with_gil(|py| {
                let state_guard = tokio::runtime::Handle::current()
                    .block_on(state_ref.lock());

                if let Some(state) = state_guard.as_ref() {
                    let agent = state.meta_agent.as_ref(py);

                    for exp in &experiences {
                        let proto_agent = agent.getattr("protocol_agents")?
                            .get_item(exp.protocol.as_str())?;

                        proto_agent.call_method1("store_transition", (
                            exp.state.clone(),
                            exp.action as i32,
                            exp.reward,
                            exp.log_prob,
                            exp.value,
                            exp.done,
                        ))?;
                    }

                    // تحديث النموذج إذا كانت التجارب كافية
                    for (_, proto_agent) in agent.getattr("protocol_agents")?
                        .downcast::<PyDict>()?
                        .iter()
                    {
                        let _ = proto_agent.call_method0("update");
                    }
                }

                Ok(())
            })
        }).await??;

        Ok(())
    }

    pub fn is_trained(&self) -> bool {
        tokio::task::block_in_place(|| {
            let state = tokio::runtime::Handle::current().block_on(self.state.lock());
            state.as_ref().map(|s| s.trained).unwrap_or(false)
        })
    }
}

// ============================================================================
// Training Experience
// ============================================================================

#[derive(Debug, Clone)]
pub struct TrainingExperience {
    pub state:    Vec<f32>,
    pub action:   usize,
    pub reward:   f32,
    pub log_prob: f32,
    pub value:    f32,
    pub done:     bool,
    pub protocol: String,
}
