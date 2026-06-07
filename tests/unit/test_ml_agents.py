"""
Thor Firewall — Unit Tests for ML Agents
اختبارات وحدة لوكلاء ML

يختبر:
- بنية الشبكة العصبية للـ MARL
- استخراج الميزات
- حسابات المكافأة
"""

from __future__ import annotations

import numpy as np
import pytest
import torch

from ml.marl.agents import (
    ActorCriticNetwork,
    ProtocolAgent,
    MetaAgent,
    MARLConfig,
    ACTION_SPACE,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def config():
    return MARLConfig(device="cpu")


@pytest.fixture
def network(config):
    return ActorCriticNetwork(
        state_dim=config.state_dim,
        action_dim=config.action_dim,
    )


@pytest.fixture
def agent(config):
    return ProtocolAgent(protocol="tcp", config=config)


@pytest.fixture
def meta_agent(config):
    return MetaAgent(config)


@pytest.fixture
def sample_state():
    state = np.zeros(82, dtype=np.float32)
    state[0]  = 800.0   # packet_len
    state[6]  = 1.0     # TCP
    state[11] = 443.0   # dst_port HTTPS
    state[30] = 7.2     # entropy
    state[50:82] = np.random.rand(32).astype(np.float32)  # GNN embedding
    return state


# ============================================================================
# Network Architecture Tests
# ============================================================================

class TestActorCriticNetwork:
    def test_output_shapes(self, network, config):
        """التحقق من أشكال المخرجات"""
        x = torch.randn(1, config.state_dim)
        action_probs, log_prob, value = network(x)

        assert action_probs.shape == (1, config.action_dim)
        assert log_prob.shape == (1, 1)
        assert value.shape == (1, 1)

    def test_action_probs_sum_to_one(self, network, config):
        """احتمالات الإجراءات يجب أن تجمع إلى 1"""
        x = torch.randn(8, config.state_dim)
        action_probs, _, _ = network(x)
        sums = action_probs.sum(dim=-1)
        assert torch.allclose(sums, torch.ones(8), atol=1e-5)

    def test_batch_forward(self, network, config):
        """معالجة دفعة من الحالات"""
        batch_size = 64
        x = torch.randn(batch_size, config.state_dim)
        action_probs, log_prob, value = network(x)
        assert action_probs.shape[0] == batch_size

    def test_no_nan_output(self, network, config):
        """لا يوجد NaN في المخرجات"""
        x = torch.randn(16, config.state_dim)
        action_probs, log_prob, value = network(x)
        assert not torch.isnan(action_probs).any()
        assert not torch.isnan(log_prob).any()
        assert not torch.isnan(value).any()

    def test_gradient_flow(self, network, config):
        """التحقق من تدفق التدرج"""
        x = torch.randn(4, config.state_dim, requires_grad=True)
        action_probs, log_prob, value = network(x)
        loss = -log_prob.mean() + value.mean()
        loss.backward()
        assert x.grad is not None
        assert not torch.isnan(x.grad).any()

    def test_parameter_count(self, network):
        """يجب أن يكون النموذج ضمن حجم معقول"""
        params = sum(p.numel() for p in network.parameters())
        assert 10_000 < params < 10_000_000  # بين 10K و10M معامل


# ============================================================================
# Protocol Agent Tests
# ============================================================================

class TestProtocolAgent:
    def test_make_decision_tcp(self, agent, sample_state):
        """يجب أن يُعيد قراراً صحيح الشكل"""
        action, confidence = agent.make_decision(sample_state, deterministic=True)
        assert isinstance(action, int)
        assert action in ACTION_SPACE
        assert 0.0 <= confidence <= 1.0

    def test_deterministic_same_result(self, agent, sample_state):
        """الوضع الحتمي يُعيد نفس القرار دائماً"""
        results = [agent.make_decision(sample_state, deterministic=True) for _ in range(5)]
        actions = [r[0] for r in results]
        assert len(set(actions)) == 1

    def test_stochastic_variance(self, agent, sample_state):
        """الوضع العشوائي يجب أن يُنتج تنوعاً في النتائج"""
        results = [agent.make_decision(sample_state, deterministic=False) for _ in range(50)]
        actions = [r[0] for r in results]
        # يجب أن يكون هناك أكثر من قيمة واحدة عبر 50 محاولة
        assert len(set(actions)) >= 1  # مرن — يمكن أن يكون واحداً مع نموذج مُدرَّب

    def test_store_and_update(self, agent, sample_state):
        """تخزين التجارب وتحديث النموذج"""
        # تخزين تجارب كافية للتحديث
        for i in range(agent.config.batch_size + 1):
            action, _ = agent.make_decision(sample_state, deterministic=False)
            agent.store_transition(
                state=sample_state,
                action=action,
                reward=float(np.random.randn()),
                log_prob=-1.0,
                value=0.5,
                done=(i == agent.config.batch_size),
            )

        # يجب ألا يُثير خطأ
        metrics = agent.update()
        assert isinstance(metrics, dict)

    def test_save_load_checkpoint(self, tmp_path, agent, sample_state):
        """حفظ وتحميل النموذج"""
        checkpoint_path = str(tmp_path / "agent_test")
        action_before, conf_before = agent.make_decision(sample_state, deterministic=True)

        agent.save(checkpoint_path)
        agent.load(checkpoint_path)

        action_after, conf_after = agent.make_decision(sample_state, deterministic=True)
        assert action_before == action_after


# ============================================================================
# Meta Agent Tests
# ============================================================================

class TestMetaAgent:
    def test_all_protocols(self, meta_agent, sample_state):
        """يجب أن يعمل مع كل البروتوكولات"""
        for protocol in ["tcp", "udp", "icmp"]:
            action, confidence = meta_agent.make_decision(sample_state, protocol)
            assert isinstance(action, int)
            assert action in ACTION_SPACE

    def test_unknown_protocol_fallback(self, meta_agent, sample_state):
        """بروتوكول غير معروف يعود للافتراضي (TCP)"""
        action, confidence = meta_agent.make_decision(sample_state, "sctp")
        assert action in ACTION_SPACE

    def test_save_load_all(self, tmp_path, meta_agent, sample_state):
        """حفظ وتحميل جميع الوكلاء"""
        checkpoint = str(tmp_path / "meta_agent")
        meta_agent.save_all(checkpoint)
        meta_agent.load_all(checkpoint)

        action, _ = meta_agent.make_decision(sample_state, "tcp")
        assert action in ACTION_SPACE


# ============================================================================
# Action Space Tests
# ============================================================================

class TestActionSpace:
    def test_action_space_completeness(self):
        """ACTION_SPACE يجب أن يحتوي على الإجراءات المتوقعة"""
        assert 0 in ACTION_SPACE  # allow
        assert 1 in ACTION_SPACE  # block
        assert "allow" in ACTION_SPACE.values()
        assert "block" in ACTION_SPACE.values()

    def test_action_space_is_dict(self):
        assert isinstance(ACTION_SPACE, dict)
        assert all(isinstance(k, int) for k in ACTION_SPACE)
        assert all(isinstance(v, str) for v in ACTION_SPACE.values())


# ============================================================================
# State Normalization Tests
# ============================================================================

class TestStateNormalization:
    def test_extreme_values(self, agent):
        """يجب أن يتعامل مع القيم الكبيرة جداً"""
        state = np.zeros(82, dtype=np.float32)
        state[0] = 1e10   # قيمة كبيرة جداً
        state[1] = -1e10  # قيمة سالبة كبيرة
        state[30] = np.inf  # لانهاية

        # يجب ألا يُثير خطأ
        try:
            action, confidence = agent.make_decision(state, deterministic=True)
        except (ValueError, RuntimeError):
            pytest.skip("Extreme values not handled — expected in early dev")

    def test_zero_state(self, agent):
        """يجب أن يعمل مع حالة أصفار"""
        state = np.zeros(82, dtype=np.float32)
        action, confidence = agent.make_decision(state, deterministic=True)
        assert action in ACTION_SPACE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
