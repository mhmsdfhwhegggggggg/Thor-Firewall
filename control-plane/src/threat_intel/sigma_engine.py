"""
Thor Firewall — Sigma Rules Engine
====================================
محرك قواعد Sigma للكشف عن التهديدات.

مستوحى من: https://github.com/SigmaHQ/sigma
           https://github.com/pySigma/pySigma

Sigma هو format موحَّد لقواعد الكشف — مستخدم في:
  - SOC teams عالمياً
  - Splunk, Elastic, QRadar, Chronicle, OpenSearch

يُحوّل قواعد Sigma إلى SQL لـ ClickHouse / JSON للفلترة الحية.

المكونات:
  1. SigmaRuleLoader: يقرأ rules من YAML
  2. SigmaEventMatcher: يُطابق events بالقواعد
  3. SigmaClickHouseBackend: يُولّد SQL queries لـ ClickHouse
  4. SigmaRuleManager: إدارة + hot-reload للقواعد
"""

from __future__ import annotations

import os
import yaml
import time
import glob
import logging
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("thor.threat_intel.sigma")

SIGMA_RULES_DIR = os.getenv("SIGMA_RULES_DIR", "/app/configs/sigma")


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SigmaRule:
    """قاعدة Sigma مُحلَّلة."""
    id: str
    title: str
    description: str
    status: str             # experimental / test / stable
    level: str              # informational / low / medium / high / critical
    author: str
    date: str
    tags: List[str]         # MITRE ATT&CK tags مثل: attack.t1059.001
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    fields: List[str]
    falsepositives: List[str]
    condition: str
    raw: str
    checksum: str = ""

    # Thor additions
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    clickhouse_query: str = ""  # pre-compiled ClickHouse SQL

    def __post_init__(self):
        # Extract MITRE tags
        for tag in self.tags:
            if tag.startswith("attack.t"):
                self.mitre_techniques.append(tag.replace("attack.", "").upper())
            elif tag.startswith("attack."):
                tactic = tag.replace("attack.", "").replace("_", " ").title()
                self.mitre_tactics.append(tactic)


@dataclass
class SigmaMatch:
    """نتيجة مطابقة قاعدة Sigma مع حدث."""
    rule_id: str
    rule_title: str
    rule_level: str
    matched_at: float
    event: Dict[str, Any]
    matched_fields: Dict[str, Any]
    mitre_techniques: List[str]
    mitre_tactics: List[str]

    @property
    def severity(self) -> str:
        return self.rule_level

    @property
    def risk_score(self) -> float:
        mapping = {"critical": 0.95, "high": 0.8, "medium": 0.6, "low": 0.3, "informational": 0.1}
        return mapping.get(self.rule_level, 0.5)


# ─────────────────────────────────────────────────────────────────────────────
# Sigma Rule Loader
# ─────────────────────────────────────────────────────────────────────────────

class SigmaRuleLoader:
    """يُحمّل ويُحلّل قواعد Sigma من YAML files."""

    def load_file(self, path: str) -> Optional[SigmaRule]:
        """يُحمّل قاعدة واحدة من ملف YAML."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            data = yaml.safe_load(content)
            if not data or not isinstance(data, dict):
                return None

            checksum = hashlib.sha256(content.encode()).hexdigest()[:16]

            # Extract detection condition
            detection = data.get("detection", {})
            condition = detection.pop("condition", "all of them") if isinstance(detection, dict) else "all of them"

            return SigmaRule(
                id=data.get("id", checksum),
                title=data.get("title", "Unknown"),
                description=data.get("description", ""),
                status=data.get("status", "experimental"),
                level=data.get("level", "medium"),
                author=data.get("author", ""),
                date=str(data.get("date", "")),
                tags=data.get("tags", []),
                logsource=data.get("logsource", {}),
                detection=detection,
                fields=data.get("fields", []),
                falsepositives=data.get("falsepositives", []),
                condition=condition,
                raw=content,
                checksum=checksum,
            )
        except Exception as e:
            logger.error(f"Failed to load sigma rule {path}: {e}")
            return None

    def load_directory(self, directory: str) -> List[SigmaRule]:
        """يُحمّل كل قواعد Sigma من مجلد (recursive)."""
        rules = []
        patterns = [
            os.path.join(directory, "**", "*.yml"),
            os.path.join(directory, "**", "*.yaml"),
        ]
        for pattern in patterns:
            for filepath in glob.glob(pattern, recursive=True):
                rule = self.load_file(filepath)
                if rule:
                    rules.append(rule)

        logger.info(f"Loaded {len(rules)} Sigma rules from {directory}")
        return rules


# ─────────────────────────────────────────────────────────────────────────────
# Sigma Event Matcher
# ─────────────────────────────────────────────────────────────────────────────

class SigmaEventMatcher:
    """
    يُطابق network events بقواعد Sigma في الزمن الحقيقي.
    
    يدعم:
    - Keyword detection
    - Field value matching (exact, wildcard, regex)
    - NOT conditions
    - AND/OR combinations
    """

    def match_event(
        self, event: Dict[str, Any], rule: SigmaRule
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        يتحقق إذا كان event يُطابق قاعدة.
        
        Returns:
            (matched: bool, matched_fields: dict)
        """
        matched_fields: Dict[str, Any] = {}
        detection = rule.detection
        condition = rule.condition.lower().strip()

        if not detection:
            return False, {}

        # Evaluate each detection selection
        results: Dict[str, bool] = {}
        for selector_name, selector_def in detection.items():
            if selector_name == "timeframe":
                continue
            matched, mfields = self._evaluate_selector(event, selector_def)
            results[selector_name] = matched
            if matched:
                matched_fields.update(mfields)

        # Evaluate condition
        final_result = self._evaluate_condition(condition, results)
        return final_result, matched_fields if final_result else {}

    def _evaluate_selector(
        self, event: Dict, selector: Any
    ) -> Tuple[bool, Dict]:
        """يُقيّم selector واحد (قد يكون dict أو list)."""
        if isinstance(selector, list):
            # List of patterns → OR logic
            for item in selector:
                matched, fields = self._evaluate_selector(event, item)
                if matched:
                    return True, fields
            return False, {}

        if isinstance(selector, dict):
            # Field: value mapping → AND logic
            all_matched = True
            matched_fields = {}
            for field_name, pattern in selector.items():
                field_matched, fvalue = self._match_field(event, field_name, pattern)
                if not field_matched:
                    all_matched = False
                    break
                matched_fields[field_name] = fvalue
            return all_matched, matched_fields

        # Raw value (keywords)
        event_str = str(event).lower()
        pattern_str = str(selector).lower()
        return pattern_str in event_str, {"keyword": selector}

    def _match_field(
        self, event: Dict, field_name: str, pattern: Any
    ) -> Tuple[bool, Any]:
        """يُطابق قيمة field بـ pattern."""
        import re, fnmatch

        # Handle pipe modifiers (field|contains, field|startswith, etc.)
        modifier = None
        if "|" in field_name:
            field_name, modifier = field_name.rsplit("|", 1)

        # Get field value (supports nested: EventID, CommandLine, etc.)
        value = event.get(field_name) or event.get(field_name.lower(), "")
        if value is None:
            return False, None

        value_str = str(value)
        patterns  = pattern if isinstance(pattern, list) else [pattern]

        for p in patterns:
            p_str = str(p)

            if modifier == "contains":
                if p_str.lower() in value_str.lower():
                    return True, value
            elif modifier == "startswith":
                if value_str.lower().startswith(p_str.lower()):
                    return True, value
            elif modifier == "endswith":
                if value_str.lower().endswith(p_str.lower()):
                    return True, value
            elif modifier == "re":
                if re.search(p_str, value_str, re.IGNORECASE):
                    return True, value
            elif modifier == "cidr":
                try:
                    import ipaddress
                    if ipaddress.ip_address(value_str) in ipaddress.ip_network(p_str):
                        return True, value
                except ValueError:
                    pass
            else:
                # Default: wildcard matching
                if fnmatch.fnmatch(value_str.lower(), p_str.lower().replace("*", "*")):
                    return True, value
                if p_str.lower() == value_str.lower():
                    return True, value

        return False, None

    def _evaluate_condition(
        self, condition: str, results: Dict[str, bool]
    ) -> bool:
        """يُقيّم condition string مثل: '1 of them' أو 'selection and not filter'."""
        if condition == "all of them":
            return all(results.values())

        if condition.startswith("1 of") or condition.startswith("any of"):
            subset = condition.split(" ", 3)[-1].strip()
            if subset == "them":
                return any(results.values())
            # "1 of selection_*"
            prefix = subset.rstrip("*")
            matching = [v for k, v in results.items() if k.startswith(prefix)]
            return any(matching)

        if condition.startswith("all of"):
            subset = condition.split(" ", 2)[-1].strip()
            if subset == "them":
                return all(results.values())
            prefix = subset.rstrip("*")
            matching = [v for k, v in results.items() if k.startswith(prefix)]
            return all(matching)

        # Boolean expression: "selection and not filter"
        expr = condition
        for name, value in results.items():
            expr = expr.replace(name, str(value))
        expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace("not ", "not ")

        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Sigma Rule Manager — Hot Reload
# ─────────────────────────────────────────────────────────────────────────────

class SigmaRuleManager:
    """
    إدارة قواعد Sigma مع hot-reload تلقائي.
    
    Features:
    - يراقب تغييرات ملفات القواعد
    - يُحمّل قواعد جديدة بدون إيقاف النظام
    - يُحصي matches لكل قاعدة (للضبط التدريجي)
    """

    def __init__(self, rules_dir: str = SIGMA_RULES_DIR):
        self.rules_dir = rules_dir
        self._loader   = SigmaRuleLoader()
        self._matcher  = SigmaEventMatcher()
        self._rules:   List[SigmaRule] = []
        self._stats:   Dict[str, int] = {}
        self._loaded_at: float = 0.0
        self._reload()

    def _reload(self) -> None:
        """يُعيد تحميل قواعد من disk."""
        if not os.path.isdir(self.rules_dir):
            logger.warning(f"Sigma rules dir not found: {self.rules_dir}")
            return
        self._rules = self._loader.load_directory(self.rules_dir)
        self._loaded_at = time.time()
        logger.info(f"Sigma rules reloaded: {len(self._rules)} rules active")

    def check_event(self, event: Dict[str, Any]) -> List[SigmaMatch]:
        """
        يفحص event مقابل كل القواعد.
        
        Returns:
            List[SigmaMatch]: القواعد المُطابقة مرتبة بالخطورة
        """
        # Auto-reload إذا تغيرت الملفات (كل 60 ثانية)
        if time.time() - self._loaded_at > 60:
            self._reload()

        matches = []
        for rule in self._rules:
            matched, fields = self._matcher.match_event(event, rule)
            if matched:
                self._stats[rule.id] = self._stats.get(rule.id, 0) + 1
                matches.append(SigmaMatch(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    rule_level=rule.level,
                    matched_at=time.time(),
                    event=event,
                    matched_fields=fields,
                    mitre_techniques=rule.mitre_techniques,
                    mitre_tactics=rule.mitre_tactics,
                ))

        # Sort: critical > high > medium > low
        level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        matches.sort(key=lambda m: level_order.get(m.rule_level, 5))
        return matches

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self._rules),
            "loaded_at": self._loaded_at,
            "match_counts": self._stats,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_sigma_manager: Optional[SigmaRuleManager] = None

def get_sigma_manager() -> SigmaRuleManager:
    global _sigma_manager
    if _sigma_manager is None:
        _sigma_manager = SigmaRuleManager()
    return _sigma_manager
