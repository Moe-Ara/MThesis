"""Custom multi-head MLP planner — no pretrained base model."""

import pickle
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import json
import torch

from intelligence.core.base import Planner
from intelligence.planners.plan_utils import sanitize_plan
from intelligence.training.train_planner_nn import (
    ACTION_TYPES,
    ALERT_TYPES,
    ALERT_TYPE_IDX,
    KEYWORDS,
    SOURCES,
    SOURCE_IDX,
    STRATEGIES,
    PlannerMLP,
)

# Map containment actions to their rollback counterparts
_ROLLBACK_MAP = {
    "BlockIp": "UnblockIp",
    "IsolateHost": "UnisolateHost",
    "DisableUser": "EnableUser",
}

# Map action types to the entity keys they need
_ACTION_ENTITY_MAP = {
    "BlockIp": {"src_ip": ["srcIp", "src_ip"]},
    "IsolateHost": {"host_id": ["hostId", "host_id", "hostname"]},
    "DisableUser": {"username": ["username", "userName", "user"]},
    "KillProcess": {
        "host_id": ["hostId", "host_id", "hostname"],
        "process_name": ["processName", "process_name"],
    },
    "QuarantineFile": {
        "host_id": ["hostId", "host_id", "hostname"],
        "file_hash": ["fileHash", "file_hash"],
    },
}


def _resolve_entity(entities: Dict[str, Any], candidates: List[str]) -> Optional[str]:
    for key in candidates:
        val = entities.get(key)
        if val:
            return str(val)
    return None


def _build_action(action_type: str, entities: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    param_spec = _ACTION_ENTITY_MAP.get(action_type)
    if not param_spec:
        return {"type": action_type, "parameters": {}}

    params = {}
    for param_key, entity_candidates in param_spec.items():
        val = _resolve_entity(entities, entity_candidates)
        if val is None:
            return None  # Missing required entity — skip action
        params[param_key] = val

    return {"type": action_type, "parameters": params}


def _build_rollback(action_type: str, entities: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rollback_type = _ROLLBACK_MAP.get(action_type)
    if not rollback_type:
        return None
    return _build_action(rollback_type, entities)


class CustomNNPlanner(Planner):
    def __init__(self, model_path: str, action_threshold: float = 0.5):
        self.model_path = Path(model_path)
        self.action_threshold = action_threshold
        self._action_thresholds: Optional[List[float]] = None
        self._model: Optional[PlannerMLP] = None
        self._meta: Dict[str, Any] = {}
        self._tfidf = None
        self._device = torch.device("cpu")
        self._load()

    def _load(self) -> None:
        meta_path = self.model_path / "meta.json"
        with meta_path.open("r", encoding="utf-8") as f:
            self._meta = json.load(f)

        input_dim = self._meta.get("input_dim", 30)
        thresholds = self._meta.get("action_thresholds")
        if isinstance(thresholds, list) and thresholds:
            self._action_thresholds = [float(t) for t in thresholds]

        # Load TF-IDF vectorizer if it exists
        tfidf_path = self.model_path / "tfidf.pkl"
        if tfidf_path.exists():
            with tfidf_path.open("rb") as f:
                self._tfidf = pickle.load(f)

        self._model = PlannerMLP(input_dim=input_dim)
        state = torch.load(self.model_path / "model.pt", map_location="cpu", weights_only=True)
        self._model.load_state_dict(state)
        self._model.eval()

    def _extract_features(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> List[float]:
        entities = alert.get("entities") or {}
        if not isinstance(entities, dict):
            entities = {}

        alert_type = alert.get("type") or alert.get("alertType") or alert.get("ruleName") or ""
        severity = float(assessment.get("severity", alert.get("severity", 0)))
        confidence = float(assessment.get("confidence", 0))

        # Collect text from hypothesis + evidence for keyword matching
        text_parts = []
        hypothesis = assessment.get("hypothesis", "")
        if hypothesis:
            text_parts.append(str(hypothesis))
        evidence = assessment.get("evidence", [])
        if isinstance(evidence, list):
            text_parts.extend(str(e) for e in evidence)
        elif evidence:
            text_parts.append(str(evidence))
        text_words = set(re.findall(r"[a-z]+", " ".join(text_parts).lower()))

        # One-hot alert type (5)
        alert_oh = [0.0] * len(ALERT_TYPES)
        idx = ALERT_TYPE_IDX.get(alert_type)
        if idx is not None:
            alert_oh[idx] = 1.0

        sev_norm = severity / 100.0
        conf_norm = confidence

        # Entity presence flags (5)
        has_src_ip = float(bool(entities.get("srcIp") or entities.get("src_ip")))
        has_host = float(bool(entities.get("hostId") or entities.get("host_id") or entities.get("hostname")))
        has_username = float(bool(entities.get("username") or entities.get("userName")))
        has_file_hash = float(bool(entities.get("fileHash") or entities.get("file_hash")))
        has_process = float(bool(entities.get("processName") or entities.get("process_name")))

        # Confidence buckets (4)
        conf_buckets = [
            float(confidence < 0.3),
            float(0.3 <= confidence < 0.6),
            float(0.6 <= confidence < 0.85),
            float(confidence >= 0.85),
        ]

        # Severity buckets (4)
        sev_buckets = [
            float(severity < 30),
            float(30 <= severity < 50),
            float(50 <= severity < 70),
            float(severity >= 70),
        ]

        # Interactions (5 + 5)
        alert_x_sev = [a * sev_norm for a in alert_oh]
        alert_x_conf = [a * conf_norm for a in alert_oh]

        # Keyword features (len(KEYWORDS))
        keyword_feats = [float(kw in text_words) for kw in KEYWORDS]

        # Source one-hot (3) — use sourceSiem from alert if available
        source = alert.get("sourceSiem", "")
        source_oh = [0.0] * len(SOURCES)
        src_idx = SOURCE_IDX.get(str(source).lower().strip())
        if src_idx is not None:
            source_oh[src_idx] = 1.0

        # Technique ID presence (1)
        raw_payload = alert.get("rawPayload") or {}
        has_technique = [float(bool(
            raw_payload.get("technique_id") if isinstance(raw_payload, dict) else False
        ))]

        base = (alert_oh + [sev_norm, conf_norm]
                + [has_src_ip, has_host, has_username, has_file_hash, has_process]
                + conf_buckets + sev_buckets
                + alert_x_sev + alert_x_conf
                + keyword_feats + source_oh + has_technique)

        # Append TF-IDF features if vectorizer is available
        if self._tfidf is not None:
            text = " ".join(text_parts).lower()
            tfidf_vec = self._tfidf.transform([text]).toarray()[0].tolist()
            base = base + tfidf_vec

        return base

    @staticmethod
    def _entity_mask(entities: Dict[str, Any]) -> List[bool]:
        """For each ACTION_TYPE, return True if the required entities are present."""
        has_src_ip = bool(entities.get("srcIp") or entities.get("src_ip"))
        has_host = bool(entities.get("hostId") or entities.get("host_id") or entities.get("hostname"))
        has_username = bool(entities.get("username") or entities.get("userName"))
        has_file_hash = bool(entities.get("fileHash") or entities.get("file_hash"))
        has_process = bool(entities.get("processName") or entities.get("process_name"))
        return [
            has_src_ip,     # BlockIp
            has_host,       # IsolateHost
            has_username,   # DisableUser
            has_host and has_process,  # KillProcess
            has_host and has_file_hash,  # QuarantineFile
            True,           # CollectForensics
            True,           # OpenTicket
            True,           # Notify
        ]

    def plan(self, alert: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(alert, assessment)
        x = torch.tensor([features], dtype=torch.float32).to(self._device)

        with torch.no_grad():
            s_logits, a_logits, p_pred = self._model(x)

        # Decode strategy
        strategy_idx = s_logits.argmax(dim=1).item()
        strategy = STRATEGIES[strategy_idx]

        # Decode actions with entity-aware masking + alignment with sanitize_plan rules.
        a_probs = torch.sigmoid(a_logits).squeeze(0)
        entities = alert.get("entities") or {}
        entity_mask = self._entity_mask(entities)
        safe_actions = {"OpenTicket", "Notify"}

        confidence = float(assessment.get("confidence", 0.0) or 0.0)
        low_confidence = confidence < 0.6

        # Extract enrichment context passed from the C# engine
        context = alert.get("context") or {}
        asset_criticality = int(context.get("assetCriticality") or 0)
        privileged = bool(context.get("privileged") or False)
        environment = str(context.get("environment") or "").lower()

        candidates: List[tuple[str, float]] = []
        for i, prob in enumerate(a_probs):
            action_type = ACTION_TYPES[i]
            if not entity_mask[i]:
                continue
            if low_confidence and action_type not in safe_actions:
                continue

            threshold = self.action_threshold
            if self._action_thresholds and i < len(self._action_thresholds):
                threshold = self._action_thresholds[i]
            if prob.item() >= threshold:
                candidates.append((action_type, float(prob.item())))

        # Ensure at least one safe action
        if not any(a in safe_actions for a, _ in candidates):
            best_safe = None
            for i, prob in enumerate(a_probs):
                action_type = ACTION_TYPES[i]
                if action_type in safe_actions:
                    score = float(prob.item())
                    if best_safe is None or score > best_safe[1]:
                        best_safe = (action_type, score)
            if best_safe:
                candidates.append(best_safe)

        # Keep top 4 by probability (align with sanitize_plan cap)
        candidates = sorted(candidates, key=lambda x: x[1], reverse=True)[:4]

        actions = []
        rollback_actions = []
        for action_type, _score in candidates:
            action = _build_action(action_type, entities)
            if action:
                actions.append(action)
                rb = _build_rollback(action_type, entities)
                if rb:
                    rollback_actions.append(rb)

        # Decode priority
        priority = int(round(p_pred.item() * 100))

        # ── Enrichment post-processing ─────────────────────────────────────────
        # The MLP was trained without enrichment context, so we apply a rule-based
        # correction layer on top of the model output to reflect asset criticality
        # and identity privilege. This is analogous to how a human analyst would
        # escalate: "Same alert pattern, but this is a crit-5 prod server — we
        # must collect forensics before it's remediated."
        enrichment_rationale: List[str] = []

        # 1. Strategy escalation for critical assets
        if asset_criticality >= 5 and confidence >= 0.70:
            if strategy in ("ObserveMore", "NotifyOnly"):
                strategy = "Contain"
                enrichment_rationale.append(
                    "Strategy escalated from passive to Contain — target is a critical asset (criticality=5/5)."
                )
            elif strategy == "Contain":
                strategy = "ContainAndCollect"
                enrichment_rationale.append(
                    "Strategy upgraded to ContainAndCollect — critical asset requires forensic preservation."
                )
        elif asset_criticality >= 4 and confidence >= 0.70:
            if strategy == "ObserveMore":
                strategy = "Contain"
                enrichment_rationale.append(
                    "Strategy escalated from ObserveMore to Contain — high-criticality asset (criticality=4/5)."
                )

        # Privileged identity: don't leave at ObserveMore if confidence is decent
        if privileged and confidence >= 0.65 and strategy == "ObserveMore":
            strategy = "Contain"
            enrichment_rationale.append(
                "Strategy escalated from ObserveMore — compromised identity has elevated privileges."
            )

        # 2. Force CollectForensics for high-criticality assets with sufficient confidence
        action_type_set = {a["type"] for a in actions}
        if asset_criticality >= 4 and confidence >= 0.65 and "CollectForensics" not in action_type_set:
            forensics_action = {"type": "CollectForensics", "parameters": {}}
            actions.append(forensics_action)
            action_type_set.add("CollectForensics")
            enrichment_rationale.append(
                f"CollectForensics added — asset criticality={asset_criticality}/5 warrants evidence preservation."
            )

        # DisableUser for privileged accounts on brute-force / auth alerts
        alert_type = alert.get("type") or ""
        if (privileged and "DisableUser" not in action_type_set
                and alert_type in ("BruteForceUser",)
                and confidence >= 0.70):
            username = (entities.get("username") or entities.get("userName") or
                        entities.get("user") or entities.get("srcuser"))
            if username:
                actions.append({"type": "DisableUser", "parameters": {"username": username}})
                rollback_actions.append({"type": "EnableUser", "parameters": {"username": username}})
                action_type_set.add("DisableUser")
                enrichment_rationale.append(
                    "DisableUser added — privileged account targeted by brute-force attack."
                )

        # 3. Priority floor based on asset criticality (critical assets must be high priority)
        crit_priority_floor = {5: 85, 4: 70, 3: 55}
        floor = crit_priority_floor.get(asset_criticality, 0)
        if floor and priority < floor:
            priority = floor
            enrichment_rationale.append(
                f"Priority floored to {floor} — asset criticality={asset_criticality}/5."
            )

        # Build rationale
        severity = float(assessment.get("severity", 0))
        rationale: List[str] = []
        if severity >= 70:
            rationale.append(f"High severity ({severity:.0f}/100) indicates significant threat potential.")
        elif severity >= 40:
            rationale.append(f"Moderate severity ({severity:.0f}/100) warrants active response.")
        else:
            rationale.append(f"Low severity ({severity:.0f}/100); monitoring recommended.")

        if confidence >= 0.85:
            rationale.append(f"High confidence ({confidence:.0%}) in threat classification.")
        elif confidence >= 0.6:
            rationale.append(f"Moderate confidence ({confidence:.0%}); response scoped accordingly.")
        else:
            rationale.append(f"Low confidence ({confidence:.0%}); only safe actions applied.")

        _STRATEGY_RATIONALE = {
            "ObserveMore": "Insufficient confidence to take containment action; additional monitoring required.",
            "NotifyOnly": "Alert escalated to SOC for analyst review without automated containment.",
            "Contain": "Active containment actions selected to stop the ongoing threat.",
            "ContainAndCollect": "Containment with forensic collection initiated to stop threat and preserve evidence.",
            "EscalateToHuman": "Alert complexity requires human analyst decision before automated action.",
        }
        if strategy in _STRATEGY_RATIONALE:
            rationale.append(_STRATEGY_RATIONALE[strategy])

        # Append enrichment override notes
        rationale.extend(enrichment_rationale)

        # Build summary
        action_types = [a["type"] for a in actions if "type" in a]
        key_actions = [t for t in action_types if t not in {"OpenTicket", "Notify"}]
        if key_actions:
            summary = f"{strategy}: " + ", ".join(key_actions[:2])
            if len(key_actions) > 2:
                summary += f" and {len(key_actions) - 2} more action(s)"
            summary += "."
        else:
            summary = "Alert logged and SOC notified for analyst review."

        # Attach per-action rationale
        _ACTION_RATIONALE = {
            "BlockIp": "Block the source IP to stop continued malicious traffic.",
            "IsolateHost": "Isolate the host to prevent lateral movement during investigation.",
            "DisableUser": "Disable the user account to prevent credential abuse.",
            "KillProcess": "Terminate the suspicious process to halt malicious activity.",
            "QuarantineFile": "Quarantine the file to prevent execution while preserving evidence.",
            "CollectForensics": "Collect forensics to preserve evidence and confirm scope.",
            "OpenTicket": "Create an auditable record for analyst review.",
            "Notify": "Notify the SOC team to coordinate investigation.",
        }
        for action in actions:
            if not action.get("rationale"):
                action["rationale"] = _ACTION_RATIONALE.get(action.get("type", ""), "")

        raw_plan = {
            "strategy": strategy,
            "priority": priority,
            "summary": summary,
            "rationale": rationale,
            "actions": actions,
            "rollbackActions": rollback_actions,
        }
        return sanitize_plan(raw_plan, alert, assessment, derive_strategy_from_actions=True)
