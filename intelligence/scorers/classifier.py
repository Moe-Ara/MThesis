import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib

from intelligence.core.base import Scorer
from intelligence.scorers.classifier_config import default_severity_for_class
from intelligence.scorers.local_model import _build_scorer_prompt


def _unique(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _build_evidence(alert: Dict[str, Any]) -> List[str]:
    entities = alert.get("entities") or {}
    raw = alert.get("rawPayload") or {}
    context = alert.get("context") or {}

    alert_type = alert.get("type") or alert.get("ruleName") or ""
    rule_id = raw.get("rule_id") or raw.get("id") or ""
    siem = alert.get("sourceSiem") or ""

    candidates = [
        f"alert_type={alert_type}" if alert_type else "",
        f"rule_id={rule_id}" if rule_id else "",
        f"siem={siem}" if siem else "",
        f"src_ip={entities.get('srcIp')}" if entities.get("srcIp") else "",
        f"dst_ip={entities.get('dstIp')}" if entities.get("dstIp") else "",
        f"host={entities.get('hostname') or entities.get('hostId')}" if (entities.get("hostname") or entities.get("hostId")) else "",
        f"user={entities.get('username')}" if entities.get("username") else "",
        f"process={entities.get('processName')}" if entities.get("processName") else "",
        f"file_hash={entities.get('fileHash')}" if entities.get("fileHash") else "",
        f"attempts={raw.get('attempts')}" if raw.get("attempts") else "",
        f"failed_logins={raw.get('failed_logins')}" if raw.get("failed_logins") else "",
        f"event_id={raw.get('EventID')}" if raw.get("EventID") else "",
        f"technique={raw.get('technique_id')}" if raw.get("technique_id") else "",
    ]
    base = _unique([c for c in candidates if c])[:5]

    # Append enrichment context as evidence
    asset_criticality = context.get("assetCriticality") or 0
    privileged = context.get("privileged") or False
    ti_reputation = int(context.get("tiReputationScore") or 0)
    ti_tags = list(context.get("tiTags") or [])
    if asset_criticality >= 4:
        base.append(f"asset_criticality={asset_criticality}/5 (critical)")
    if privileged:
        base.append("target_identity=privileged")
    if ti_reputation >= 50:
        base.append(f"ti_reputation={ti_reputation}/100")
    if ti_tags:
        base.append(f"ti_tags=[{', '.join(ti_tags[:3])}]")

    return base


def _build_hypothesis(alert: Dict[str, Any], severity_label: str) -> str:
    alert_type = str(alert.get("type") or "")
    rule_name = str(alert.get("ruleName") or "")
    text = f"{alert_type} {rule_name}".lower()
    entities = alert.get("entities") or {}
    raw = alert.get("rawPayload") or {}

    # Pick the most specific entity for context
    src_ip = entities.get("srcIp") or entities.get("src_ip") or ""
    host = entities.get("hostname") or entities.get("hostId") or ""
    user = entities.get("username") or ""
    process = entities.get("processName") or ""
    attempts = raw.get("attempts") or raw.get("failed_logins") or ""

    if "portscan" in text or "scan" in text:
        subject = f" from {src_ip}" if src_ip else ""
        count = f" ({attempts} port probes)" if attempts else ""
        base = f"Potential reconnaissance activity via port scanning{subject}{count}."
    elif "bruteforce" in text or "brute force" in text:
        subject = f" against account '{user}'" if user else ""
        count = f" ({attempts} failed attempts)" if attempts else ""
        base = f"Multiple failed authentication attempts{subject}{count} suggest brute-force activity."
    elif "malware" in text or "trojan" in text:
        subject = f" on host {host}" if host else ""
        base = f"Indicators of malware execution{subject}."
    elif "suspiciousprocess" in text or "process" in text:
        subject = f" '{process}' on host {host}" if process else (f" on host {host}" if host else "")
        base = f"Suspicious process activity{subject} detected."
    elif "phish" in text:
        base = "Suspicious email or phishing-related activity detected."
    else:
        base = "Suspicious activity detected that warrants review."

    # Append enrichment context to the hypothesis when relevant
    context = alert.get("context") or {}
    asset_criticality = int(context.get("assetCriticality") or 0)
    privileged = bool(context.get("privileged") or False)
    ti_reputation = int(context.get("tiReputationScore") or 0)
    ti_tags = list(context.get("tiTags") or [])

    # Build a TI note if threat intel matched with notable reputation
    if ti_reputation >= 70 and ti_tags:
        top_tags = ", ".join(ti_tags[:3])
        ti_note = f" Origin identified in threat intelligence ({top_tags}; reputation {ti_reputation}/100)."
    elif ti_reputation >= 50 and ti_tags:
        ti_note = f" Source appears in threat intelligence feeds (reputation {ti_reputation}/100)."
    else:
        ti_note = ""

    enrichment_notes = []
    if asset_criticality >= 5:
        enrichment_notes.append("Target is a critical production asset")
    elif asset_criticality >= 4:
        enrichment_notes.append("Target is a high-criticality asset")
    if privileged:
        enrichment_notes.append("compromised account has elevated privileges")
    enrichment_suffix = (" — " + "; ".join(enrichment_notes) + ".") if enrichment_notes else ""

    if severity_label == "benign":
        return "Likely benign or low-confidence alert."
    if severity_label == "low":
        return f"{base}{ti_note} Impact appears limited.{enrichment_suffix}"
    if severity_label == "high":
        return f"{base}{ti_note} High likelihood of malicious intent.{enrichment_suffix}"
    if severity_label == "critical":
        return f"{base}{ti_note} Critical indicators present — immediate action recommended.{enrichment_suffix}"
    return base + ti_note + enrichment_suffix


class ClassifierScorer(Scorer):
    def __init__(self, model_path: str, meta_path: Optional[str] = None):
        model_file, meta_file = self._resolve_paths(model_path, meta_path)
        self._model = joblib.load(model_file)
        self._meta = self._load_meta(meta_file)

    @staticmethod
    def _resolve_paths(model_path: str, meta_path: Optional[str]) -> tuple[Path, Path]:
        path = Path(model_path)
        if path.is_dir():
            model_file = path / "model.joblib"
            meta_file = path / "meta.json"
        else:
            model_file = path
            meta_file = Path(meta_path) if meta_path else path.with_suffix(".meta.json")
        if not model_file.exists():
            raise FileNotFoundError(f"Classifier model not found: {model_file}")
        if not meta_file.exists():
            raise FileNotFoundError(f"Classifier metadata not found: {meta_file}")
        return model_file, meta_file

    @staticmethod
    def _load_meta(path: Path) -> Dict[str, Any]:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    # Label-calibrated confidence floors.
    # In a 5-class problem, raw max(proba) underestimates certainty — a top score
    # of 0.50 beating the next class at 0.20 is actually decisive. These floors
    # ensure the confidence signal is meaningful for downstream threshold logic.
    _LABEL_CONFIDENCE_FLOOR = {
        "critical": 0.88,
        "high": 0.72,
        "medium": 0.52,
        "low": 0.38,
        "benign": 0.22,
    }

    def _predict(self, prompt: str) -> tuple[str, float]:
        labels = self._model.predict([prompt])
        label = str(labels[0])
        confidence = 0.5
        if hasattr(self._model, "predict_proba"):
            proba = self._model.predict_proba([prompt])[0]
            raw_conf = float(max(proba))
            # Use the label-calibrated floor when the raw confidence is below it,
            # but only if the top class beats the runner-up by a clear margin (>= 1.1x).
            # In a 5-class problem (random baseline 20%), a 1.1x margin is meaningful.
            sorted_proba = sorted(proba, reverse=True)
            decisive = len(sorted_proba) < 2 or sorted_proba[0] >= sorted_proba[1] * 1.1
            floor = self._LABEL_CONFIDENCE_FLOOR.get(label, 0.5)
            if decisive and raw_conf < floor:
                confidence = floor
            else:
                confidence = raw_conf
        return label, max(0.01, min(0.99, confidence))

    def score(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        prompt = _build_scorer_prompt(alert)
        label, confidence = self._predict(prompt)
        class_to_severity = self._meta.get("class_to_severity") or self._meta.get("classToSeverity") or {}
        severity = class_to_severity.get(label)
        if severity is None:
            severity = default_severity_for_class(label)
        severity = float(severity)

        # Apply enrichment boosts — external context corroborates or escalates the alert
        context = alert.get("context") or {}
        asset_criticality = int(context.get("assetCriticality") or 0)
        privileged = bool(context.get("privileged") or False)
        environment = str(context.get("environment") or "")
        ti_reputation = int(context.get("tiReputationScore") or 0)

        # Threat intel boost: a known-bad IP or file hash with high reputation score
        # directly corroborates the alert — the system should be very confident.
        if ti_reputation >= 90:
            confidence = max(confidence, 0.90)   # near-certain threat intel match
            severity = max(severity, 85.0)
        elif ti_reputation >= 70:
            confidence = max(confidence, 0.82)   # strong TI corroboration
            severity = max(severity, 75.0)
        elif ti_reputation >= 50:
            confidence = max(confidence, 0.70)   # moderate TI signal

        # Boost confidence when high-criticality asset or privileged identity is involved:
        # the system should be MORE decisive about acting on alerts for critical targets.
        if asset_criticality >= 5:
            confidence = max(confidence, 0.85)  # critical asset → at least 85% confident
            severity = max(severity, 80.0)
        elif asset_criticality >= 4:
            confidence = max(confidence, 0.78)  # high-criticality asset → at least 78% confident
            severity = max(severity, 70.0)

        if privileged:
            confidence = max(confidence, 0.75)  # privileged identity → higher scrutiny

        # Escalate severity for prod environment high-criticality assets
        if asset_criticality >= 4 and environment.lower() == "prod":
            severity = max(severity, 75.0)

        severity = int(max(0, min(100, round(severity))))
        confidence = max(0.01, min(0.99, confidence))

        hypothesis = _build_hypothesis(alert, label)
        evidence = _build_evidence(alert)

        return {
            "severity": severity,
            "confidence": float(confidence),
            "hypothesis": hypothesis,
            "evidence": evidence,
        }
