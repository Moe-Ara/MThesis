"""Train a lightweight multi-head MLP planner from structured features.

No pretrained base model — learns entirely from the pipe-delimited dataset.
"""

import argparse
import json
import logging
import pickle
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import torch
import torch.nn as nn
from sklearn.feature_extraction.text import TfidfVectorizer
from torch.utils.data import DataLoader, TensorDataset

from intelligence.core.utils import extract_json, repair_json
from intelligence.training.build_planner_seq2seq_dataset import parse_pipe_completion

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Label vocabularies ────────────────────────────────────────────────────────

ALERT_TYPES = ["PortScanFromIp", "BenignNoise", "SuspiciousProcessOnHost", "MalwareHashOnHost", "BruteForceUser"]
STRATEGIES = ["ObserveMore", "NotifyOnly", "Contain", "ContainAndCollect", "EscalateToHuman"]
ACTION_TYPES = ["BlockIp", "IsolateHost", "DisableUser", "KillProcess", "QuarantineFile",
                "CollectForensics", "OpenTicket", "Notify"]

ALERT_TYPE_IDX = {v: i for i, v in enumerate(ALERT_TYPES)}
STRATEGY_IDX = {v: i for i, v in enumerate(STRATEGIES)}
ACTION_IDX = {v: i for i, v in enumerate(ACTION_TYPES)}

# ── Feature extraction from compact seq2seq prompts ───────────────────────────

_RE_TYPE = re.compile(r"Type:\s*(.+)")
_RE_SEV_CONF = re.compile(r"Severity:\s*([\d.]+)\s+Confidence:\s*([\d.]+)\s+\((\w+)\)")
_RE_HYPOTHESIS = re.compile(r"Hypothesis:\s*(.+)")
_RE_EVIDENCE = re.compile(r"Evidence:\s*(\[.+\])")
_RE_ENTITIES = re.compile(r"Entities:\s*(\{.*\})")

# Security-relevant keywords extracted from training data analysis.
# Each keyword group correlates with specific response strategies/actions.
KEYWORDS = [
    # Indicate benign / low-risk → ObserveMore / NotifyOnly
    "benign", "normal", "legitimate", "routine",
    # Indicate scanning / recon → BlockIp
    "scan", "scanning", "reconnaissance", "port",
    # Indicate persistence / advanced → ContainAndCollect
    "persistence", "registry", "lateral", "movement", "escalation", "privilege",
    # Indicate malware / file threats → QuarantineFile
    "malware", "hash", "file", "payload",
    # Indicate process threats → KillProcess
    "process", "execution", "running", "injection",
    # Indicate brute force / auth → DisableUser
    "brute", "failed", "logins", "authentication", "account",
    # Indicate severity / urgency
    "adversary", "attacker", "malicious", "suspicious", "unusual",
    # Forensic indicators → CollectForensics
    "forensic", "sysmon", "event", "technique",
]
KEYWORD_IDX = {k: i for i, k in enumerate(KEYWORDS)}

SOURCES = ["cic-ids", "mitre-attack", "mordor"]
SOURCE_IDX = {v: i for i, v in enumerate(SOURCES)}

# TF-IDF settings
TFIDF_MAX_FEATURES = 128
TFIDF_NGRAM_RANGE = (1, 2)  # unigrams + bigrams


def _extract_text_from_prompt(prompt: str) -> str:
    """Extract hypothesis + evidence text for TF-IDF vectorization."""
    parts = []
    m_hyp = _RE_HYPOTHESIS.search(prompt)
    if m_hyp:
        parts.append(m_hyp.group(1))
    m_ev = _RE_EVIDENCE.search(prompt)
    if m_ev:
        parts.append(m_ev.group(1))
    return " ".join(parts).lower()


def _extract_features(prompt: str, source: str = "", technique_id: str = "",
                      tfidf_vec: Optional[List[float]] = None) -> Optional[List[float]]:
    """Extract a fixed-size feature vector from a compact seq2seq prompt.

    Features (total dims):
      - alert_type one-hot (5)
      - severity, confidence (2)
      - entity presence flags (5)
      - confidence buckets (4)
      - severity buckets (4)
      - alert_type x severity interaction (5)
      - alert_type x confidence interaction (5)
      - keyword presence from hypothesis+evidence (len(KEYWORDS))
      - source one-hot (3)
      - has_technique_id (1)
    """
    m_type = _RE_TYPE.search(prompt)
    m_sc = _RE_SEV_CONF.search(prompt)
    m_ent = _RE_ENTITIES.search(prompt)

    if not m_type or not m_sc:
        return None

    alert_type = m_type.group(1).strip()
    severity = float(m_sc.group(1))
    confidence = float(m_sc.group(2))

    entities: Dict[str, Any] = {}
    if m_ent:
        try:
            entities = json.loads(m_ent.group(1))
        except json.JSONDecodeError:
            pass

    # Extract text from hypothesis + evidence for keyword matching
    text_parts = []
    m_hyp = _RE_HYPOTHESIS.search(prompt)
    if m_hyp:
        text_parts.append(m_hyp.group(1))
    m_ev = _RE_EVIDENCE.search(prompt)
    if m_ev:
        text_parts.append(m_ev.group(1))
    text_lower = " ".join(text_parts).lower()
    text_words = set(re.findall(r"[a-z]+", text_lower))

    # One-hot alert type (5)
    alert_oh = [0.0] * len(ALERT_TYPES)
    idx = ALERT_TYPE_IDX.get(alert_type)
    if idx is not None:
        alert_oh[idx] = 1.0

    # Numeric features
    sev_norm = severity / 100.0
    conf_norm = confidence

    # Entity presence flags
    has_src_ip = float(bool(entities.get("srcIp") or entities.get("src_ip")))
    has_host = float(bool(entities.get("hostId") or entities.get("host_id") or entities.get("hostname")))
    has_username = float(bool(entities.get("username") or entities.get("userName")))
    has_file_hash = float(bool(entities.get("fileHash") or entities.get("file_hash")))
    has_process = float(bool(entities.get("processName") or entities.get("process_name")))

    # Confidence buckets (maps to strategy decision boundaries)
    conf_buckets = [
        float(confidence < 0.3),
        float(0.3 <= confidence < 0.6),
        float(0.6 <= confidence < 0.85),
        float(confidence >= 0.85),
    ]

    # Severity buckets
    sev_buckets = [
        float(severity < 30),
        float(30 <= severity < 50),
        float(50 <= severity < 70),
        float(severity >= 70),
    ]

    # Interaction: alert_type x severity and alert_type x confidence
    alert_x_sev = [a * sev_norm for a in alert_oh]
    alert_x_conf = [a * conf_norm for a in alert_oh]

    # Keyword presence features from hypothesis + evidence text
    keyword_feats = [float(kw in text_words) for kw in KEYWORDS]

    # Source one-hot (3)
    source_oh = [0.0] * len(SOURCES)
    src_idx = SOURCE_IDX.get(source.lower().strip())
    if src_idx is not None:
        source_oh[src_idx] = 1.0

    # Technique ID presence
    has_technique = [float(bool(technique_id and technique_id.strip()))]

    base = (alert_oh + [sev_norm, conf_norm]
            + [has_src_ip, has_host, has_username, has_file_hash, has_process]
            + conf_buckets + sev_buckets
            + alert_x_sev + alert_x_conf
            + keyword_feats + source_oh + has_technique)
    if tfidf_vec is not None:
        base = base + tfidf_vec
    return base


# Required entity keys per action type (used for label sanitization)
_ACTION_REQUIRED_ENTITIES = {
    "BlockIp": [["srcIp", "src_ip"]],
    "IsolateHost": [["hostId", "host_id", "hostname"]],
    "DisableUser": [["username", "userName", "user"]],
    "KillProcess": [["hostId", "host_id", "hostname"], ["processName", "process_name"]],
    "QuarantineFile": [["hostId", "host_id", "hostname"], ["fileHash", "file_hash"]],
}

_SAFE_ACTIONS = {"OpenTicket", "Notify"}
_CONTAIN_ACTIONS = {"BlockIp", "IsolateHost", "DisableUser", "KillProcess", "QuarantineFile"}


def _has_entity(entities: Dict[str, Any], candidates: List[str]) -> bool:
    return any(bool(entities.get(k)) for k in candidates)


def _action_feasible(action_type: str, entities: Dict[str, Any]) -> bool:
    """Check if action can be fulfilled given available entities."""
    required = _ACTION_REQUIRED_ENTITIES.get(action_type)
    if not required:
        return True  # Safe actions always feasible
    return all(_has_entity(entities, candidates) for candidates in required)


def _derive_strategy_from_actions(action_types: set, confidence: float, severity: float) -> str:
    """Mirror the derive_strategy logic from plan_utils."""
    if confidence < 0.3:
        return "ObserveMore"
    if not action_types or action_types.issubset({"OpenTicket", "Notify", "CollectForensics"}):
        return "NotifyOnly"
    if "CollectForensics" in action_types:
        return "ContainAndCollect"
    if action_types & _CONTAIN_ACTIONS:
        return "Contain"
    if confidence >= 0.85 and severity >= 70:
        return "ContainAndCollect"
    if confidence >= 0.6 and severity >= 50:
        return "Contain"
    return "NotifyOnly"


def _entity_action_mask(entities: Dict[str, Any]) -> List[bool]:
    """For each ACTION_TYPE, return True if the required entities exist."""
    return [_action_feasible(at, entities) for at in ACTION_TYPES]


def _parse_completion(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    text = raw.strip()
    if "|" in text and "strategy=" in text:
        return parse_pipe_completion(text)
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = extract_json(text) or repair_json(text)
        if isinstance(parsed, dict):
            return parsed.get("plan") if isinstance(parsed.get("plan"), dict) else parsed
    parsed = extract_json(text) or repair_json(text)
    if isinstance(parsed, dict):
        return parsed.get("plan") if isinstance(parsed.get("plan"), dict) else parsed
    return None


def _extract_labels(
    completion: str, entities: Optional[Dict[str, Any]] = None,
    confidence: float = 0.0, severity: float = 0.0,
) -> Optional[Tuple[int, List[float], float, List[float]]]:
    """Extract strategy index, multi-hot action vector, priority, and entity mask.

    Supports pipe-delimited and JSON completions.
    When entities are provided, sanitizes labels:
    - Removes actions whose required entities are missing
    - Filters containment actions at low confidence (<0.6)
    - Re-derives strategy from feasible actions (matching pipeline behavior)
    - Returns entity mask for loss masking
    """
    parsed = _parse_completion(completion)
    if not parsed:
        return None

    actions = parsed.get("actions", [])
    action_types_raw = set()
    action_multi = [0.0] * len(ACTION_TYPES)

    low_confidence = confidence < 0.6

    for action in actions:
        atype = action.get("type", "") if isinstance(action, dict) else ""
        aidx = ACTION_IDX.get(atype)
        if aidx is None:
            continue

        # Skip infeasible actions (entity-aware sanitization)
        if entities is not None and not _action_feasible(atype, entities):
            continue

        # Skip containment at low confidence (matches sanitize_plan)
        if low_confidence and atype not in _SAFE_ACTIONS:
            continue

        action_multi[aidx] = 1.0
        action_types_raw.add(atype)

    # Ensure at least one safe action
    if not action_types_raw & _SAFE_ACTIONS:
        ot_idx = ACTION_IDX.get("OpenTicket")
        if ot_idx is not None:
            action_multi[ot_idx] = 1.0
            action_types_raw.add("OpenTicket")

    # Re-derive strategy from sanitized actions (matches pipeline)
    if entities is not None:
        strategy = _derive_strategy_from_actions(action_types_raw, confidence, severity)
    else:
        strategy = parsed.get("strategy", "")

    strat_idx = STRATEGY_IDX.get(strategy)
    if strat_idx is None:
        return None

    priority = float(parsed.get("priority", 50)) / 100.0

    # Entity mask: which action slots are feasible for this sample
    if entities is not None:
        emask = [float(_action_feasible(at, entities)) for at in ACTION_TYPES]
        # Safe actions are always feasible
        for at in _SAFE_ACTIONS:
            aidx = ACTION_IDX.get(at)
            if aidx is not None:
                emask[aidx] = 1.0
        # At low confidence, mask out all non-safe actions
        if low_confidence:
            for i, at in enumerate(ACTION_TYPES):
                if at not in _SAFE_ACTIONS:
                    emask[i] = 0.0
    else:
        emask = [1.0] * len(ACTION_TYPES)

    return strat_idx, action_multi, priority, emask


# ── Model ─────────────────────────────────────────────────────────────────────

class PlannerMLP(nn.Module):
    def __init__(self, input_dim: int = 30, hidden1: int = 512, hidden2: int = 256,
                 hidden3: int = 128, n_strategies: int = 5, n_actions: int = 8):
        super().__init__()
        self.shared = nn.Sequential(
            nn.Linear(input_dim, hidden1),
            nn.BatchNorm1d(hidden1),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden1, hidden2),
            nn.BatchNorm1d(hidden2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden2, hidden3),
            nn.BatchNorm1d(hidden3),
            nn.ReLU(),
            nn.Dropout(0.1),
        )
        self.strategy_head = nn.Linear(hidden3, n_strategies)
        self.action_head = nn.Linear(hidden3, n_actions)
        self.priority_head = nn.Linear(hidden3, 1)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        h = self.shared(x)
        strategy_logits = self.strategy_head(h)
        action_logits = self.action_head(h)
        priority = torch.sigmoid(self.priority_head(h))
        return strategy_logits, action_logits, priority


# ── Dataset loading ───────────────────────────────────────────────────────────

def load_dataset(data_path: Path, tfidf_path: Optional[Path] = None
                  ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, TfidfVectorizer]:
    """Load dataset and build TF-IDF features from hypothesis+evidence text.

    Returns feature tensors + the fitted TfidfVectorizer (to be saved with model).
    """
    records = []
    texts = []
    skipped = 0

    with data_path.open("r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            prompt = record.get("prompt", "")
            completion = record.get("completion", "")

            source = record.get("source", "")
            technique_id = record.get("technique_id", "")

            # Check basic feature extraction works
            m_type = _RE_TYPE.search(prompt)
            m_sc = _RE_SEV_CONF.search(prompt)
            if not m_type or not m_sc:
                skipped += 1
                continue

            # Parse entities, confidence, severity for label sanitization
            m_ent = _RE_ENTITIES.search(prompt)
            entities = {}
            if m_ent:
                try:
                    entities = json.loads(m_ent.group(1))
                except json.JSONDecodeError:
                    pass
            confidence = float(m_sc.group(2))
            severity = float(m_sc.group(1))

            labels = _extract_labels(
                completion, entities=entities, confidence=confidence, severity=severity,
            )
            if labels is None:
                skipped += 1
                continue

            records.append((prompt, source, technique_id, labels))
            texts.append(_extract_text_from_prompt(prompt))

    # Fit TF-IDF on all texts
    if tfidf_path and tfidf_path.exists():
        with tfidf_path.open("rb") as f:
            tfidf = pickle.load(f)
        log.info(f"Loaded existing TF-IDF vectorizer ({tfidf.max_features} features)")
    else:
        tfidf = TfidfVectorizer(
            max_features=TFIDF_MAX_FEATURES,
            ngram_range=TFIDF_NGRAM_RANGE,
            sublinear_tf=True,
            min_df=3,
        )
        tfidf.fit(texts)
        log.info(f"Fitted TF-IDF vectorizer: {len(tfidf.vocabulary_)} features")

    tfidf_matrix = tfidf.transform(texts).toarray()

    features_list = []
    strategy_list = []
    action_list = []
    priority_list = []
    emask_list = []

    for i, (prompt, source, technique_id, labels) in enumerate(records):
        tfidf_vec = tfidf_matrix[i].tolist()
        feats = _extract_features(prompt, source=source, technique_id=technique_id,
                                  tfidf_vec=tfidf_vec)
        if feats is None:
            skipped += 1
            continue

        strat_idx, action_multi, priority, emask = labels
        features_list.append(feats)
        strategy_list.append(strat_idx)
        action_list.append(action_multi)
        priority_list.append(priority)
        emask_list.append(emask)

    log.info(f"Loaded {len(features_list)} examples ({skipped} skipped)")
    return (
        torch.tensor(features_list, dtype=torch.float32),
        torch.tensor(strategy_list, dtype=torch.long),
        torch.tensor(action_list, dtype=torch.float32),
        torch.tensor(priority_list, dtype=torch.float32).unsqueeze(1),
        torch.tensor(emask_list, dtype=torch.float32),
        tfidf,
    )


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(model: PlannerMLP, loader: DataLoader, device: torch.device) -> Dict[str, float]:
    model.eval()
    correct_strategy = 0
    total = 0
    action_tp = 0
    action_fp = 0
    action_fn = 0
    priority_abs_err = 0.0

    with torch.no_grad():
        for batch in loader:
            X, y_strat, y_act, y_pri = batch[0], batch[1], batch[2], batch[3]
            emask = batch[4] if len(batch) > 4 else None
            X, y_strat, y_act, y_pri = X.to(device), y_strat.to(device), y_act.to(device), y_pri.to(device)
            s_logits, a_logits, p_pred = model(X)

            # Strategy accuracy
            s_pred = s_logits.argmax(dim=1)
            correct_strategy += (s_pred == y_strat).sum().item()

            # Action F1 (multi-label) — only evaluate on feasible actions
            a_pred = (torch.sigmoid(a_logits) > 0.5).float()
            if emask is not None:
                emask_d = emask.to(device)
                a_pred = a_pred * emask_d
                y_act_masked = y_act * emask_d
            else:
                y_act_masked = y_act
            action_tp += (a_pred * y_act_masked).sum().item()
            action_fp += (a_pred * (1 - y_act_masked)).sum().item()
            action_fn += ((1 - a_pred) * y_act_masked).sum().item()

            # Priority MAE
            priority_abs_err += (p_pred - y_pri).abs().sum().item()

            total += X.size(0)

    strat_acc = correct_strategy / total if total else 0
    precision = action_tp / (action_tp + action_fp) if (action_tp + action_fp) > 0 else 0
    recall = action_tp / (action_tp + action_fn) if (action_tp + action_fn) > 0 else 0
    action_f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    priority_mae = (priority_abs_err / total * 100) if total else 0

    return {
        "strategy_acc": round(strat_acc, 4),
        "action_f1": round(action_f1, 4),
        "action_precision": round(precision, 4),
        "action_recall": round(recall, 4),
        "priority_mae": round(priority_mae, 2),
        "samples": total,
    }


def _collect_probs_labels(
    model: PlannerMLP, loader: DataLoader, device: torch.device
) -> Tuple[torch.Tensor, torch.Tensor]:
    """Collect action probabilities and labels for threshold tuning."""
    model.eval()
    probs = []
    labels = []
    with torch.no_grad():
        for batch in loader:
            X, y_act = batch[0], batch[2]
            X = X.to(device)
            y_act = y_act.to(device)
            _, a_logits, _ = model(X)
            probs.append(torch.sigmoid(a_logits).cpu())
            labels.append(y_act.cpu())
    return torch.cat(probs, dim=0), torch.cat(labels, dim=0)


def tune_action_thresholds(
    model: PlannerMLP,
    loader: DataLoader,
    device: torch.device,
    grid: Optional[List[float]] = None,
) -> List[float]:
    """Tune per-action thresholds on a held-out set to maximize F1."""
    if grid is None:
        grid = [i / 20 for i in range(1, 20)]  # 0.05..0.95

    probs, labels = _collect_probs_labels(model, loader, device)
    probs_np = probs.numpy()
    labels_np = labels.numpy()

    thresholds: List[float] = []
    for action_idx in range(probs_np.shape[1]):
        best_t = 0.5
        best_f1 = -1.0
        y_true = labels_np[:, action_idx]
        for t in grid:
            y_pred = (probs_np[:, action_idx] >= t).astype(float)
            tp = (y_pred * y_true).sum()
            fp = (y_pred * (1 - y_true)).sum()
            fn = ((1 - y_pred) * y_true).sum()
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            if f1 > best_f1:
                best_f1 = f1
                best_t = t
        thresholds.append(best_t)
    return thresholds


# ── Training ──────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Train custom NN planner (no pretrained base).")
    parser.add_argument("--data", type=Path,
                        default=Path("intelligence/training/data/planner_seq2seq_train_compact.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("intelligence/models/planner_nn"))
    parser.add_argument("--epochs", type=int, default=150)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--test-size", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    torch.manual_seed(args.seed)

    # Load data
    X, y_strat, y_act, y_pri, emask, tfidf = load_dataset(args.data)
    n = X.size(0)
    input_dim = X.size(1)

    # Split
    indices = torch.randperm(n, generator=torch.Generator().manual_seed(args.seed))
    split = int(n * (1 - args.test_size))
    train_idx, test_idx = indices[:split], indices[split:]

    train_ds = TensorDataset(X[train_idx], y_strat[train_idx], y_act[train_idx], y_pri[train_idx], emask[train_idx])
    test_ds = TensorDataset(X[test_idx], y_strat[test_idx], y_act[test_idx], y_pri[test_idx], emask[test_idx])

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size)

    log.info(f"Train: {len(train_ds)}, Test: {len(test_ds)}, Features: {input_dim}")

    # Model
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PlannerMLP(input_dim=input_dim).to(device)
    param_count = sum(p.numel() for p in model.parameters())
    log.info(f"Model parameters: {param_count:,} (device: {device})")

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)

    criterion_strat = nn.CrossEntropyLoss()
    # Action imbalance handling: weight rare actions higher.
    pos_counts = y_act[train_idx].sum(dim=0).clamp(min=1.0)
    neg_counts = (y_act[train_idx].size(0) - pos_counts).clamp(min=1.0)
    pos_weight = (neg_counts / pos_counts).to(device)
    # Use reduction='none' so we can apply entity masks per-element
    criterion_act = nn.BCEWithLogitsLoss(pos_weight=pos_weight, reduction="none")
    criterion_pri = nn.MSELoss()

    # Class weights for strategy (handle imbalance)
    strat_counts = torch.bincount(y_strat[train_idx], minlength=len(STRATEGIES)).float()
    strat_weights = (1.0 / (strat_counts + 1.0)).to(device)
    strat_weights = strat_weights / strat_weights.sum() * len(STRATEGIES)
    criterion_strat = nn.CrossEntropyLoss(weight=strat_weights)

    # Training loop
    best_f1 = 0.0
    best_epoch = 0

    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            X_b, ys, ya, yp, em = batch[0], batch[1], batch[2], batch[3], batch[4]
            X_b, ys, ya, yp, em = (X_b.to(device), ys.to(device), ya.to(device),
                                    yp.to(device), em.to(device))
            s_logits, a_logits, p_pred = model(X_b)

            loss_s = criterion_strat(s_logits, ys)
            # Masked action loss: only backprop through feasible action slots
            raw_act_loss = criterion_act(a_logits, ya)  # (batch, n_actions)
            masked_act_loss = raw_act_loss * em
            loss_a = masked_act_loss.sum() / em.sum().clamp(min=1.0)
            loss_p = criterion_pri(p_pred, yp)
            loss = loss_s + 0.5 * loss_a + 0.1 * loss_p

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * X_b.size(0)

        scheduler.step()
        avg_loss = total_loss / len(train_ds)

        if epoch % 10 == 0 or epoch == 1:
            metrics = evaluate(model, test_loader, device)
            log.info(
                f"Epoch {epoch:3d}/{args.epochs} | loss={avg_loss:.4f} | "
                f"strategy_acc={metrics['strategy_acc']:.4f} | action_f1={metrics['action_f1']:.4f} | "
                f"priority_mae={metrics['priority_mae']:.1f}"
            )
            if metrics["action_f1"] >= best_f1:
                best_f1 = metrics["action_f1"]
                best_epoch = epoch
                # Save best model
                args.output.mkdir(parents=True, exist_ok=True)
                torch.save(model.state_dict(), args.output / "model.pt")
                meta = {
                    "input_dim": input_dim,
                    "alert_types": ALERT_TYPES,
                    "strategies": STRATEGIES,
                    "action_types": ACTION_TYPES,
                    "best_epoch": best_epoch,
                    "metrics": metrics,
                }
                with (args.output / "meta.json").open("w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)

    # Save TF-IDF vectorizer
    args.output.mkdir(parents=True, exist_ok=True)
    tfidf_path = args.output / "tfidf.pkl"
    with tfidf_path.open("wb") as f:
        pickle.dump(tfidf, f)
    log.info(f"Saved TF-IDF vectorizer to {tfidf_path}")

    # Final eval + threshold tuning
    model.load_state_dict(torch.load(args.output / "model.pt", weights_only=True))
    final = evaluate(model, test_loader, device)
    thresholds = tune_action_thresholds(model, test_loader, device)
    log.info(f"Best model from epoch {best_epoch}: {json.dumps(final, indent=2)}")

    # Save final results
    results = {"best_epoch": best_epoch, "metrics": final, "action_thresholds": thresholds}
    with (args.output / "eval_results.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Update meta with tuned thresholds + final eval + tfidf info
    meta_path = args.output / "meta.json"
    if meta_path.exists():
        with meta_path.open("r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["action_thresholds"] = thresholds
        meta["eval_metrics"] = final
        meta["tfidf_max_features"] = TFIDF_MAX_FEATURES
        meta["tfidf_ngram_range"] = list(TFIDF_NGRAM_RANGE)
        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
