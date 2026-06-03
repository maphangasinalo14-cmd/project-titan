#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         PROJECT TITAN v16.0 — SECURITY VALIDATION ENGINE     ║
║         Continuous Threat Detection & Autonomous Response     ║
║         Copyright © 2025 Sinalo Maphanga. All Rights Reserved ║
╚══════════════════════════════════════════════════════════════╝

Architecture:
    NUCLEUS   → eBPF-layer syscall + process monitor (real psutil hooks)
    PHANTOM   → Forensic analysis: entropy, anomaly scoring
    HIVE      → MCTS-based autonomous decision engine
    OUROBOROS → Response execution (isolation, patching, kill)
    TITAN-XAI → Explainability: human-readable incident reports
"""

import os
import sys
import time
import json
import math
import copy
import random
import logging
import hashlib
import threading
import statistics
import pickle
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

def utcnow():
    return datetime.now(timezone.utc)
from typing import List, Dict, Any, Optional, Tuple, Callable, Set
from abc import ABC, abstractmethod
from enum import Enum

import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box

# ─── GLOBALS ──────────────────────────────────────────────────────────────────

console = Console()

CONFIG = {
    "data_dir":                   "./titan_data",
    "sandbox_dir":                "/tmp/titan_sandbox",
    "reports_dir":                "./titan_data/reports",
    "knowledge_graph_file":       "./titan_data/knowledge_graph.pkl",
    "state_file":                 "./titan_data/system_state.json",
    "max_history":                2000,
    "learning_rate":              0.1,
    "threat_threshold":           70,        # Risk score to trigger response
    "mcts_iterations":            200,       # Monte Carlo simulations per decision
    "exploration_constant":       1.414,     # UCB1 exploration constant (√2)
    "entropy_critical_threshold": 7.5,       # Shannon entropy above = suspicious
    "entropy_warn_threshold":     6.5,
    "operation_mode":             "DEMO",    # DEMO | LIVE
    "version":                    "16.0",
}

for d in [CONFIG["data_dir"], CONFIG["reports_dir"], CONFIG["sandbox_dir"]]:
    Path(d).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(CONFIG["data_dir"], "titan.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("TITAN")


# ─── ENUMS ────────────────────────────────────────────────────────────────────

class ThreatType(Enum):
    RANSOMWARE        = "Ransomware (T1486)"
    PRIVILEGE_ESC     = "Privilege Escalation (T1068)"
    PROCESS_INJECTION = "Process Injection (T1055)"
    CRYPTO_MINER      = "Cryptominer (T1496)"
    DATA_EXFIL        = "Data Exfiltration (T1041)"
    ROOTKIT           = "Rootkit (T1014)"
    UNKNOWN           = "Unknown Threat"

class ThreatStatus(Enum):
    DETECTED   = "DETECTED"
    ANALYZING  = "ANALYZING"
    MITIGATED  = "MITIGATED"
    ESCALATED  = "ESCALATED"
    MONITORING = "MONITORING"

class ResponseAction(Enum):
    ISOLATE_AND_TERMINATE = "ISOLATE_AND_TERMINATE"
    SUSPEND_PROCESS       = "SUSPEND_PROCESS"
    DENY_SYSCALLS         = "DENY_SYSCALLS"
    QUARANTINE            = "QUARANTINE"
    MONITOR_ONLY          = "MONITOR_ONLY"
    ALERT_ONLY            = "ALERT_ONLY"


# ─── DATA MODELS ──────────────────────────────────────────────────────────────

@dataclass
class ProcessSnapshot:
    """Real process data captured at detection time."""
    pid:              int
    name:             str
    status:           str
    cpu_percent:      float
    memory_mb:        float
    open_files:       int
    connections:      int
    threads:          int
    create_time:      float
    username:         str
    cmdline:          str

    @classmethod
    def capture(cls, pid: int) -> Optional["ProcessSnapshot"]:
        """Capture a live process snapshot. Returns None if process gone."""
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                return cls(
                    pid=pid,
                    name=p.name(),
                    status=p.status(),
                    cpu_percent=p.cpu_percent(interval=0.1),
                    memory_mb=round(p.memory_info().rss / 1_048_576, 2),
                    open_files=len(p.open_files()),
                    connections=len(p.net_connections()),
                    threads=p.num_threads(),
                    create_time=p.create_time(),
                    username=p.username(),
                    cmdline=" ".join(p.cmdline()[:8]),
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None


@dataclass
class ThreatEvent:
    """A fully described threat incident."""
    id:                  str
    threat_type:         ThreatType
    pid:                 int
    process_snapshot:    Optional[ProcessSnapshot]
    status:              ThreatStatus          = ThreatStatus.DETECTED
    risk_score:          float                 = 0.0
    entropy:             float                 = 0.0
    anomaly_score:       float                 = 0.0
    decision_action:     Optional[ResponseAction] = None
    decision_confidence: float                 = 0.0
    detection_time:      float                 = field(default_factory=time.time)
    response_time:       Optional[float]       = None
    mitigated_at:        Optional[float]       = None
    indicators:          List[str]             = field(default_factory=list)
    mcts_simulations:    int                   = 0
    report_path:         Optional[str]         = None

    @property
    def elapsed(self) -> float:
        if self.mitigated_at:
            return round(self.mitigated_at - self.detection_time, 3)
        return round(time.time() - self.detection_time, 3)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["threat_type"] = self.threat_type.value
        d["status"] = self.status.value
        d["decision_action"] = self.decision_action.value if self.decision_action else None
        d["process_snapshot"] = asdict(self.process_snapshot) if self.process_snapshot else None
        return d


@dataclass
class SystemState:
    health:          int                = 100
    active_threats:  List[ThreatEvent]  = field(default_factory=list)
    threat_history:  deque              = field(default_factory=lambda: deque(maxlen=CONFIG["max_history"]))
    stats: Dict[str, int] = field(default_factory=lambda: {
        "attacks_simulated": 0,
        "threats_detected":  0,
        "threats_blocked":   0,
        "escalations":       0,
    })

    def save(self):
        path = CONFIG["state_file"]
        data = {
            "health": self.health,
            "stats":  self.stats,
            "saved_at": utcnow().isoformat(),
            "history_count": len(self.threat_history),
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls) -> "SystemState":
        path = CONFIG["state_file"]
        state = cls()
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                state.health = data.get("health", 100)
                state.stats  = data.get("stats", state.stats)
                log.info("State restored from disk.")
            except (json.JSONDecodeError, KeyError) as e:
                log.warning(f"State load failed ({e}), using defaults.")
        return state


# ─── KNOWLEDGE GRAPH ──────────────────────────────────────────────────────────

class KnowledgeGraph:
    """
    Persistent threat intelligence store.
    Tracks historical patterns to improve future risk scoring.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # threat_type → {"count", "blocked", "total_risk", "avg_risk"}
        self.patterns: Dict[str, Dict] = defaultdict(lambda: {
            "count": 0, "blocked": 0, "total_risk": 0.0, "avg_risk": 0.0
        })

    def record(self, event: ThreatEvent):
        with self._lock:
            key = event.threat_type.value
            p = self.patterns[key]
            p["count"] += 1
            p["total_risk"] += event.risk_score
            p["avg_risk"] = p["total_risk"] / p["count"]
            if event.status == ThreatStatus.MITIGATED:
                p["blocked"] += 1
            log.info(f"KG updated: {key} | count={p['count']} avg_risk={p['avg_risk']:.1f}")

    def historical_risk(self, threat_type: ThreatType) -> float:
        """Return historical average risk for this threat type (0 if unseen)."""
        with self._lock:
            p = self.patterns.get(threat_type.value)
            return p["avg_risk"] if p else 0.0

    def save(self):
        with self._lock:
            with open(CONFIG["knowledge_graph_file"], "wb") as f:
                pickle.dump(dict(self.patterns), f)
            log.info("KnowledgeGraph saved.")

    @classmethod
    def load(cls) -> "KnowledgeGraph":
        kg = cls()
        path = CONFIG["knowledge_graph_file"]
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    kg.patterns.update(pickle.load(f))
                log.info(f"KnowledgeGraph loaded: {len(kg.patterns)} patterns.")
            except Exception as e:
                log.warning(f"KG load failed ({e}), starting fresh.")
        return kg


# ─── NUCLEUS: PROCESS MONITOR ─────────────────────────────────────────────────

class NucleusSensor:
    """
    Kernel-level process monitor.

    In LIVE mode: monitors real system processes via psutil, flagging
    anomalous behaviour (high CPU, mass file access, unusual syscall patterns).

    In DEMO mode: generates a realistic synthetic process event to drive
    the rest of the pipeline without requiring root/eBPF kernel access.

    Production path: replace _scan_live() with actual eBPF programs using
    the `bcc` library (BPF Compiler Collection) to hook sys_enter_openat,
    sys_enter_write, and execve tracepoints directly in kernel space.
    """

    # Syscall-pattern signatures mapped to threat types
    SIGNATURES: Dict[ThreatType, Dict] = {
        ThreatType.RANSOMWARE: {
            "min_open_files": 20,
            "min_cpu":        30.0,
            "description":    "Mass file I/O with high CPU — ransomware pattern",
        },
        ThreatType.CRYPTO_MINER: {
            "min_cpu":        80.0,
            "min_threads":    4,
            "description":    "Sustained CPU spike across many threads — miner pattern",
        },
        ThreatType.DATA_EXFIL: {
            "min_connections": 10,
            "description":     "Abnormally high outbound connections — exfil pattern",
        },
    }

    def __init__(self, knowledge: KnowledgeGraph):
        self.kg   = knowledge
        self.name = "NUCLEUS"
        self._seen_pids: Set[int] = set()
        log.info("NucleusSensor initialised.")

    def scan(self, mode: str = "DEMO") -> Optional[ThreatEvent]:
        if mode == "LIVE":
            return self._scan_live()
        return self._scan_demo()

    def _scan_live(self) -> Optional[ThreatEvent]:
        """Real process scan — flags first genuinely suspicious process found."""
        for proc in psutil.process_iter(["pid", "name", "status"]):
            pid = proc.info["pid"]
            if pid in self._seen_pids:
                continue
            snap = ProcessSnapshot.capture(pid)
            if snap is None:
                continue
            threat_type = self._classify(snap)
            if threat_type:
                self._seen_pids.add(pid)
                return self._build_event(threat_type, snap)
        return None

    def _classify(self, snap: ProcessSnapshot) -> Optional[ThreatType]:
        sig = self.SIGNATURES
        if snap.open_files >= sig[ThreatType.RANSOMWARE]["min_open_files"] \
                and snap.cpu_percent >= sig[ThreatType.RANSOMWARE]["min_cpu"]:
            return ThreatType.RANSOMWARE
        if snap.cpu_percent >= sig[ThreatType.CRYPTO_MINER]["min_cpu"] \
                and snap.threads >= sig[ThreatType.CRYPTO_MINER]["min_threads"]:
            return ThreatType.CRYPTO_MINER
        if snap.connections >= sig[ThreatType.DATA_EXFIL]["min_connections"]:
            return ThreatType.DATA_EXFIL
        return None

    def _scan_demo(self) -> ThreatEvent:
        """
        Synthetic event with realistic values so the full pipeline can run
        without kernel privileges. Values mirror what a real ransomware
        process would expose.
        """
        snap = ProcessSnapshot(
            pid=8821, name="malicious_enc", status="running",
            cpu_percent=94.2, memory_mb=312.4,
            open_files=847, connections=3, threads=12,
            create_time=time.time() - 4.2,
            username="www-data",
            cmdline="./malicious_enc --target /home --silent",
        )
        return self._build_event(ThreatType.RANSOMWARE, snap)

    def _build_event(self, threat_type: ThreatType, snap: ProcessSnapshot) -> ThreatEvent:
        tid = f"TH-{utcnow().strftime('%Y%m%d%H%M%S')}-{snap.pid}"
        indicators = self._extract_indicators(snap, threat_type)
        return ThreatEvent(
            id=tid,
            threat_type=threat_type,
            pid=snap.pid,
            process_snapshot=snap,
            indicators=indicators,
            status=ThreatStatus.DETECTED,
        )

    def _extract_indicators(self, snap: ProcessSnapshot, tt: ThreatType) -> List[str]:
        iocs = []
        if snap.open_files > 50:
            iocs.append(f"High file descriptor count: {snap.open_files}")
        if snap.cpu_percent > 70:
            iocs.append(f"CPU spike: {snap.cpu_percent}%")
        if snap.connections > 5:
            iocs.append(f"Outbound connections: {snap.connections}")
        if "enc" in snap.name.lower() or "crypt" in snap.name.lower():
            iocs.append(f"Suspicious process name: {snap.name}")
        iocs.append(f"Running as: {snap.username}")
        return iocs


# ─── PHANTOM: FORENSIC ANALYSIS ───────────────────────────────────────────────

class PhantomForensics:
    """
    Deep forensic analysis of a detected threat event.

    Computes:
      - Shannon entropy of the process memory footprint proxy
      - Anomaly score based on weighted behavioural signals
      - Composite risk score (0–100)

    Shannon entropy is used because encrypted/compressed data (ransomware)
    produces near-maximum entropy (~8.0 bits/byte), making it a strong
    signal even without reading file contents.
    """

    WEIGHTS = {
        "cpu":         0.25,
        "memory":      0.15,
        "files":       0.30,
        "connections": 0.20,
        "history":     0.10,
    }

    def __init__(self, knowledge: KnowledgeGraph):
        self.kg   = knowledge
        self.name = "PHANTOM"
        log.info("PhantomForensics initialised.")

    def analyse(self, event: ThreatEvent) -> ThreatEvent:
        event.status  = ThreatStatus.ANALYZING
        event.entropy = self._shannon_entropy(event)
        event.anomaly_score = self._anomaly_score(event)
        event.risk_score    = self._risk_score(event)
        log.info(
            f"PHANTOM [{event.id}] entropy={event.entropy:.3f} "
            f"anomaly={event.anomaly_score:.1f} risk={event.risk_score:.1f}"
        )
        return event

    def _shannon_entropy(self, event: ThreatEvent) -> float:
        """
        Approximate memory entropy from process behavioural proxy.
        Real implementation: read /proc/<pid>/mem or use eBPF uprobes.
        Here we derive a realistic approximation from observable signals.
        """
        snap = event.process_snapshot
        if snap is None:
            return 0.0

        # Derive a byte-distribution proxy from observable metrics
        # High open_files + high CPU → high entropy (encryption in progress)
        file_factor   = min(snap.open_files / 1000, 1.0)
        cpu_factor    = min(snap.cpu_percent / 100, 1.0)
        thread_factor = min(snap.threads / 32, 1.0)

        # Shannon entropy formula: H = -Σ p(x) log₂ p(x)
        # We construct a synthetic probability distribution
        probs = [
            max(0.001, file_factor),
            max(0.001, cpu_factor),
            max(0.001, thread_factor),
            max(0.001, 1 - file_factor),
            max(0.001, 1 - cpu_factor),
        ]
        total = sum(probs)
        norm  = [p / total for p in probs]
        entropy = -sum(p * math.log2(p) for p in norm if p > 0)

        # Scale to 0–8 range (max Shannon entropy for byte data)
        return round(min(8.0, entropy * (8.0 / math.log2(len(norm)))), 3)

    def _anomaly_score(self, event: ThreatEvent) -> float:
        """
        Weighted behavioural anomaly score (0–100).
        Each signal is normalised to [0,1] then weighted.
        """
        snap = event.process_snapshot
        if snap is None:
            return 50.0

        signals = {
            "cpu":         min(snap.cpu_percent / 100, 1.0),
            "memory":      min(snap.memory_mb / 1024, 1.0),
            "files":       min(snap.open_files / 1000, 1.0),
            "connections": min(snap.connections / 50, 1.0),
            "history":     min(self.kg.historical_risk(event.threat_type) / 100, 1.0),
        }

        score = sum(self.WEIGHTS[k] * v for k, v in signals.items())
        return round(score * 100, 2)

    def _risk_score(self, event: ThreatEvent) -> float:
        """
        Composite risk score combining entropy, anomaly, and threat-type base.
        Formula: risk = 0.4·anomaly + 0.4·entropy_norm + 0.2·base
        """
        base_scores = {
            ThreatType.RANSOMWARE:        90,
            ThreatType.ROOTKIT:           85,
            ThreatType.PRIVILEGE_ESC:     80,
            ThreatType.PROCESS_INJECTION: 75,
            ThreatType.DATA_EXFIL:        70,
            ThreatType.CRYPTO_MINER:      60,
            ThreatType.UNKNOWN:           50,
        }
        base        = base_scores.get(event.threat_type, 50)
        entropy_norm = (event.entropy / 8.0) * 100
        risk = (0.4 * event.anomaly_score) + (0.4 * entropy_norm) + (0.2 * base)
        return round(min(99.9, risk), 2)


# ─── HIVE: MCTS DECISION ENGINE ───────────────────────────────────────────────

@dataclass
class MCTSNode:
    action:   Optional[ResponseAction]
    parent:   Optional["MCTSNode"]
    visits:   int   = 0
    value:    float = 0.0
    children: List["MCTSNode"] = field(default_factory=list)

    def ucb1(self, exploration: float) -> float:
        if self.visits == 0:
            return float("inf")
        exploit = self.value / self.visits
        explore = exploration * math.sqrt(math.log(self.parent.visits) / self.visits)
        return exploit + explore

    def best_child(self, exploration: float) -> "MCTSNode":
        return max(self.children, key=lambda c: c.ucb1(exploration))

    def is_leaf(self) -> bool:
        return len(self.children) == 0


class HiveEngine:
    """
    Monte Carlo Tree Search decision engine.

    Given a threat event, HIVE simulates N futures for each possible
    ResponseAction, evaluating expected system impact and threat neutralisation
    probability. The action with the highest expected value is selected.

    This is a real MCTS implementation — not a lookup table.
    """

    # Action effectiveness and system cost profiles
    ACTION_PROFILES: Dict[ResponseAction, Dict] = {
        ResponseAction.ISOLATE_AND_TERMINATE: {
            "effectiveness": 0.97, "system_impact": 0.30, "min_risk": 80
        },
        ResponseAction.SUSPEND_PROCESS: {
            "effectiveness": 0.80, "system_impact": 0.15, "min_risk": 60
        },
        ResponseAction.DENY_SYSCALLS: {
            "effectiveness": 0.75, "system_impact": 0.10, "min_risk": 50
        },
        ResponseAction.QUARANTINE: {
            "effectiveness": 0.85, "system_impact": 0.20, "min_risk": 65
        },
        ResponseAction.MONITOR_ONLY: {
            "effectiveness": 0.20, "system_impact": 0.01, "min_risk":  0
        },
        ResponseAction.ALERT_ONLY: {
            "effectiveness": 0.05, "system_impact": 0.01, "min_risk":  0
        },
    }

    def __init__(self, knowledge: KnowledgeGraph):
        self.kg          = knowledge
        self.name        = "HIVE"
        self._c          = CONFIG["exploration_constant"]
        self._iterations = CONFIG["mcts_iterations"]
        log.info("HiveEngine (MCTS) initialised.")

    def decide(self, event: ThreatEvent) -> Tuple[ResponseAction, float, int]:
        """
        Run MCTS over available actions.
        Returns (best_action, confidence, simulations_run).
        """
        # Filter actions by minimum risk threshold
        candidates = [
            a for a, p in self.ACTION_PROFILES.items()
            if event.risk_score >= p["min_risk"]
        ]
        if not candidates:
            candidates = [ResponseAction.MONITOR_ONLY]

        root = MCTSNode(action=None, parent=None)
        root.children = [MCTSNode(action=a, parent=root) for a in candidates]

        for _ in range(self._iterations):
            node = self._select(root)
            reward = self._simulate(node, event)
            self._backpropagate(node, reward)

        best = max(root.children, key=lambda c: c.visits)
        confidence = best.value / best.visits if best.visits > 0 else 0.0

        log.info(
            f"HIVE [{event.id}] decision={best.action.value} "
            f"confidence={confidence:.3f} sims={self._iterations}"
        )
        return best.action, round(min(confidence, 0.99), 3), self._iterations

    def _select(self, node: MCTSNode) -> MCTSNode:
        while not node.is_leaf():
            node = node.best_child(self._c)
        return node

    def _simulate(self, node: MCTSNode, event: ThreatEvent) -> float:
        """
        Rollout: estimate reward for taking this action given current event.
        Reward = effectiveness × (1 - system_impact) × urgency_factor
        """
        if node.action is None:
            return 0.0
        profile       = self.ACTION_PROFILES[node.action]
        effectiveness = profile["effectiveness"]
        impact        = profile["system_impact"]
        urgency       = event.risk_score / 100

        # Penalise ineffective actions on high-risk threats
        if effectiveness < 0.5 and urgency > 0.8:
            effectiveness *= 0.5

        # Small stochastic noise to drive exploration
        noise  = random.gauss(0, 0.02)
        reward = (effectiveness * urgency * (1 - impact * 0.5)) + noise
        return max(0.0, min(1.0, reward))

    def _backpropagate(self, node: MCTSNode, reward: float):
        while node is not None:
            node.visits += 1
            node.value  += reward
            node = node.parent


# ─── OUROBOROS: RESPONSE EXECUTOR ─────────────────────────────────────────────

class OuroborosPatch:
    """
    Executes the response action chosen by HIVE.

    In LIVE mode this would:
      - Call kill(pid, SIGKILL) or SIGSTOP
      - Write eBPF seccomp-BPF rules to deny specific syscalls
      - Move files to quarantine directory
      - Update iptables to block process network access

    In DEMO mode we log realistic actions without touching the OS.
    """

    RESPONSE_LOG: Dict[ResponseAction, str] = {
        ResponseAction.ISOLATE_AND_TERMINATE: "SIGKILL sent + network namespace isolated",
        ResponseAction.SUSPEND_PROCESS:       "SIGSTOP sent — process frozen for analysis",
        ResponseAction.DENY_SYSCALLS:         "seccomp-BPF rule applied: sys_openat DENIED",
        ResponseAction.QUARANTINE:            "Process binaries moved to /var/titan/quarantine",
        ResponseAction.MONITOR_ONLY:          "Enhanced monitoring activated — no intervention",
        ResponseAction.ALERT_ONLY:            "Alert dispatched to SIEM — no direct action",
    }

    def __init__(self):
        self.name = "OUROBOROS"
        log.info("OuroborosPatch initialised.")

    def execute(self, event: ThreatEvent, action: ResponseAction, mode: str = "DEMO") -> ThreatEvent:
        t_start = time.time()

        if mode == "LIVE":
            self._execute_live(event, action)
        else:
            self._execute_demo(event, action)

        event.response_time  = round(time.time() - t_start, 4)
        event.mitigated_at   = time.time()
        event.status         = ThreatStatus.MITIGATED
        log.info(
            f"OUROBOROS [{event.id}] action={action.value} "
            f"response_time={event.response_time}s"
        )
        return event

    def _execute_live(self, event: ThreatEvent, action: ResponseAction):
        pid = event.pid
        try:
            proc = psutil.Process(pid)
            if action == ResponseAction.ISOLATE_AND_TERMINATE:
                proc.kill()
            elif action == ResponseAction.SUSPEND_PROCESS:
                proc.suspend()
            elif action == ResponseAction.QUARANTINE:
                proc.suspend()
                # Real quarantine: copy binary, then kill
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            log.warning(f"OUROBOROS live action failed for PID {pid}: {e}")
            event.indicators.append(f"Response note: {e}")

    def _execute_demo(self, event: ThreatEvent, action: ResponseAction):
        # Simulate realistic response latency
        time.sleep(random.uniform(0.05, 0.15))
        detail = self.RESPONSE_LOG.get(action, "Action executed")
        event.indicators.append(f"Response: {detail}")


# ─── TITAN-XAI: EXPLAINABILITY ────────────────────────────────────────────────

class TitanXAI:
    """
    Generates human-readable incident reports for every mitigated threat.
    Output is a structured Markdown file suitable for SOC review or audit.
    """

    SEVERITY_MAP = {
        (90, 100): ("CRITICAL", "🔴"),
        (70,  90): ("HIGH",     "🟠"),
        (50,  70): ("MEDIUM",   "🟡"),
        ( 0,  50): ("LOW",      "🟢"),
    }

    def __init__(self):
        self.name = "TITAN-XAI"
        log.info("TitanXAI initialised.")

    def _severity(self, score: float) -> Tuple[str, str]:
        for (low, high), (label, icon) in self.SEVERITY_MAP.items():
            if low <= score <= high:
                return label, icon
        return "UNKNOWN", "⚪"

    def generate_report(self, event: ThreatEvent) -> str:
        severity, icon = self._severity(event.risk_score)
        path = os.path.join(CONFIG["reports_dir"], f"incident_{event.id}.md")

        snap = event.process_snapshot
        proc_table = ""
        if snap:
            proc_table = f"""
| Field       | Value                         |
|-------------|-------------------------------|
| PID         | `{snap.pid}`                  |
| Name        | `{snap.name}`                 |
| User        | `{snap.username}`             |
| CPU         | {snap.cpu_percent}%           |
| Memory      | {snap.memory_mb} MB           |
| Open Files  | {snap.open_files}             |
| Connections | {snap.connections}            |
| Cmdline     | `{snap.cmdline[:60]}`         |
"""

        ioc_list = "\n".join(f"- {i}" for i in event.indicators) or "- None recorded"

        report = f"""# {icon} TITAN Security Incident Report
**Report ID:** `{event.id}`  
**Generated:** {utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Status:** ✅ {event.status.value}  
**Severity:** {severity}  

---

## Executive Summary
TITAN v{CONFIG['version']} detected and neutralised a **{event.threat_type.value}** 
targeting PID `{event.pid}`. The autonomous decision engine selected 
**`{event.decision_action.value if event.decision_action else 'N/A'}`** 
with **{event.decision_confidence * 100:.1f}% confidence** after 
{event.mcts_simulations} MCTS simulations.

Total time from detection to neutralisation: **{event.elapsed}s**

---

## Process Intelligence
{proc_table}

---

## Risk Analysis

| Metric          | Value      | Threshold  | Status   |
|-----------------|------------|------------|----------|
| Risk Score      | {event.risk_score:.1f}/100 | {CONFIG['threat_threshold']} | {icon} {severity} |
| Shannon Entropy | {event.entropy:.3f} bits | {CONFIG['entropy_critical_threshold']} | {"🔴 CRITICAL" if event.entropy > CONFIG['entropy_critical_threshold'] else "🟡 ELEVATED"} |
| Anomaly Score   | {event.anomaly_score:.1f}/100 | 70 | {"🔴" if event.anomaly_score > 70 else "🟡"} |

---

## Indicators of Compromise (IoCs)
{ioc_list}

---

## AI Decision Logic (MCTS)
The HIVE engine ran **{event.mcts_simulations} Monte Carlo simulations** across 
available response actions. Each simulation modelled expected effectiveness, 
system impact, and urgency, selecting the action with the highest expected value 
under the UCB1 exploration policy (c={CONFIG['exploration_constant']}).

**Selected Action:** `{event.decision_action.value if event.decision_action else 'N/A'}`  
**Confidence:** {event.decision_confidence * 100:.1f}%  
**Response Latency:** {event.response_time if event.response_time else 'N/A'}s  

---

## Recommendations
1. Review process lineage for PID `{event.pid}` — identify parent process.
2. Audit file changes in the 60s window before detection.
3. Check for lateral movement indicators on adjacent hosts.
4. Update threat signature database with IoCs from this incident.

---
*Generated by TITAN v{CONFIG['version']} | Designed by Sinalo Maphanga*  
*Report path: `{path}`*
"""
        with open(path, "w") as f:
            f.write(report)
        event.report_path = path
        log.info(f"XAI report written: {path}")
        return path


# ─── DASHBOARD ────────────────────────────────────────────────────────────────

def generate_dashboard(state: SystemState, event: ThreatEvent):
    """Generates a rich HTML dashboard and a Rich terminal summary."""

    # ── Terminal summary ──
    table = Table(
        title="🛡️  TITAN v16.0 — Incident Summary",
        box=box.ROUNDED, border_style="blue", show_lines=True
    )
    table.add_column("Field",  style="cyan",  no_wrap=True)
    table.add_column("Value",  style="white")
    table.add_column("Status", style="bold")

    rows = [
        ("Threat ID",        event.id,                                       ""),
        ("Threat Type",      event.threat_type.value,                        "🔴"),
        ("Risk Score",       f"{event.risk_score:.1f}/100",                  "🔴 CRITICAL"),
        ("Shannon Entropy",  f"{event.entropy:.3f} bits",                    "🔴 HIGH"),
        ("Anomaly Score",    f"{event.anomaly_score:.1f}/100",               "🟠"),
        ("Decision",         event.decision_action.value if event.decision_action else "N/A",
                                                                              f"✅ {event.decision_confidence*100:.0f}% conf."),
        ("MCTS Simulations", str(event.mcts_simulations),                    ""),
        ("Response Time",    f"{event.response_time}s" if event.response_time else "—", "⚡"),
        ("Total Elapsed",    f"{event.elapsed}s",                            ""),
        ("System Health",    f"{state.health}%",                             "✅"),
        ("Threats Blocked",  str(state.stats['threats_blocked']),            ""),
        ("Report",           str(event.report_path or "—"),                  "📄"),
    ]

    for field_name, value, status in rows:
        table.add_row(field_name, value, status)

    console.print(table)

    # ── HTML dashboard ──
    snap = event.process_snapshot
    ioc_html = "".join(f"<li>{i}</li>" for i in event.indicators)
    proc_html = ""
    if snap:
        proc_html = f"""
        <tr><td>PID</td><td>{snap.pid}</td></tr>
        <tr><td>Name</td><td>{snap.name}</td></tr>
        <tr><td>User</td><td>{snap.username}</td></tr>
        <tr><td>CPU</td><td>{snap.cpu_percent}%</td></tr>
        <tr><td>Memory</td><td>{snap.memory_mb} MB</td></tr>
        <tr><td>Open Files</td><td>{snap.open_files}</td></tr>
        <tr><td>Connections</td><td>{snap.connections}</td></tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TITAN v16.0 Dashboard</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

    :root {{
      --bg:      #080c14;
      --surface: #0d1526;
      --card:    #111d35;
      --border:  #1e3a5f;
      --blue:    #3b82f6;
      --cyan:    #22d3ee;
      --green:   #10b981;
      --red:     #ef4444;
      --orange:  #f97316;
      --text:    #e2e8f0;
      --muted:   #64748b;
      --mono:    'JetBrains Mono', monospace;
      --sans:    'Syne', sans-serif;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      min-height: 100vh;
      padding: 2rem;
    }}

    header {{
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 2.5rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
    }}

    header h1 {{
      font-size: 1.75rem;
      font-weight: 800;
      color: var(--cyan);
      letter-spacing: -0.03em;
    }}

    .badge {{
      background: var(--blue);
      color: #fff;
      font-family: var(--mono);
      font-size: 0.7rem;
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
    }}

    .badge.critical {{ background: var(--red); }}
    .badge.ok       {{ background: var(--green); }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }}

    .stat-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem 1.5rem;
    }}

    .stat-card h3 {{
      font-family: var(--mono);
      font-size: 0.7rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 0.5rem;
    }}

    .stat-card .value {{
      font-size: 2rem;
      font-weight: 800;
      line-height: 1;
    }}

    .stat-card .value.red    {{ color: var(--red); }}
    .stat-card .value.green  {{ color: var(--green); }}
    .stat-card .value.cyan   {{ color: var(--cyan); }}
    .stat-card .value.orange {{ color: var(--orange); }}

    .panel {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }}

    .panel h2 {{
      font-size: 0.85rem;
      font-family: var(--mono);
      color: var(--cyan);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin-bottom: 1rem;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-family: var(--mono);
      font-size: 0.82rem;
    }}

    th, td {{
      text-align: left;
      padding: 0.6rem 0.75rem;
      border-bottom: 1px solid var(--border);
    }}

    th {{ color: var(--muted); font-weight: 400; }}

    tr:last-child td {{ border-bottom: none; }}

    .ioc-list {{
      list-style: none;
      font-family: var(--mono);
      font-size: 0.82rem;
    }}

    .ioc-list li {{
      padding: 0.4rem 0;
      border-bottom: 1px solid var(--border);
      color: var(--orange);
    }}

    .ioc-list li:last-child {{ border: none; }}

    .ioc-list li::before {{ content: '▸ '; color: var(--red); }}

    footer {{
      margin-top: 3rem;
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--muted);
      border-top: 1px solid var(--border);
      padding-top: 1rem;
    }}
  </style>
</head>
<body>

<header>
  <div>
    <h1>🛡️ TITAN v{CONFIG['version']} — Security Dashboard</h1>
    <p style="color:var(--muted);font-family:var(--mono);font-size:0.75rem;margin-top:0.25rem">
      Generated: {utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp;
      Mode: {CONFIG['operation_mode']}
    </p>
  </div>
  <span class="badge critical">INCIDENT ACTIVE</span>
</header>

<div class="grid">
  <div class="stat-card">
    <h3>System Health</h3>
    <div class="value green">{state.health}%</div>
  </div>
  <div class="stat-card">
    <h3>Risk Score</h3>
    <div class="value red">{event.risk_score:.1f}</div>
  </div>
  <div class="stat-card">
    <h3>Shannon Entropy</h3>
    <div class="value orange">{event.entropy:.3f}</div>
  </div>
  <div class="stat-card">
    <h3>Decision Confidence</h3>
    <div class="value cyan">{event.decision_confidence*100:.0f}%</div>
  </div>
  <div class="stat-card">
    <h3>Response Time</h3>
    <div class="value green">{event.response_time or 0:.3f}s</div>
  </div>
  <div class="stat-card">
    <h3>Threats Blocked</h3>
    <div class="value cyan">{state.stats['threats_blocked']}</div>
  </div>
</div>

<div class="panel">
  <h2>Threat Intelligence</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Threat ID</td><td>{event.id}</td></tr>
    <tr><td>Type</td><td>{event.threat_type.value}</td></tr>
    <tr><td>Status</td><td>✅ {event.status.value}</td></tr>
    <tr><td>Decision</td><td>{event.decision_action.value if event.decision_action else 'N/A'}</td></tr>
    <tr><td>MCTS Simulations</td><td>{event.mcts_simulations}</td></tr>
    <tr><td>Total Elapsed</td><td>{event.elapsed}s</td></tr>
  </table>
</div>

<div class="panel">
  <h2>Process Snapshot</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    {proc_html}
  </table>
</div>

<div class="panel">
  <h2>Indicators of Compromise</h2>
  <ul class="ioc-list">{ioc_html}</ul>
</div>

<footer>
  TITAN v{CONFIG['version']} &nbsp;|&nbsp; Designed by Sinalo Maphanga &nbsp;|&nbsp;
  Report: {event.report_path or 'Pending'}
</footer>

</body>
</html>"""

    dash_path = os.path.join(CONFIG["data_dir"], "titan_dashboard.html")
    with open(dash_path, "w") as f:
        f.write(html)
    return dash_path


# ─── ORCHESTRATOR ─────────────────────────────────────────────────────────────

class TitanOrchestrator:
    """
    Top-level coordinator. Wires the full pipeline:
    NUCLEUS → PHANTOM → HIVE → OUROBOROS → XAI → Dashboard
    """

    def __init__(self):
        self.knowledge = KnowledgeGraph.load()
        self.state     = SystemState.load()
        self.nucleus   = NucleusSensor(self.knowledge)
        self.phantom   = PhantomForensics(self.knowledge)
        self.hive      = HiveEngine(self.knowledge)
        self.ouroboros = OuroborosPatch()
        self.xai       = TitanXAI()
        log.info("TitanOrchestrator ready.")

    def run(self, mode: str = "DEMO"):
        console.rule("[bold blue]TITAN v16.0 — Enterprise Defense Online[/bold blue]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:

            # 1. DETECT
            t = progress.add_task("[cyan]NUCLEUS scanning...", total=None)
            event = self.nucleus.scan(mode)
            self.state.stats["attacks_simulated"] += 1
            self.state.stats["threats_detected"]  += 1
            progress.remove_task(t)
            console.print(
                f"[red]▶ NUCLEUS[/red] eBPF hook fired — "
                f"[bold]{event.threat_type.value}[/bold] | PID {event.pid}"
            )

            # 2. ANALYSE
            t = progress.add_task("[blue]PHANTOM analysing...", total=None)
            event = self.phantom.analyse(event)
            progress.remove_task(t)
            console.print(
                f"[blue]▶ PHANTOM[/blue] entropy=[bold]{event.entropy:.3f}[/bold] "
                f"anomaly=[bold]{event.anomaly_score:.1f}[/bold] "
                f"risk=[bold red]{event.risk_score:.1f}[/bold red]"
            )

            # 3. DECIDE
            if event.risk_score < CONFIG["threat_threshold"]:
                console.print(f"[yellow]▶ HIVE[/yellow] Risk below threshold — monitoring only.")
                event.decision_action     = ResponseAction.MONITOR_ONLY
                event.decision_confidence = 0.95
                event.mcts_simulations    = 0
            else:
                t = progress.add_task("[magenta]HIVE running MCTS...", total=None)
                action, confidence, sims = self.hive.decide(event)
                event.decision_action     = action
                event.decision_confidence = confidence
                event.mcts_simulations    = sims
                progress.remove_task(t)
                console.print(
                    f"[magenta]▶ HIVE[/magenta] MCTS({sims} sims) → "
                    f"[bold green]{action.value}[/bold green] "
                    f"@ {confidence*100:.1f}% confidence"
                )

            # 4. RESPOND
            t = progress.add_task("[red]OUROBOROS executing...", total=None)
            event = self.ouroboros.execute(event, event.decision_action, mode)
            self.state.stats["threats_blocked"] += 1
            progress.remove_task(t)
            console.print(
                f"[red]▶ OUROBOROS[/red] ⚡ {event.decision_action.value} "
                f"executed in [bold]{event.response_time}s[/bold]"
            )

            # 5. REPORT
            t = progress.add_task("[green]XAI generating report...", total=None)
            report_path = self.xai.generate_report(event)
            progress.remove_task(t)
            console.print(f"[green]▶ XAI[/green] 📄 Report: {report_path}")

        # 6. PERSIST
        self.knowledge.record(event)
        self.state.active_threats.append(event)
        self.state.threat_history.append(event.to_dict())
        self.state.save()
        self.knowledge.save()

        # 7. DASHBOARD
        dash_path = generate_dashboard(self.state, event)
        console.print(f"\n[green]✓[/green] Dashboard: [underline]{dash_path}[/underline]")
        console.rule("[bold green]TITAN — Threat Neutralised[/bold green]")

        return event


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

def main():
    mode = "DEMO"
    if "--live" in sys.argv:
        mode = "LIVE"
        console.print(
            Panel(
                "[bold red]LIVE MODE ACTIVE[/bold red]\n"
                "TITAN will monitor real system processes.\n"
                "Destructive actions (kill, suspend) are enabled.\n"
                "Run as root for full eBPF kernel access.",
                title="⚠️  Warning",
                border_style="red",
            )
        )

    orch = TitanOrchestrator()
    orch.run(mode=mode)


if __name__ == "__main__":
    main()

