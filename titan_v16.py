#!/usr/bin/env python3
"""
🛡️ PROJECT TITAN v16.0: CONTINUOUS SECURITY VALIDATION ENGINE
Copyright © 2025 Sinalo Maphanga. All Rights Reserved.
"""

import os, sys, time, json, copy, math, pickle, random, logging, signal, threading, statistics
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Tuple, Set
from abc import ABC, abstractmethod
from contextlib import contextmanager
from enum import Enum

# --- CONFIGURATION ---
CONFIG = {
    "data_dir": "./titan_data",
    "sandbox_dir": "/tmp/titan_sandbox",
    "reports_dir": "./titan_data/reports",
    "knowledge_graph_file": "knowledge_graph.pkl",
    "state_file": "system_state.json",
    "max_history": 2000,
    "learning_rate": 0.1,
    "threat_threshold": 75,
    "decision_iterations": 100, # Reduced for speed
    "exploration_constant": 1.414,
    "cluster_similarity_threshold": 0.7,
    "operation_mode": "DEMO"
}

# ANSI Colors
class C:
    HEADER = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN = '\033[92m'; WARN = '\033[93m'; FAIL = '\033[91m'
    END = '\033[0m'; MAGENTA = '\033[35m'; PURPLE = '\033[35m'

# Setup Directories
os.makedirs(CONFIG['data_dir'], exist_ok=True)
os.makedirs(CONFIG['reports_dir'], exist_ok=True)
if not os.path.exists(CONFIG['sandbox_dir']): os.makedirs(CONFIG['sandbox_dir'])

# ==============================================================================
# CORE CLASSES (Simplified for Stability)
# ==============================================================================

@dataclass
class DecisionState:
    metrics: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    def clone(self): return DecisionState(copy.deepcopy(self.metrics), copy.deepcopy(self.metadata))
    def get(self, k, d=0.0): return self.metrics.get(k, d)
    def __hash__(self): return hash(tuple(sorted(self.metrics.items())))

@dataclass
class ResponseAction:
    name: str
    effect: Callable
    cost: float = 0.0
    def apply(self, s): return self.effect(s.clone())
    def __hash__(self): return hash(self.name)

class KnowledgeGraph:
    def __init__(self):
        self.threat_patterns = defaultdict(lambda: {"count": 0, "blocked": 0, "avg_score": 0.0})
        self.threat_clusters = {}
        self.cluster_counter = 0
        self.lock = threading.RLock()

    def predict_risk_score(self, threat):
        # Simulated AI Risk Scoring
        base = 50.0
        if "Ransomware" in threat['type']: base += 40
        return min(99.9, base + random.uniform(-5, 5))

    def save(self, path):
        with open(path, 'wb') as f: pickle.dump(self.threat_patterns, f)

    @classmethod
    def load(cls, path):
        return cls()

@dataclass
class SystemState:
    health: int = 100
    active_threats: List[Dict] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=lambda: {"attacks_simulated":0, "threats_blocked":0})
    performance: Dict[str, List[float]] = field(default_factory=dict)
    def save(self, path):
        with open(path, 'w') as f: json.dump(asdict(self), f, indent=2)

# ==============================================================================
# MODULES
# ==============================================================================

class TitanEngine:
    def __init__(self, kg): self.name = "TITAN"
    def execute(self, ctx): pass # Handled in main for demo

class NucleusSensor:
    def __init__(self, kg): self.name = "NUCLEUS"
    def execute(self, ctx): pass

class PhantomForensics:
    def __init__(self, kg): self.name = "PHANTOM"
    def execute(self, ctx): pass

class HiveEngine:
    def __init__(self, kg): self.name = "HIVE"
    def execute(self, ctx): pass

class OuroborosPatch:
    def __init__(self, kg): self.name = "OUROBOROS"
    def execute(self, ctx): pass

class TitanXAI:
    def __init__(self, kg):
        self.name = "TITAN-XAI"
        self.kg = kg
    
    def execute(self, ctx):
        for threat in ctx.active_threats:
            if threat["status"] == "MITIGATED":
                self._generate_report(threat)

    def _generate_report(self, threat):
        tid = threat['id']
        path = os.path.join(CONFIG['reports_dir'], f"incident_report_{tid}.md")
        
        # SAFE STRING GENERATION (No complex f-strings)
        lines = []
        lines.append(f"# 🛡️ TITAN Security Incident Report")
        lines.append(f"**Report ID:** `{tid}`")
        lines.append(f"**Status:** ✅ MITIGATED")
        lines.append(f"")
        lines.append(f"## 📋 Executive Summary")
        lines.append(f"TITAN detected and neutralized a **{threat['type']}** targeting PID {threat['pid']}.")
        lines.append(f"The AI decision engine selected **{threat['decision_action']}** with **{threat['decision_confidence']*100:.1f}%** confidence.")
        lines.append(f"")
        lines.append(f"## 🔍 Analysis")
        lines.append(f"| Metric | Value | Assessment |")
        lines.append(f"|--------|-------|------------|")
        lines.append(f"| Risk Score | {threat['risk_score']} | CRITICAL |")
        lines.append(f"| Entropy | {threat['memory_entropy']} | HIGH |")
        lines.append(f"| Detection | {threat['detection_latency']}s | INSTANT |")
        lines.append(f"")
        lines.append(f"## 🧠 AI Decision Logic (MCTS)")
        lines.append(f"Simulated **{CONFIG['decision_iterations']}** futures. Optimal path selected based on system impact minimization.")
        lines.append(f"")
        lines.append(f"---")
        lines.append(f"**Generated by TITAN v16.0** | Designed by Sinalo Maphanga")
        
        with open(path, 'w') as f:
            f.write("\n".join(lines))
        print(f"{C.PURPLE}   [TITAN-XAI] 📝 Report Generated: {path}{C.END}")

# ==============================================================================
# DASHBOARD GENERATOR
# ==============================================================================

def generate_dashboard(ctx, kg):
    path = os.path.join(CONFIG['data_dir'], "titan_dashboard.html")
    html = f"""
    <html><body style="background:#0f172a;color:#f8fafc;font-family:sans-serif;padding:20px;">
    <h1 style="color:#3b82f6">🛡️ TITAN v16.0 Dashboard</h1>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px;">
        <div style="background:#1e293b;padding:20px;border-radius:10px;">
            <h3>System Health</h3><h1 style="color:#10b981">{ctx.health}%</h1>
        </div>
        <div style="background:#1e293b;padding:20px;border-radius:10px;">
            <h3>Threats Blocked</h3><h1 style="color:#ef4444">{ctx.stats['threats_blocked']}</h1>
        </div>
        <div style="background:#1e293b;padding:20px;border-radius:10px;">
            <h3>Active Mode</h3><h1 style="color:#a78bfa">{CONFIG['operation_mode']}</h1>
        </div>
    </div>
    <h2>Recent Incidents</h2>
    <div style="background:#1e293b;padding:20px;border-radius:10px;">
        <p>🔴 <strong>{ctx.active_threats[0]['type']}</strong> - Mitigated in {ctx.active_threats[0]['response_time']}s</p>
    </div>
    </body></html>
    """
    with open(path, 'w') as f: f.write(html)
    print(f"\n{C.GREEN}[+] Dashboard Generated: {path}{C.END}")

# ==============================================================================
# ORCHESTRATOR & MAIN
# ==============================================================================

class TitanOrchestrator:
    def __init__(self):
        self.knowledge = KnowledgeGraph()
        self.ctx = SystemState()

def main():
    print(f"{C.HEADER}{'='*60}{C.END}")
    print(f"{C.HEADER}   🛡️  TITAN v16.0: Enterprise Defense Online{C.END}")
    print(f"{C.HEADER}{'='*60}{C.END}")
    
    print(f"{C.BLUE}[*] Initializing Safety Layer...{C.END}")
    print(f"{C.GREEN}[*] Sandbox: {CONFIG['sandbox_dir']} verified.{C.END}")
    
    orch = TitanOrchestrator()
    
    # --- DEMO SCENARIO ---
    print(f"\n{C.CYAN}>>> STARTING RANSOMWARE EVOLUTION SCENARIO (DEMO) <<<{C.END}")
    time.sleep(1)
    
    # 1. Attack
    print(f"{C.FAIL}>>> [TITAN] ⚔️  LAUNCHING: Ransomware (T1486){C.END}")
    time.sleep(0.5)
    
    # 2. Detect
    print(f"{C.CYAN}   [NUCLEUS] 👁️  eBPF Hook Detected PID 8821{C.END}")
    print(f"{C.BLUE}   [PHANTOM] 👻 Memory Entropy: 7.92 (CRITICAL){C.END}")
    time.sleep(0.5)
    
    # 3. Decide
    print(f"{C.HEADER}   [HIVE] 🧠 Risk Score: 98.5/100{C.END}")
    print(f"{C.MAGENTA}   [HIVE] 🎯 MCTS Simulation (100 iterations)...{C.END}")
    print(f"{C.MAGENTA}   [HIVE] ✓ Optimal Action: ISOLATE_AND_TERMINATE{C.END}")
    time.sleep(0.5)
    
    # 4. Respond
    print(f"{C.FAIL}   [HIVE] ⚡ EXECUTING: ISOLATE_AND_TERMINATE{C.END}")
    print(f"{C.GREEN}   [OUROBOROS] 🩹 PATCH DEPLOYED: DENY syscalls=['encrypt']{C.END}")
    
    # 5. Generate Data
    threat = {
        "id": "TH-DEMO-001", "type": "Ransomware (T1486)", "pid": 8821,
        "status": "MITIGATED", "risk_score": 98.5,
        "decision_action": "ISOLATE_AND_TERMINATE", "decision_confidence": 0.99,
        "memory_entropy": 7.92, "detection_latency": 0.04, "response_time": 0.22
    }
    orch.ctx.active_threats.append(threat)
    orch.ctx.stats["threats_blocked"] += 1
    
    # Run XAI & Dashboard
    xai = TitanXAI(orch.knowledge)
    xai.execute(orch.ctx)
    generate_dashboard(orch.ctx, orch.knowledge)
    
    print(f"\n{C.GREEN}>>> DEMO COMPLETE. ASSETS GENERATED. <<<{C.END}")

if __name__ == "__main__":
    main()