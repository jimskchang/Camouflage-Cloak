import os
import json
import logging
import threading
from collections import defaultdict
from datetime import datetime

import matplotlib.pyplot as plt
import matplotlib.animation as animation

# === Export Path ===
L7_TRACKER_LOG = os.path.join(os.path.dirname(__file__), "..", "os_record", "l7_http_log.json")

# === Thread Synchronization Lock ===
data_lock = threading.Lock()

# === In-Memory Stats ===
l7_data = defaultdict(lambda: defaultdict(int))   # {src_ip: {banner_type: count}}
ja3_map = defaultdict(set)                        # {src_ip: set(ja3)}
ua_map = defaultdict(set)                         # {src_ip: set(user-agent)}

# State placeholder for animation engine allocation
_ani_reference = None


def log_http_banner(src_ip: str, ja3: str, banner_type: str, user_agent: str = None):
    """
    Log per-IP HTTP/JA3/User-Agent correlations securely using mutex synchronization.
    """
    try:
        with data_lock:
            l7_data[src_ip][banner_type] += 1
            if ja3:
                ja3_map[src_ip].add(ja3)
            if user_agent:
                ua_map[src_ip].add(user_agent)
                
        logging.info(f"📥 L7 Telemetry Captured: {src_ip} | Type: {banner_type} | JA3={ja3}")
        
        # Periodically dump to disk to allow out-of-process dashboards to read data safely
        export()
    except Exception as e:
        logging.warning(f"⚠️ log_http_banner write failure: {e}")


def export():
    """
    Export full L7 banner hit map with JA3 and User-Agent metadata to JSON safely.
    """
    try:
        with data_lock:
            export_data = {
                "updated": datetime.utcnow().isoformat(),
                "banner_hits": {k: dict(v) for k, v in l7_data.items()},
                "ja3_map": {k: list(v) for k, v in ja3_map.items()},
                "user_agents": {k: list(v) for k, v in ua_map.items()}
            }
        
        # Ensure target directories exist before dropping logfile entries
        os.makedirs(os.path.dirname(L7_TRACKER_LOG), exist_ok=True)
        with open(L7_TRACKER_LOG, "w") as f:
            json.dump(export_data, f, indent=2)
            
    except Exception as e:
        logging.warning(f"⚠️ L7 export disk persistent error sync: {e}")


def _update_plot(frame, ax):
    """
    Internal: Re-render the live graph safely from an isolated data copy.
    """
    try:
        # FIXED: Extract data under a lock to prevent cross-thread modification crashes
        with data_lock:
            current_data = {k: dict(v) for k, v in l7_data.items()}

        ax.clear()
        summary = defaultdict(int)
        for ip, banners in current_data.items():
            for banner, count in banners.items():
                summary[banner] += count

        if not summary:
            ax.set_title("Live HTTP Banner Stats - Waiting for traffic...", fontsize=11, pad=10)
            ax.set_ylabel("Hits")
            ax.set_xlabel("Banner Type")
            return

        labels = list(summary.keys())
        values = [summary[k] for k in labels]

        # FIXED: Assign locations explicitly via set_xticks before populating text strings
        x_positions = list(range(len(labels)))
        ax.bar(x_positions, values, color="#3498db", edgecolor="#2980b9")
        
        ax.set_xticks(x_positions)
        ax.set_xticklabels(labels, rotation=25, ha='right', fontsize=9)
        
        ax.set_title("📊 Live Deception Engine HTTP Banner Hits", fontsize=12, fontweight='bold', pad=12)
        ax.set_ylabel("Total Hits Triggered", fontsize=10)
        ax.set_xlabel("Detected Client Signatures", fontsize=10)
        ax.set_ylim(0, max(values) + max(1, int(max(values) * 0.15)))
        ax.grid(axis='y', linestyle='--', alpha=0.5)
        
    except Exception as e:
        logging.error(f"⚠️ Internal visual frame plotting pipeline crash: {e}")


def launch_plot():
    """
    Configures and initializes the visualization interface elements safely.
    Note: To comply with runtime engine constraints, call this function 
    from your application script's main parent process thread loop.
    """
    global _ani_reference
    try:
        logging.info("🎨 Spawning real-time visualization dashboard window layout elements...")
        fig, ax = plt.subplots(figsize=(8, 5))
        
        # FIXED: Pass ax context explicitly and pin animation variable to prevent premature GC recycling
        _ani_reference = animation.FuncAnimation(fig, _update_plot, fargs=(ax,), interval=1000, cache_frame_data=False)
        
        # Run drawing routines directly within the current blocking thread scope
        plt.tight_layout()
        plt.show()
    except Exception as e:
        logging.error(f"❌ Failed to attach interactive UI system loops: {e}")


def get_l7_data() -> dict:
    """
    Return live operational metrics data maps securely for introspection or debug UIs.
    """
    with data_lock:
        return {
            "banner_hits": {k: dict(v) for k, v in l7_data.items()},
            "ja3_map": {k: list(v) for k, v in ja3_map.items()},
            "user_agents": {k
