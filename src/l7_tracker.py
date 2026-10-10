import os
import json
import logging
import threading
import multiprocessing
from collections import defaultdict
from datetime import datetime
from typing import Optional

import matplotlib.pyplot as plt
import matplotlib.animation as animation

# === Export Path ===
L7_TRACKER_LOG = os.path.join(os.path.dirname(__file__), "..", "os_record", "l7_http_log.json")

# === Thread/Process Synchronization Lock ===
# NOTE: If using multiprocessing, this MUST be replaced with multiprocessing.Lock()
# by the coordinator that initializes the Manager proxies.
data_lock: Optional[threading.Lock] = threading.Lock()

# === Shared Stats Store ===
# Will be replaced with multiprocessing.Manager().dict() proxies in multiprocessing mode
l7_data = defaultdict(lambda: defaultdict(int))   
ja3_map = defaultdict(set)                        
ua_map = defaultdict(set)                         

_ani_anchor = None


def _set_multiprocessing_lock(mp_lock):
    """
    Call this from the multiprocessing coordinator to swap the lock.
    Must be called BEFORE any worker processes start.
    """
    global data_lock
    data_lock = mp_lock


def _ensure_set(store, key):
    """
    Safely ensure a key exists in the store and contains a set.
    Works with both regular dicts and multiprocessing.Manager().dict() proxies.
    """
    if key not in store:
        store[key] = set()
    return store[key]


def log_http_banner(src_ip: str, ja3: str, banner_type: str, user_agent: str = None):
    """
    Log per-IP HTTP/JA3/User-Agent correlations securely using mutex synchronization.
    """
    try:
        with data_lock:
            l7_data[src_ip][banner_type] += 1
            
            if ja3:
                target = _ensure_set(ja3_map, src_ip)
                target.add(ja3)
            
            if user_agent:
                target = _ensure_set(ua_map, src_ip)
                target.add(user_agent)
        
        logging.info(f"📥 L7 Traffic Profiled: {src_ip} | Banner: {banner_type} | JA3={ja3}")
        
        # Call export() OUTSIDE the lock to avoid nested locking
        export()
    except Exception as e:
        logging.warning(f"⚠️ log_http_banner state update error: {e}")


def export():
    """
    Export full L7 banner hit map with JA3 and User-Agent metadata to JSON safely.
    """
    try:
        with data_lock:
            # Snapshot the data while locked
            export_data = {
                "updated": datetime.utcnow().isoformat(),
                "banner_hits": {k: dict(v) for k, v in l7_data.items()},
                "ja3_map": {k: sorted(v) for k, v in ja3_map.items()},
                "user_agents": {k: sorted(v) for k, v in ua_map.items()}
            }
        
        # File I/O happens OUTSIDE the lock
        log_dir = os.path.dirname(L7_TRACKER_LOG)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(L7_TRACKER_LOG, "w") as f:
            json.dump(export_data, f, indent=2)
    except Exception as e:
        logging.warning(f"⚠️ L7 background JSON export failed: {e}")


def _update_plot(frame, ax):
    """
    Internal: Safely extracts a point-in-time snapshot to update the UI components.
    """
    try:
        with data_lock:
            current_hits = {k: dict(v) for k, v in l7_data.items()}
        
        # All matplotlib operations happen OUTSIDE the lock
        ax.clear()
        summary = defaultdict(int)
        for ip, banners in current_hits.items():
            for banner, count in banners.items():
                summary[banner] += count

        if not summary:
            ax.set_title("Live HTTP Banner Stats - Waiting for active probes...", fontsize=11, pad=10)
            ax.set_ylabel("Hits")
            ax.set_xlabel("Banner Type")
            return

        labels = list(summary.keys())
        values = [summary[k] for k in labels]
        x_positions = list(range(len(labels)))

        ax.bar(x_positions, values, color="#2c3e50", edgecolor="#34495e")
        ax.set_xticks(x_positions)
        ax.set_xticklabels(labels, rotation=25, ha='right', fontsize=9)
        ax.set_title("📊 Live Deception Engine HTTP Banner Hits", fontsize=12, fontweight='bold', pad=12)
        ax.set_ylabel("Total Captured Hits", fontsize=10)
        ax.set_xlabel("Target Server Emulation Profile", fontsize=10)
        ax.set_ylim(0, max(values) + max(1, int(max(values) * 0.15)))
        ax.grid(axis='y', linestyle='--', alpha=0.5)
        
    except Exception as e:
        logging.error(f"⚠️ Error occurred inside frame rendering loop: {e}")


def launch_plot():
    """
    Launches the real-time banner stats engine visualization interface.
    CRITICAL: This must be invoked directly inside the main parent process thread loop.
    """
    global _ani_anchor
    try:
        logging.info("🎨 Constructing interactive metric dashboard elements...")
        fig, ax = plt.subplots(figsize=(8, 5))
        
        _ani_anchor = animation.FuncAnimation(
            fig, _update_plot, fargs=(ax,), interval=1000, cache_frame_data=False
        )
        
        plt.tight_layout()
        plt.show()
    except Exception as e:
        logging.error(f"❌ Failed to attach interactive UI environment loop: {e}")


def get_l7_data() -> dict:
    """
    Return clean serialized states for introspection or debug API layers.
    """
    with data_lock:
        return {
            "banner_hits": {k: dict(v) for k, v in l7_data.items()},
            "ja3_map": {k: sorted(v) for k, v in ja3_map.items()},
            "user_agents": {k: sorted(v) for k, v in ua_map.items()}
        }
