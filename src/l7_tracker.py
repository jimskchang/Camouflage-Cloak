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

# === Thread/Process Synchronization Lock ===
data_lock = threading.Lock()

# === Shared Stats Store ===
# Note: When spawned via the multiprocessing coordinator, these will be replaced 
# with multiprocessing.Manager().dict() proxies to bridge the process memory silos.
l7_data = defaultdict(lambda: defaultdict(int))   # {src_ip: {banner_type: count}}
ja3_map = defaultdict(set)                        # {src_ip: set(ja3)}
ua_map = defaultdict(set)                         # {src_ip: set(user-agent)}

# Retain global animation anchor to prevent garbage collection sweeps
_ani_anchor = None


def log_http_banner(src_ip: str, ja3: str, banner_type: str, user_agent: str = None):
    """
    Log per-IP HTTP/JA3/User-Agent correlations securely using mutex synchronization.
    Called by sniffing threads or background worker states.
    """
    try:
        with data_lock:
            l7_data[src_ip][banner_type] += 1
            if ja3:
                # Handle both managed lists and native sets gracefully
                if isinstance(ja3_map[src_ip], set):
                    ja3_map[src_ip].add(ja3)
                else:
                    if ja3 not in ja3_map[src_ip]:
                        ja3_map[src_ip].append(ja3)
            if user_agent:
                if isinstance(ua_map[src_ip], set):
                    ua_map[src_ip].add(user_agent)
                else:
                    if user_agent not in ua_map[src_ip]:
                        ua_map[src_ip].append(user_agent)
                        
        logging.info(f"📥 L7 Traffic Profiled: {src_ip} | Banner: {banner_type} | JA3={ja3}")
        
        # Non-blocking async persistence flush
        export()
    except Exception as e:
        logging.warning(f"⚠️ log_http_banner state update error: {e}")


def export():
    """
    Export full L7 banner hit map with JA3 and User-Agent metadata to JSON safely.
    Handles cross-process/cross-thread conversion mutations automatically.
    """
    try:
        with data_lock:
            export_data = {
                "updated": datetime.utcnow().isoformat(),
                "banner_hits": {k: dict(v) for k, v in l7_data.items()},
                "ja3_map": {k: list(v) for k, v in ja3_map.items()},
                "user_agents": {k: list(v) for k, v in ua_map.items()}
            }
        
        os.makedirs(os.path.dirname(L7_TRACKER_LOG), exist_ok=True)
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
            # Create a localized deep-copy reference to avoid concurrent modification crashes
            current_hits = {k: dict(v) for k, v in l7_data.items()}

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

        # Render clean categorical bar graph plots
        ax.bar(x_positions, values, color="#2c3e50", edgecolor="#34495e")
        
        # FIXED: Explicitly set ticks before mapping text labels to satisfy modern Matplotlib APIs
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
        
        # Pass the ax context object explicitly into the functional frame engine updates
        _ani_anchor = animation.FuncAnimation(fig, _update_plot, fargs=(ax,), interval=1000, cache_frame_data=False)
        
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
            "ja3_map": {k: list(v) for k, v in ja3_map.items()},
            "user_agents": {k: list(v) for k, v in ua_map.items()}
        }
