# src/l7_tracker.py

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

# === In-Memory Stats ===
l7_data = defaultdict(lambda: defaultdict(int))   # {src_ip: {banner_type: count}}
ja3_map = defaultdict(set)                        # {src_ip: set(ja3)}
ua_map = defaultdict(set)                         # {src_ip: set(user-agent)}

# === Plot Setup ===
fig, ax = plt.subplots()


def log_http_banner(src_ip: str, ja3: str, banner_type: str, user_agent: str = None):
    """
    Log per-IP HTTP/JA3/User-Agent correlations.
    """
    try:
        l7_data[src_ip][banner_type] += 1
        if ja3:
            ja3_map[src_ip].add(ja3)
        if user_agent:
            ua_map[src_ip].add(user_agent)
        logging.info(f"📥 L7: {src_ip} | {banner_type} | JA3={ja3} | UA={user_agent}")
    except Exception as e:
        logging.warning(f"⚠️ log_http_banner error: {e}")


def export():
    """
    Export full L7 banner hit map with JA3 and User-Agent metadata to JSON.
    """
    try:
        export_data = {
            "updated": datetime.utcnow().isoformat(),
            "banner_hits": {k: dict(v) for k, v in l7_data.items()},
            "ja3_map": {k: list(v) for k, v in ja3_map.items()},
            "user_agents": {k: list(v) for k, v in ua_map.items()}
        }
        with open(L7_TRACKER_LOG, "w") as f:
            json.dump(export_data, f, indent=2)
        logging.info(f"📤 Exported L7 tracker to: {L7_TRACKER_LOG}")
    except Exception as e:
        logging.warning(f"⚠️ L7 export failed: {e}")


def _update_plot(frame):
    """
    Internal: Update matplotlib chart.
    """
    ax.clear()
    summary = defaultdict(int)
    for ip in l7_data:
        for banner in l7_data[ip]:
            summary[banner] += l7_data[ip][banner]

    if not summary:
        ax.set_title("Live HTTP Banner Stats - Waiting for traffic...")
        return

    labels = list(summary.keys())
    values = [summary[k] for k in labels]

    ax.bar(labels, values)
    ax.set_title("📊 Live HTTP Banner Hits")
    ax.set_ylabel("Hits")
    ax.set_xlabel("Banner Type")
    ax.set_ylim(0, max(values + [1]))
    ax.set_xticklabels(labels, rotation=30, ha='right')


def launch_plot():
    """
    Launch a real-time banner stats chart (non-blocking).
    """
    ani = animation.FuncAnimation(fig, _update_plot, interval=1000)
    threading.Thread(target=plt.show, daemon=True).start()


def get_l7_data() -> dict:
    """
    Return live stats for introspection or debug UI.
    """
    return {
        "banner_hits": {k: dict(v) for k, v in l7_data.items()},
        "ja3_map": {k: list(v) for k, v in ja3_map.items()},
        "user_agents": {k: list(v) for k, v in ua_map.items()}
    }
