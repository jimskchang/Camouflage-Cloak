import json
import logging
import os
import threading
from collections import defaultdict
from datetime import datetime
from typing import Optional

import matplotlib.animation as animation
import matplotlib.pyplot as plt

# === Export Path ===
L7_TRACKER_LOG = os.path.join(os.path.dirname(__file__), "..", "os_record", "l7_http_log.json")

# === Thread/Process Synchronization Lock ===
# Use a re-entrant lock so nested snapshots and exports do not deadlock.
data_lock: Optional[threading.RLock] = threading.RLock()

# === Shared Stats Store ===
# These are process-local by default; a parent coordinator can replace them with Manager proxy objects
# before workers start if multiprocessing sharing is required.
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


def _snapshot():
    """Return a consistent snapshot of the current L7 state."""
    with data_lock:
        return {
            "updated": datetime.utcnow().isoformat(),
            "banner_hits": {k: dict(v) for k, v in l7_data.items()},
            "ja3_map": {k: sorted(v) for k, v in ja3_map.items()},
            "user_agents": {k: sorted(v) for k, v in ua_map.items()},
        }


def export_snapshot(snapshot=None):
    """Write a serialized snapshot to disk without holding the lock during I/O."""
    if snapshot is None:
        snapshot = _snapshot()

    log_dir = os.path.dirname(L7_TRACKER_LOG)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    with open(L7_TRACKER_LOG, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2)


def log_http_banner(src_ip: str, ja3: str, banner_type: str, user_agent: str = None):
    """
    Log per-IP HTTP/JA3/User-Agent correlations securely using mutex synchronization.
    """
    try:
        with data_lock:
            l7_data[src_ip][banner_type] += 1

            if ja3:
                _ensure_set(ja3_map, src_ip).add(ja3)

            if user_agent:
                _ensure_set(ua_map, src_ip).add(user_agent)

            snapshot = _snapshot()

        export_snapshot(snapshot)
        logging.info("📥 L7 Traffic Profiled: %s | Banner: %s | JA3=%s", src_ip, banner_type, ja3)
    except Exception as exc:
        logging.warning("⚠️ log_http_banner state update error: %s", exc)


def export():
    """
    Export full L7 banner hit map with JA3 and User-Agent metadata to JSON safely.
    """
    try:
        export_snapshot(_snapshot())
    except Exception as exc:
        logging.warning("⚠️ L7 background JSON export failed: %s", exc)


def _update_plot(frame, ax):
    """
    Internal: Safely extracts a point-in-time snapshot to update the UI components.
    """
    try:
        current_hits = _snapshot()["banner_hits"]

        ax.clear()
        summary = defaultdict(int)
        for _, banners in current_hits.items():
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
        ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=9)
        ax.set_title("📊 Live Deception Engine HTTP Banner Hits", fontsize=12, fontweight="bold", pad=12)
        ax.set_ylabel("Total Captured Hits", fontsize=10)
        ax.set_xlabel("Target Server Emulation Profile", fontsize=10)
        ax.set_ylim(0, max(values) + max(1, int(max(values) * 0.15)))
        ax.grid(axis="y", linestyle="--", alpha=0.5)

    except Exception as exc:
        logging.error("⚠️ Error occurred inside frame rendering loop: %s", exc)


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
    except Exception as exc:
        logging.error("❌ Failed to attach interactive UI environment loop: %s", exc)


def get_l7_data() -> dict:
    """
    Return clean serialized states for introspection or debug API layers.
    """
    with data_lock:
        return {
            "banner_hits": {k: dict(v) for k, v in l7_data.items()},
            "ja3_map": {k: sorted(v) for k, v in ja3_map.items()},
            "user_agents": {k: sorted(v) for k, v in ua_map.items()},
        }


class L7Tracker:
    """Thin compatibility wrapper used by the main runtime."""

    def __init__(self, shared_state=None):
        self.shared_state = shared_state

    def log_http_banner(self, src_ip: str, ja3: str, banner_type: str, user_agent: str = None):
        return log_http_banner(src_ip, ja3, banner_type, user_agent)

    def export(self):
        return export()

    def launch_plot(self):
        return launch_plot()

    def get_l7_data(self):
        return get_l7_data()


__all__ = [
    "L7Tracker",
    "log_http_banner",
    "export",
    "launch_plot",
    "get_l7_data",
    "_set_multiprocessing_lock",
]

