# src/l7_tracker.py

import os
import json
import logging
import threading
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.animation as animation

# ============================
# Configuration
# ============================
L7_TRACKER_LOG = os.path.join(os.path.dirname(__file__), "..", "os_record", "l7_http_log.json")

# ============================
# Tracker Class
# ============================
class L7Tracker:
    def __init__(self):
        self.l7_data = defaultdict(lambda: defaultdict(int))
        self.ja3_map = defaultdict(list)
        self.ua_map = defaultdict(list)
        self.lock = threading.Lock()

        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 8))
        self.ani = animation.FuncAnimation(self.fig, self._update_plot, interval=1000)
        threading.Thread(target=plt.show, daemon=True).start()

    def log_http_banner(self, src_ip: str, ja3: str, banner_type: str, user_agent: str = None):
        try:
            with self.lock:
                self.l7_data[src_ip][banner_type] += 1
                if ja3 and ja3 not in self.ja3_map[src_ip]:
                    self.ja3_map[src_ip].append(ja3)
                if user_agent and user_agent not in self.ua_map[src_ip]:
                    self.ua_map[src_ip].append(user_agent)
                logging.info(f"📅 Logged banner: {src_ip} → {banner_type} | JA3={ja3} | UA={user_agent}")
        except Exception as e:
            logging.warning(f"⚠️ log_http_banner error: {e}")

    def export(self):
        try:
            with self.lock:
                export_data = {
                    "updated": datetime.utcnow().isoformat(),
                    "banner_hits": self.l7_data,
                    "ja3_map": self.ja3_map,
                    "user_agents": self.ua_map
                }
                with open(L7_TRACKER_LOG, "w") as f:
                    json.dump(export_data, f, indent=2)
                logging.info(f"📤 Exported L7 tracker to: {L7_TRACKER_LOG}")
        except Exception as e:
            logging.warning(f"⚠️ Failed to export L7 data: {e}")

    def _update_plot(self, frame):
        with self.lock:
            # --- Plot 1: Banner Hits ---
            self.ax1.clear()
            banner_summary = defaultdict(int)
            for ip in self.l7_data:
                for banner in self.l7_data[ip]:
                    banner_summary[banner] += self.l7_data[ip][banner]

            if banner_summary:
                labels = list(banner_summary.keys())
                values = [banner_summary[k] for k in labels]
                self.ax1.bar(labels, values)
                self.ax1.set_title("🌐 Live HTTP Banner Stats")
                self.ax1.set_ylabel("Hits")
                self.ax1.set_xticklabels(labels, rotation=45, ha='right')
            else:
                self.ax1.set_title("(no HTTP banners yet)")

            # --- Plot 2: Unique JA3 + UA combos per IP ---
            self.ax2.clear()
            labels = []
            values = []
            for ip in sorted(set(list(self.ja3_map.keys()) + list(self.ua_map.keys()))):
                ja3_count = len(self.ja3_map.get(ip, []))
                ua_count = len(self.ua_map.get(ip, []))
                label = f"{ip}\nJA3:{ja3_count}/UA:{ua_count}"
                labels.append(label)
                values.append(ja3_count + ua_count)

            if labels:
                self.ax2.bar(labels, values)
                self.ax2.set_title("🔍 Unique JA3 + UA per IP")
                self.ax2.set_ylabel("Distinct Values")
                self.ax2.set_xticklabels(labels, rotation=30, ha='right')
            else:
                self.ax2.set_title("(no JA3/UA logged yet)")

# ============================
# Singleton Export
# ============================
l7_tracker = L7Tracker()
