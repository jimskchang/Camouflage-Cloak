# src/l7_tracker.py

import os
import json
import logging
import threading
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.animation as animation

# Path to export L7 HTTP log
L7_TRACKER_LOG = os.path.join(os.path.dirname(__file__), "..", "os_record", "l7_http_log.json")

# In-memory tracker structure: {src_ip: {banner_type: count, 'ja3': [hashes], 'ua': [strings]}}
l7_data = defaultdict(lambda: defaultdict(int))
ja3_map = defaultdict(list)
ua_map = defaultdict(list)

# Real-time plot
fig, ax = plt.subplots()


def log_http_banner(src_ip: str, ja3: str, banner_type: str, user_agent: str = None):
    try:
        l7_data[src_ip][banner_type] += 1
        if ja3:
            if ja3 not in ja3_map[src_ip]:
                ja3_map[src_ip].append(ja3)
        if user_agent:
            if user_agent not in ua_map[src_ip]:
                ua_map[src_ip].append(user_agent)
        logging.info(f"📥 Logged banner: {src_ip} → {banner_type} | JA3={ja3} | UA={user_agent}")
    except Exception as e:
        logging.warning(f"⚠️ log_http_banner error: {e}")


def export():
    try:
        with open(L7_TRACKER_LOG, "w") as f:
            json.dump({
                "updated": datetime.utcnow().isoformat(),
                "banner_hits": l7_data,
                "ja3_map": ja3_map,
                "user_agents": ua_map
            }, f, indent=2)
        logging.info(f"📤 Exported L7 tracker to: {L7_TRACKER_LOG}")
    except Exception as e:
        logging.warning(f"⚠️ Failed to export L7 data: {e}")


def _update_plot(frame):
    ax.clear()
    summary = defaultdict(int)
    for ip in l7_data:
        for banner in l7_data[ip]:
            summary[banner] += l7_data[ip][banner]

    if not summary:
        ax.set_title("No L7 Traffic Yet")
        return

    labels = list(summary.keys())
    values = [summary[k] for k in labels]

    ax.bar(labels, values)
    ax.set_title("Live HTTP Banner Stats")
    ax.set_ylabel("Hits")
    ax.set_xlabel("Banner Type")
    ax.set_ylim(0, max(values + [1]))
    ax.set_xticklabels(labels, rotation=45, ha='right')


def launch_plot():
    ani = animation.FuncAnimation(fig, _update_plot, interval=1000)
    threading.Thread(target=plt.show, daemon=True).start()
