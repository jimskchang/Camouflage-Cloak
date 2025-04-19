# src/l7_tracker.py

import os
import json
import logging
from collections import defaultdict
from datetime import datetime

L7_TRACKER_LOG = os.path.join(os.path.dirname(__file__), "..", "os_record", "l7_http_log.json")
banner_hits = defaultdict(lambda: defaultdict(int))  # {src_ip: {banner_type: count}}

def log_http_banner(src_ip: str, ja3: str, banner_type: str):
    try:
        banner_hits[src_ip][banner_type] += 1
        logging.info(f"📥 L7 Banner tracked: {src_ip} → {banner_type}")
    except Exception as e:
        logging.warning(f"⚠️ log_http_banner error: {e}")

def export():
    try:
        with open(L7_TRACKER_LOG, "w") as f:
            json.dump({
                "updated": datetime.utcnow().isoformat(),
                "banner_hits": banner_hits
            }, f, indent=2)
        logging.info(f"📤 Exported L7 banner log: {L7_TRACKER_LOG}")
    except Exception as e:
        logging.warning(f"⚠️ Failed to export L7 log: {e}")
