import json
import csv
import logging
import os
from datetime import datetime
from src.settings import LEARNED_FINGERPRINTS_FILE, OS_RECORD_PATH

# Try importing standard Unix process lock constraints; fallback to safe pass modes if non-POSIX
try:
    import fcntl
except ImportError:
    fcntl = None

# Structured log export directory configuration
STRUCTURED_LOG_DIR = os.path.join(OS_RECORD_PATH, "structured_logs")
os.makedirs(STRUCTURED_LOG_DIR, exist_ok=True)

def dump_fingerprints_to_csv():
    """
    Translates learned_fingerprints.json into an analytics-ready CSV format.
    Features process-safe file locks and dynamically flattens nested metadata.
    """
    try:
        if not os.path.exists(LEARNED_FINGERPRINTS_FILE):
            logging.warning("⚠️ Learned fingerprints source file not found; skipping export task.")
            return

        fingerprints = {}
        
        # FIXED: Implement shared advisory process locks to protect against concurrent write crashes
        with open(LEARNED_FINGERPRINTS_FILE, 'r') as f:
            if fcntl:
                try:
                    fcntl.flock(f, fcntl.LOCK_SH)  # Establish shared read lock
                except IOError:
                    logging.warning("⚠️ File locked by another worker process; waiting...")
                    
            try:
                fingerprints = json.load(f)
            finally:
                if fcntl:
                    fcntl.flock(f, fcntl.LOCK_UN)  # Explicit release signature

        if not fingerprints:
            logging.info("ℹ️ Fingerprints data registry empty; skipping export.")
            return

        # Generate a structured time-series timestamp filename 
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        csv_filename = os.path.join(STRUCTURED_LOG_DIR, f"fingerprints_{timestamp}.csv")

        # FIXED: Flatten nested metadata configurations dynamically during loop iterations
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Expanded CSV Schema Header to account for deep protocol metrics tracking
            writer.writerow(["fingerprint_hash", "resolved_os", "hit_count", "last_seen_timestamp"])
            
            for hash_val, details in fingerprints.items():
                if isinstance(details, dict):
                    # Gracefully pull nested parameters out of structured profiling objects
                    os_name = details.get("resolved_os", "UNKNOWN")
                    hit_count = details.get("hit_count", 1)
                    last_seen = details.get("last_seen", datetime.now().isoformat())
                    writer.writerow([hash_val, os_name, hit_count, last_seen])
                else:
                    # Fallback string routing logic for backwards compatibility with raw flat schemas
                    writer.writerow([hash_val, str(details), "1", "N/A"])

        logging.info(f"💾 Process-safe structured log dumped successfully: {csv_filename}")
        
    except json.JSONDecodeError as jde:
        logging.error(f"❌ Failed to extract json frames due to transient dirty read states: {jde}")
    except Exception as e:
        logging.error(f"❌ Failed to parse fingerprints conversion pipeline: {e}")

if __name__ == "__main__":
    # Facilitate direct execution tracking capabilities for debugging or cron tasks
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    dump_fingerprints_to_csv()
