# src/log_manager.py

import json
import csv
import logging
import os
import time
from datetime import datetime
from src.settings import LEARNED_FINGERPRINTS_FILE, OS_RECORD_PATH

# 結構化日誌輸出目錄
STRUCTURED_LOG_DIR = os.path.join(OS_RECORD_PATH, "structured_logs")
os.makedirs(STRUCTURED_LOG_DIR, exist_ok=True)

def dump_fingerprints_to_csv():
    """
    將 learned_fingerprints.json 轉化為 CSV 並保存到結構化日誌目錄中
    """
    try:
        if not os.path.exists(LEARNED_FINGERPRINTS_FILE):
            logging.warning("⚠️ Learned fingerprints file not found, skipping dump.")
            return

        # 讀取當前學習到的指紋
        with open(LEARNED_FINGERPRINTS_FILE, 'r') as f:
            fingerprints = json.load(f)
        
        if not fingerprints:
            logging.info("ℹ️ No fingerprints to dump.")
            return

        # 生成結構化日誌檔名 (例如: fingerprints_2026-02-27_17-57.csv)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
        csv_filename = os.path.join(STRUCTURED_LOG_DIR, f"fingerprints_{timestamp}.csv")

        # 寫入 CSV
        with open(csv_filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["fingerprint_hash", "resolved_os"]) # CSV Header
            for hash_val, os_name in fingerprints.items():
                writer.writerow([hash_val, os_name])

        logging.info(f"💾 Structured log dumped: {csv_filename}")
        
    except Exception as e:
        logging.error(f"❌ Failed to dump fingerprints to CSV: {e}")

if __name__ == "__main__":
    # 允許直接運行此腳本進行測試
    logging.basicConfig(level=logging.INFO)
    dump_fingerprints_to_csv()
