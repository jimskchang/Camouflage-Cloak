import json
import logging
import os
from src.settings import LEARNED_FINGERPRINTS_FILE, AUTO_LEARN_MISSING

class FingerprintLearner:
    def __init__(self):
        self.fingerprint_map = {}
        self.load_learned_fingerprints()

    def load_learned_fingerprints(self):
        """從檔案載入已學習的指紋映射"""
        if os.path.exists(LEARNED_FINGERPRINTS_FILE):
            try:
                with open(LEARNED_FINGERPRINTS_FILE, 'r') as f:
                    self.fingerprint_map = json.load(f)
                logging.info(f"📚 Loaded {len(self.fingerprint_map)} learned fingerprints.")
            except Exception as e:
                logging.error(f"❌ Error loading fingerprints: {e}")
                self.fingerprint_map = {}
        else:
            self.fingerprint_map = {}

    def save_learned_fingerprints(self):
        """將學習到的指紋保存到檔案"""
        try:
            with open(LEARNED_FINGERPRINTS_FILE, 'w') as f:
                json.dump(self.fingerprint_map, f, indent=4)
            logging.info(f"💾 Saved updated fingerprint map.")
        except Exception as e:
            logging.error(f"❌ Error saving fingerprints: {e}")

    def match_or_learn(self, hash_digest, packet):
        """
        匹配指紋，如果未找到且 AUTO_LEARN_MISSING 為真，則學習新指紋
        """
        hash_str = hash_digest.hex() # 將 bytes 轉為字串以便存入 JSON

        if hash_str in self.fingerprint_map:
            os_name = self.fingerprint_map[hash_str]
            logging.info(f"✅ Match found: {hash_str[:10]}... is {os_name}")
            return os_name
        
        if AUTO_LEARN_MISSING:
            # 💡 標記為待識別的未知 OS
            new_os_name = "unknown_learned" 
            self.fingerprint_map[hash_str] = new_os_name
            self.save_learned_fingerprints()
            logging.info(f"🆕 Learned new fingerprint: {hash_str[:10]}... as {new_os_name}")
            return new_os_name
            
        return None
