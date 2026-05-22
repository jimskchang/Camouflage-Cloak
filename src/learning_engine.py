import json
import logging
import os
from src.settings import LEARNED_FINGERPRINTS_FILE, AUTO_LEARN_MISSING

class FingerprintLearner:
    def __init__(self):
        self.fingerprint_map = {}
        self._is_dirty = False  # Track unsaved in-memory updates to prevent disk thrashing
        self.load_learned_fingerprints()

    def load_learned_fingerprints(self):
        """Loads learned fingerprint maps dynamically from storage."""
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

    def save_learned_fingerprints(self, force=False):
        """
        Saves the learned fingerprint cache to disk.
        Flushes writes only if data changes occur, protecting high-load performance pipelines.
        """
        if not self._is_dirty and not force:
            return

        try:
            with open(LEARNED_FINGERPRINTS_FILE, 'w') as f:
                json.dump(self.fingerprint_map, f, indent=4)
            self._is_dirty = False
            logging.info(f"💾 Saved updated fingerprint map safely to disk storage profiles.")
        except Exception as e:
            logging.error(f"❌ Error saving fingerprints: {e}")

    def match_or_learn(self, hash_digest, packet):
        """
        Matches fingerprints or registers new unique profiles safely 
        without triggering blocking write loops.
        """
        hash_str = hash_digest.hex()

        # 1. Successful Lookup Check
        if hash_str in self.fingerprint_map:
            os_name = self.fingerprint_map[hash_str]
            logging.info(f"✅ Match found: {hash_str[:10]}... is {os_name}")
            return os_name
        
        # 2. Dynamic Fingerprint Registration
        if AUTO_LEARN_MISSING:
            # FIXED: Create distinct, indexed profile keys using hash fragments and targeted ports
            target_port = packet.l4_field.get("dest_port", "unknown")
            short_sig = hash_str[:8]
            new_os_name = f"unknown_learned_p{target_port}_{short_sig}"
            
            self.fingerprint_map[hash_str] = new_os_name
            self._is_dirty = True  # Mark cache as modified without blocking execution paths
            
            logging.info(f"🆕 Registered unique tracking profile: {hash_str[:10]}... as {new_os_name}")
            return new_os_name
            
        return None
