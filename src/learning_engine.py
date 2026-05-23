import json
import logging
import os
try:
    import fcntl
except ImportError:
    fcntl = None

from src.settings import LEARNED_FINGERPRINTS_FILE, AUTO_LEARN_MISSING

class FingerprintLearner:
    def __init__(self, shared_map_proxy=None):
        """
        Hardened learning engine backing store.
        Accepts an optional multiprocessing.Manager().dict() proxy to share states across processes.
        """
        self._is_dirty = False
        if shared_map_proxy is not None:
            self.fingerprint_map = shared_map_proxy
            # If the proxy is freshly initialized and empty, read what exists on disk
            if len(self.fingerprint_map) == 0 and os.path.exists(LEARNED_FINGERPRINTS_FILE):
                self.load_learned_fingerprints()
        else:
            self.fingerprint_map = {}
            self.load_learned_fingerprints()

    def load_learned_fingerprints(self):
        """Loads learned fingerprint maps dynamically with defensive advisory locking."""
        if os.path.exists(LEARNED_FINGERPRINTS_FILE):
            try:
                with open(LEARNED_FINGERPRINTS_FILE, 'r') as f:
                    if fcntl:
                        fcntl.flock(f, fcntl.LOCK_SH)
                    data = json.load(f)
                    for k, v in data.items():
                        self.fingerprint_map[k] = v
                logging.info(f" 📚 Loaded {len(self.fingerprint_map)} learned fingerprints from disk safely.")
            except Exception as e:
                logging.error(f" ❌ Error loading fingerprints from storage vector: {e}")

    def save_learned_fingerprints(self, force=False):
        """Saves the process proxy state cache cleanly to disk without race-condition data loss."""
        if not self._is_dirty and not force:
            return
        try:
            # Convert proxy format back to a standard flat dictionary representation for serialization
            native_data = dict(self.fingerprint_map)
            with open(LEARNED_FINGERPRINTS_FILE, 'w') as f:
                if fcntl:
                    fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(native_data, f, indent=4)
                if fcntl:
                    fcntl.flock(f, fcntl.LOCK_UN)
            self._is_dirty = False
            logging.info(" 💾 Saved updated fingerprint map safely to shared storage profiles.")
        except Exception as e:
            logging.error(f" ❌ Error persisting updated fingerprints cache to disk: {e}")

    def match_or_learn(self, hash_digest, packet):
        """Matches fingerprints or registers unique profiles safely without blocking worker threads."""
        hash_str = hash_digest.hex() if isinstance(hash_digest, bytes) else str(hash_digest)
        
        if hash_str in self.fingerprint_map:
            return self.fingerprint_map[hash_str]
        
        if AUTO_LEARN_MISSING:
            target_port = packet.l4_field.get("dest_port", "unknown") if hasattr(packet, 'l4_field') else "unknown"
            short_sig = hash_str[:8]
            new_os_name = f"unknown_learned_p{target_port}_{short_sig}"
            
            self.fingerprint_map[hash_str] = new_os_name
            self._is_dirty = True
            
            logging.info(f"🆕 Registered unique tracking profile process-wide: {hash_str[:10]}... → {new_os_name}")
            return new_os_name
        
        return "generic_linux"
