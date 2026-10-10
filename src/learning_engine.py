"""Fingerprint learning engine with multiprocessing-safe state management.

Refactored to accept a multiprocessing.Lock() for synchronized access to shared fingerprint map.
"""

import json
import logging
import os

try:
    import fcntl
except ImportError:
    fcntl = None

from src.settings import LEARNED_FINGERPRINTS_FILE, AUTO_LEARN_MISSING


class FingerprintLearner:
    """Fingerprint learner with multiprocessing support.
    
    Accepts an optional multiprocessing.Manager().dict() proxy to share state across processes.
    Also accepts a corresponding lock for synchronized access.
    """

    def __init__(self, shared_map_proxy=None, shared_lock=None):
        """Initialize learner with optional shared state.
        
        Args:
            shared_map_proxy: multiprocessing.Manager().dict() proxy (optional)
            shared_lock: multiprocessing.Manager().Lock() for synchronization (optional)
        """
        self._is_dirty = False
        self.shared_lock = shared_lock
        
        if shared_map_proxy is not None:
            self.fingerprint_map = shared_map_proxy
            # If proxy is freshly initialized and empty, read from disk
            if len(self.fingerprint_map) == 0 and os.path.exists(LEARNED_FINGERPRINTS_FILE):
                self.load_learned_fingerprints()
        else:
            self.fingerprint_map = {}
            self.load_learned_fingerprints()

    def load_learned_fingerprints(self):
        """Load learned fingerprints from disk with defensive locking."""
        if os.path.exists(LEARNED_FINGERPRINTS_FILE):
            try:
                with open(LEARNED_FINGERPRINTS_FILE, 'r') as f:
                    if fcntl:
                        fcntl.flock(f, fcntl.LOCK_SH)
                    try:
                        data = json.load(f)
                        for k, v in data.items():
                            self.fingerprint_map[k] = v
                        logging.info(
                            f"📚 Loaded {len(self.fingerprint_map)} learned fingerprints from disk"
                        )
                    finally:
                        if fcntl:
                            fcntl.flock(f, fcntl.LOCK_UN)
            except Exception as e:
                logging.error(f"❌ Error loading fingerprints: {e}")

    def save_learned_fingerprints(self, force=False):
        """Save fingerprint map to disk with lock protection.
        
        Args:
            force: Force save even if not dirty (optional)
        """
        if not self._is_dirty and not force:
            return
        try:
            # Convert proxy to native dict for serialization
            native_data = dict(self.fingerprint_map)
            with open(LEARNED_FINGERPRINTS_FILE, 'w') as f:
                if fcntl:
                    fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    json.dump(native_data, f, indent=4)
                finally:
                    if fcntl:
                        fcntl.flock(f, fcntl.LOCK_UN)
            self._is_dirty = False
            logging.info("💾 Saved updated fingerprint map to disk")
        except Exception as e:
            logging.error(f"❌ Error saving fingerprints: {e}")

    def match_or_learn(self, hash_digest, packet):
        """Match fingerprints or register unique profiles safely.
        
        Uses shared lock when available to ensure thread-safe access across processes.
        
        Args:
            hash_digest: Hash bytes or string to match
            packet: Packet object for learning context
        
        Returns:
            str: Matched or learned OS name
        """
        hash_str = hash_digest.hex() if isinstance(hash_digest, bytes) else str(hash_digest)
        
        # === Use shared lock if available ===
        if self.shared_lock:
            with self.shared_lock:
                if hash_str in self.fingerprint_map:
                    return self.fingerprint_map[hash_str]
        else:
            if hash_str in self.fingerprint_map:
                return self.fingerprint_map[hash_str]
        
        # Not found - try to learn if enabled
        if AUTO_LEARN_MISSING:
            target_port = (
                packet.l4_field.get("dest_port", "unknown") 
                if hasattr(packet, 'l4_field') 
                else "unknown"
            )
            short_sig = hash_str[:8]
            new_os_name = f"unknown_learned_p{target_port}_{short_sig}"
            
            # === Use shared lock for write ===
            if self.shared_lock:
                with self.shared_lock:
                    self.fingerprint_map[hash_str] = new_os_name
            else:
                self.fingerprint_map[hash_str] = new_os_name
            
            self._is_dirty = True
            logging.info(
                f"🆕 Registered unique profile: {hash_str[:10]}... → {new_os_name}"
            )
            return new_os_name
        
        return "generic_linux"
