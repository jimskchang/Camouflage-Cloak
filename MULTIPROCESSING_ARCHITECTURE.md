# Multiprocessing Architecture: Full Re-Architecture

## Design Principles

1. **Unified Ownership**: All shared state is created and owned by the main process via a single `SharedStateManager` factory.
2. **Explicit Proxies**: Workers receive only what they need; no implicit globals or module-level mutation.
3. **Deterministic Initialization**: Manager proxies and locks are created before any worker is spawned.
4. **Clear Boundaries**: Worker code does not call UI code, does not create new locks, does not lazy-initialize global state.
5. **Read-Write Separation**: Some state (e.g., config) is read-only; others (e.g., l7_data) are write-protected by locks.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│ MAIN PROCESS                                                    │
│                                                                 │
│  1. Initialize SharedStateManager                              │
│     ├─ Create Manager() once                                   │
│     ├─ Create all manager dicts & locks                        │
│     └─ Return SharedState bundle                               │
│                                                                 │
│  2. Spawn workers with SharedState                             │
│     └─ Workers NEVER create new Manager() instances            │
│                                                                 │
│  3. UI Thread (Main Process Only)                              │
│     ├─ launch_plot() reads shared state with lock              │
│     └─ Never called by workers                                 │
│                                                                 │
│  4. Cleanup & Export                                           │
│     └─ Called only in main process at teardown                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ WORKER PROCESS (1..N)                                           │
│                                                                 │
│  • Accepts SharedState bundle (read-only container object)     │
│  • Uses locks from bundle to access shared state               │
│  • Never creates new locks or Manager() proxies                │
│  • Never calls UI code (launch_plot, matplotlib, etc.)         │
│  • Reads config from shared_state.config (immutable)           │
│  • Appends to shared_state.l7_tracker, ja3_log with lock       │
└─────────────────────────────────────────────────────────────────┘
```

---

## File: `src/shared_state.py` (NEW)

A single source of truth for all multiprocessing infrastructure.

```python
import os
import logging
from multiprocessing import Manager, Lock as MPLock
from datetime import datetime

class SharedState:
    """
    Immutable container for all cross-process state and synchronization primitives.
    Created once in main process; passed to all workers.
    """
    def __init__(self, manager):
        # Config (read-only, never modified)
        self.config = {
            "scan_mode": None,
            "nic": None,
            "host": None,
            "dest": None,
            "enable_gui": True,
        }
        
        # === L7 Tracker State (write-protected) ===
        self.l7_data = manager.dict()           # {src_ip: {banner_type: count}}
        self.ja3_map = manager.dict()           # {src_ip: [ja3_hash1, ja3_hash2, ...]}
        self.ua_map = manager.dict()            # {src_ip: [ua1, ua2, ...]}
        self.l7_lock = manager.Lock()           # Guards above three
        
        # === JA3 Log State (write-protected) ===
        self.ja3_log = manager.dict()           # {src_ip: [ja3_hash, ...]}
        self.ja3_lock = manager.Lock()          # Guards ja3_log
        
        # === Fingerprint Learner State (write-protected) ===
        self.fingerprint_map = manager.dict()   # {hash_hex: learned_os_name}
        self.fingerprint_lock = manager.Lock()  # Guards fingerprint_map
        
        # === Stats & Monitoring ===
        self.packet_count = manager.Value('i', 0)  # Total packets processed
        self.error_count = manager.Value('i', 0)   # Total errors
        
    def update_config(self, **kwargs):
        """Main process only: set configuration before spawning workers."""
        for k, v in kwargs.items():
            if k in self.config:
                self.config[k] = v
    
    def to_dict(self):
        """Return a snapshot of current state (for debugging/export)."""
        with self.l7_lock:
            return {
                "config": dict(self.config),
                "l7_data": dict(self.l7_data),
                "ja3_map": {k: list(v) for k, v in self.ja3_map.items()},
                "ua_map": {k: list(v) for k, v in self.ua_map.items()},
                "ja3_log": {k: list(v) for k, v in self.ja3_log.items()},
                "packet_count": self.packet_count.value,
                "error_count": self.error_count.value,
            }

class SharedStateFactory:
    """Factory for creating and managing the SharedState singleton."""
    
    @staticmethod
    def create():
        """
        Create SharedState with a fresh Manager.
        Call ONCE in main process BEFORE spawning workers.
        """
        manager = Manager()
        state = SharedState(manager)
        logging.info("✅ SharedStateFactory: Initialized multiprocessing state manager")
        return state
```

---

## Module Changes Summary

### `main.py`
- **Remove**: All `manager.dict()` creation
- **Add**: `SharedStateFactory.create()` call
- **Pass**: `shared_state` object to `packet_worker()`
- **Remove**: GUI code from worker context (already done, keep it)

### `src/l7_tracker.py`
- **Change**: Accept `shared_state` as parameter instead of module globals
- **Remove**: `_set_multiprocessing_lock()` hack
- **Remove**: Module-level `l7_data`, `ja3_map`, `ua_map`, `data_lock`
- **Add**: All functions take `shared_state` as first parameter

### `src/os_recorder.py`
- **Change**: Accept `shared_state` instead of separate `ja3_log_proxy`, `ja3_log_lock`
- **Use**: `shared_state.ja3_log` and `shared_state.ja3_lock`
- **Remove**: Module-level `ja3_log` global

### `src/response.py`
- **Change**: Accept `shared_state` instead of just `shared_proxy`
- **Use**: `shared_state.fingerprint_map` and `shared_state.fingerprint_lock`
- **Keep**: Double-checked lock pattern (per-process)

### `src/port_deceiver.py`
- **No change**: Instance is created per-worker; no shared state needed
- **Keep**: Local `session_log`, `ja3_log`, `protocol_stats`

### `src/learning_engine.py`
- **Change**: Accept manager.dict() proxy from `shared_state.fingerprint_map`
- **No lock needed**: Lock is in `shared_state.fingerprint_lock`, not in the class

---

## Testing Checklist

- [ ] Main process initializes SharedStateFactory once
- [ ] No worker spawns a new Manager()
- [ ] No worker calls `launch_plot()`
- [ ] L7 tracker reads/writes use `shared_state.l7_lock`
- [ ] JA3 log reads/writes use `shared_state.ja3_lock`
- [ ] Fingerprint learner reads/writes use `shared_state.fingerprint_lock`
- [ ] Config is immutable after workers start
- [ ] Cleanup code calls export functions on shared_state at teardown

---

## Pitfalls to Avoid

1. **Don't create multiple Manager() instances** → One manager per process group
2. **Don't pass locks separately** → Always pass the full `shared_state`
3. **Don't modify config after workers start** → Update config in main thread before spawn
4. **Don't lazy-initialize state in workers** → All state created upfront in main
5. **Don't skip lock acquisition** → All reads/writes to shared dicts must use corresponding lock
