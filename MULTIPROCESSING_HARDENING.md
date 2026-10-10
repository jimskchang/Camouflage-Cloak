# Multiprocessing Safety Hardening Guide

## Overview
This document outlines critical multiprocessing issues in Camouflage-Cloak and provides step-by-step fixes.

---

## Issue 1: Missing Lock Initialization in `main.py`

### Current Code (lines 106–115)
```python
manager = Manager()
connection_states = manager.dict()
template_dict = manager.dict()
pair_dict = manager.dict()
shared_fingerprint_proxy = manager.dict()

# Synchronize visual dashboard data [13]
l7_tracker.l7_data = manager.dict()
l7_tracker.ja3_map = manager.dict()
l7_tracker.ua_map = manager.dict()
```

### Problem
- Creates manager proxies but **never initializes the lock** for `l7_tracker`
- `l7_tracker.data_lock` remains as `threading.Lock()` instead of `manager.Lock()`
- Workers will deadlock when trying to acquire a threading lock in multiprocessing context

### Fix
Add after line 110:
```python
# CRITICAL: Initialize multiprocessing lock for l7_tracker
mp_lock = manager.Lock()
l7_tracker._set_multiprocessing_lock(mp_lock)
```

---

## Issue 2: Unprotected Global State in `os_recorder.py`

### Current Code (lines 12, 36, 104–112)
```python
ja3_log = {}  # Line 12 — global, unprotected

def templateSynthesis(...):
    ja3_log.setdefault(src_ip, []).append(ja3_hash)  # Race condition!

def export_ja3_log(path, nic):
    global ja3_log
    # No lock — concurrent access not safe
    with open(outfile, "w") as f:
        json.dump(ja3_log, f, indent=2)
```

### Problem
- Global `ja3_log` is accessed by multiple workers **without synchronization**
- Race condition: two workers append to `ja3_log[ip]` simultaneously
- Export function reads while workers write

### Fix Strategy
**Create a managed JA3 export in `main.py`:**

```python
# In main.py, inside run_sniffing_engine():
ja3_log_lock = manager.Lock()
ja3_log_proxy = manager.dict()  # Replaces module global

# Pass to packet_worker:
def packet_worker(queue, args, host_ip, ..., ja3_log_proxy, ja3_log_lock):
    ...
```

**Update `os_recorder.py`:**
```python
# Add to templateSynthesis signature:
def templateSynthesis(packet, proto_type, template_dict, pair_dict, host_ip, 
                      base_path=None, enable_l7=False, ja3_log_proxy=None, ja3_log_lock=None):
    ...
    # Line 36: Protected append
    if ja3_hash and ja3_log_proxy and ja3_log_lock:
        with ja3_log_lock:
            if src_ip not in ja3_log_proxy:
                ja3_log_proxy[src_ip] = []
            ja3_log_proxy[src_ip].append(ja3_hash)
```

---

## Issue 3: Instance State Not Multiprocessing-Safe in `port_deceiver.py`

### Current Code (lines 38–42)
```python
self.protocol_stats = {}
self.session_log = {}
self.ja3_log = {}
self.sent_packets = []

l7_tracker.launch_plot()  # Risky in worker context!
```

### Problem
- Instance dicts are local to each PortDeceiver instance
- If PortDeceiver is created inside a worker process, these will be separate copies
- `launch_plot()` in `__init__` will spawn matplotlib window per worker — bad!

### Fix
1. **Move `launch_plot()` to main process only** (in `main.py`)
2. **Make PortDeceiver state multiprocessing-safe:**

```python
# In PortDeceiver.__init__():
def __init__(self, interface_ip, os_name, ports_config, nic, mac=None, 
             replay=False, interactive=False, enable_dns=False, enable_tls=False,
             shared_session_log=None, shared_session_lock=None):
    ...
    self.interface_ip = interface_ip
    self.os_name = os_name
    # ... keep other assignments ...
    
    # Use shared state if available
    self.shared_session_log = shared_session_log
    self.shared_session_lock = shared_session_lock
    # Keep local copy as fallback
    self.protocol_stats = {}
    self.session_log = {}
    self.ja3_log = {}
    self.sent_packets = []
    
    # DO NOT call launch_plot() here!
    # logging.info(f"PortDeceiver initialized for {interface_ip}")
```

---

## Issue 4: Unsynchronized Global Learner in `response.py`

### Current Code (lines 10–17)
```python
_process_learner_instance = None

def get_shared_learner(shared_proxy=None):
    global _process_learner_instance
    if _process_learner_instance is None:
        _process_learner_instance = FingerprintLearner(shared_map_proxy=shared_proxy)
    return _process_learner_instance
```

### Problem
- Lazy initialization in a worker process is fine, but **no lock** if multiple threads call simultaneously
- `shared_proxy` is a manager dict proxy — OK, but no documentation

### Fix
```python
import threading

_process_learner_instance = None
_learner_lock = threading.Lock()  # Per-process, not manager lock

def get_shared_learner(shared_proxy=None):
    """
    Thread-safe lazy initialization of the learner instance per worker process.
    Each process gets one learner instance; manager proxies handle cross-process sync.
    """
    global _process_learner_instance
    if _process_learner_instance is None:
        with _learner_lock:
            if _process_learner_instance is None:
                _process_learner_instance = FingerprintLearner(shared_map_proxy=shared_proxy)
    return _process_learner_instance
```

---

## Summary: Changes by File

| File | Issue | Fix Type | Priority |
|------|-------|----------|----------|
| `main.py` | Missing lock init | Add `l7_tracker._set_multiprocessing_lock(mp_lock)` | **CRITICAL** |
| `main.py` | GUI window spawned in workers | Move `l7_tracker.launch_plot()` to main thread only | **HIGH** |
| `os_recorder.py` | Race condition on `ja3_log` | Accept manager proxies as params, use lock | **CRITICAL** |
| `port_deceiver.py` | Instance state unsafe | Accept manager proxies, don't call `launch_plot()` in `__init__` | **HIGH** |
| `response.py` | Lazy init race (minor) | Add double-checked lock pattern | **LOW** |

---

## Testing Checklist

- [ ] Run with `--scan ts` for 2+ minutes; verify no deadlocks
- [ ] Check `os_record/l7_http_log.json` is updated in real-time
- [ ] Verify `ja3_observed_*.json` exports all seen JA3s (no duplicates lost)
- [ ] Confirm single matplotlib window appears (not per-worker)
- [ ] Stress test with high packet rate (>10k pps) — no crashes

---

## References

- `l7_tracker.py` — Already fixed ✅
- `main.py` lines 102–149
- `os_recorder.py` lines 12, 36, 104–114
- `port_deceiver.py` lines 16, 38–44
- `response.py` lines 10–17
