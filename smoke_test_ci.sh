#!/usr/bin/env bash
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
export PYTHONPATH="${REPO_ROOT}:${REPO_ROOT}/src:${PYTHONPATH:-}"

LOG_DIR="${LOG_DIR:-${RUNNER_TEMP:-/tmp}/camouflage-cloak-ci}"
mkdir -p "$LOG_DIR"

CI_SMOKE_ALLOW_PRIVILEGED="${CI_SMOKE_ALLOW_PRIVILEGED:-0}"
RUN_PRIVILEGED=false
if [[ "$(id -u 2>/dev/null || echo 0)" -eq 0 ]] && [[ "$CI_SMOKE_ALLOW_PRIVILEGED" == "1" ]]; then
  RUN_PRIVILEGED=true
fi

FAILURES=0

log_section() {
  echo
  echo "============================================================"
  echo "$1"
  echo "============================================================"
}

expect_marker() {
  local file="$1"
  local marker="$2"
  local label="${3:-marker '$marker'}"

  if grep -Fq "$marker" "$file"; then
    echo "[PASS] $label found"
    return 0
  fi

  echo "[FAIL] $label not found in log: $file"
  echo "Missing marker: $marker"
  return 1
}

expect_not_marker() {
  local file="$1"
  local marker="$2"
  local label="${3:-disallowed marker '$marker'}"

  if grep -Fq "$marker" "$file"; then
    echo "[FAIL] $label unexpectedly present in log: $file"
    echo "Unexpected marker: $marker"
    return 1
  fi

  echo "[PASS] $label absent"
  return 0
}

run_and_capture() {
  local name="$1"
  local expected_rc="$2"
  shift 2

  local log_file="$LOG_DIR/${name}.log"
  log_section "$name"

  set +e
  "$@" >"$log_file" 2>&1
  local rc=$?
  set -e

  echo "Exit code: $rc"
  tail -n 80 "$log_file" || true

  if [[ "$rc" -ne "$expected_rc" ]]; then
    echo "[FAIL] $name exited with $rc; expected $expected_rc"
    FAILURES=$((FAILURES + 1))
    return 1
  fi

  if grep -Eqi 'Traceback|Fatal Python error|Unhandled exception|Exception in thread|core dumped' "$log_file"; then
    echo "[FAIL] $name contains fatal runtime markers"
    FAILURES=$((FAILURES + 1))
    return 1
  fi

  echo "[PASS] $name exit code matches"
  return 0
}

# Test 1: invalid NIC should fail before runtime starts.
run_and_capture "invalid_nic" 2 bash -c "$PYTHON_BIN main.py --scan ts --nic fake0 --no-gui --te 1" || true
expect_marker "$LOG_DIR/invalid_nic.log" "Invalid NIC" "invalid NIC validation"
expect_not_marker "$LOG_DIR/invalid_nic.log" "SharedState initialized" "runtime started unexpectedly"

# Test 2: invalid host IP should fail in validation.
run_and_capture "invalid_host" 2 bash -c "$PYTHON_BIN main.py --scan ts --nic lo --host 999.999.999.999 --no-gui --te 1" || true
expect_marker "$LOG_DIR/invalid_host.log" "Invalid host IP" "invalid host validation"

# Test 3: invalid pd JSON should fail during argument validation.
run_and_capture "invalid_json_status" 2 bash -c "$PYTHON_BIN main.py --scan pd --nic lo --status '{bad json}' --no-gui --te 1" || true
expect_marker "$LOG_DIR/invalid_json_status.log" "Invalid JSON for --status" "invalid status payload"

# Test 4: privileged runtime startup smoke test.
if [[ "$RUN_PRIVILEGED" == "true" ]]; then
  run_and_capture "valid_startup" 0 bash -c "$PYTHON_BIN main.py --scan ts --nic lo --dest $LOG_DIR/valid_startup_out --no-gui --te 1" || true
  expect_marker "$LOG_DIR/valid_startup.log" "Runtime context" "startup runtime context logged"
  expect_marker "$LOG_DIR/valid_startup.log" "SharedState initialized" "shared state initialized"
  expect_marker "$LOG_DIR/valid_startup.log" "Processing complete" "shutdown completed"
  expect_not_marker "$LOG_DIR/valid_startup.log" "Traceback" "unexpected traceback"

  # Test 5: SIGTERM graceful shutdown.
  log_section "sigterm_shutdown"
  local sigterm_log="$LOG_DIR/sigterm_shutdown.log"
  set +e
  "$PYTHON_BIN" main.py --scan ts --nic lo --dest "$LOG_DIR/sigterm_out" --no-gui --te 5 >"$sigterm_log" 2>&1 &
  local pid=$!
  sleep 2
  kill -TERM "$pid"
  wait "$pid"
  local sigterm_rc=$?
  set -e

  echo "Exit code: $sigterm_rc"
  tail -n 80 "$sigterm_log" || true

  if [[ "$sigterm_rc" -ne 0 ]]; then
    echo "[FAIL] sigterm_shutdown exited with $sigterm_rc; expected 0"
    FAILURES=$((FAILURES + 1))
  else
    expect_marker "$sigterm_log" "收到中断信号" "SIGTERM handled"
    expect_marker "$sigterm_log" "Processing complete" "graceful finalization"
    expect_not_marker "$sigterm_log" "Traceback" "unexpected traceback on shutdown"
    echo "[PASS] sigterm_shutdown"
  fi
else
  log_section "privileged_runtime_skipped"
  echo "[SKIP] privileged runtime startup and SIGTERM tests skipped because root/privileged capture is unavailable in CI."
fi

# Final summary
if [[ "$FAILURES" -ne 0 ]]; then
  echo
  echo "CI smoke test failed with ${FAILURES} failing checks."
  exit 1
fi

echo
echo "CI smoke tests passed."
exit 0
