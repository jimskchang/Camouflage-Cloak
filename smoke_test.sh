#!/usr/bin/env bash
set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
export PYTHONPATH="${REPO_ROOT}:${REPO_ROOT}/src:${PYTHONPATH:-}"
TEST_DIR="${TEST_DIR:-${TMPDIR:-/tmp}/camouflage-cloak-smoke}"
mkdir -p "$TEST_DIR"

NIC="${NIC:-lo}"
EXPECTED_ROOT_MODE="${EXPECTED_ROOT_MODE:-auto}"

pass_count=0
fail_count=0

run_expect_status() {
  local name="$1"
  local expected_status="$2"
  shift 2

  local log_path="$TEST_DIR/${name}.log"
  echo "==> ${name}"

  set +e
  "$@" >"$log_path" 2>&1
  local status=$?
  set -e

  echo "--- ${name} log ---"
  cat "$log_path"
  echo "--- end log ---"

  if [[ "$status" == "$expected_status" ]]; then
    echo "[PASS] ${name}"
    pass_count=$((pass_count + 1))
  else
    echo "[FAIL] ${name} (expected exit ${expected_status}, got ${status})"
    fail_count=$((fail_count + 1))
  fi

  echo
}

run_skip() {
  local name="$1"
  echo "==> ${name}"
  echo "[SKIP] ${name} (requires elevated privileges)"
  echo
}

if [[ "$EXPECTED_ROOT_MODE" == "auto" ]]; then
  if [[ "$(id -u 2>/dev/null || echo 0)" -ne 0 ]]; then
    RUN_ROOT_TESTS=false
  else
    RUN_ROOT_TESTS=true
  fi
else
  RUN_ROOT_TESTS="$EXPECTED_ROOT_MODE"
fi

run_expect_status "invalid_nic" 2 bash -c "$PYTHON_BIN main.py --scan ts --nic fake0 --no-gui --te 1"
run_expect_status "invalid_host" 2 bash -c "$PYTHON_BIN main.py --scan ts --nic $NIC --host 999.999.999.999 --no-gui --te 1"
run_expect_status "invalid_json_status" 2 bash -c "$PYTHON_BIN main.py --scan pd --nic $NIC --status '{bad json}' --no-gui --te 1"

if [[ "$RUN_ROOT_TESTS" == "true" ]]; then
  run_expect_status "valid_startup" 0 bash -c "$PYTHON_BIN main.py --scan ts --nic $NIC --dest $TEST_DIR/out --no-gui --te 1"

  # Graceful SIGTERM shutdown test.
  local signal_log="$TEST_DIR/sigterm_test.log"
  echo "==> sigterm_shutdown"
  set +e
  "$PYTHON_BIN" main.py --scan ts --nic "$NIC" --dest "$TEST_DIR/sigterm_out" --no-gui --te 5 >"$signal_log" 2>&1 &
  local pid=$!
  sleep 2
  kill -TERM "$pid"
  wait "$pid"
  local signal_status=$?
  set -e

  echo "--- sigterm_shutdown log ---"
  cat "$signal_log"
  echo "--- end log ---"

  if [[ "$signal_status" == "0" ]]; then
    echo "[PASS] sigterm_shutdown"
    pass_count=$((pass_count + 1))
  else
    echo "[FAIL] sigterm_shutdown (exit ${signal_status})"
    fail_count=$((fail_count + 1))
  fi
  echo
else
  run_skip "valid_startup"
  run_skip "sigterm_shutdown"
fi

# Final summary
echo "========================================"
echo "Smoke test summary: ${pass_count} passed, ${fail_count} failed"
if [[ "$fail_count" -ne 0 ]]; then
  echo "Smoke tests failed."
  exit 1
fi

echo "Smoke tests passed."
exit 0
