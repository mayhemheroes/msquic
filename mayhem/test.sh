#!/usr/bin/env bash
#
# msquic/mayhem/test.sh — ADDITIVE golden oracle over the FUZZED parse/spin paths.
#
# WHY NOT msquic's own suite: msquic's real test suite (QUIC_BUILD_TEST=on) stands up loopback
# client+server sockets and needs a working network/datapath + ~minutes of runtime — too heavy and
# environment-dependent for a build-time gate. Instead we exercise the EXACT code the fuzzers hit,
# using the STANDALONE reproducers (StandaloneFuzzTargetMain) that build.sh already produces, replayed
# over the committed golden seed corpus under ASan+UBSan:
#
#   fuzz-standalone     — feeds every mayhem/fuzz/testsuite/* seed through MsQuicApi()+SetParam().
#                         Asserts: binary exits 0 AND stderr contains "Done: <seed>" (the standalone
#                         driver's per-input completion marker). A sanitizer abort (UAF/OOB/UB) or
#                         nonzero exit = FAIL. Missing "Done:" = neutered/sabotaged binary = FAIL.
#   spinquic-standalone — replays one minimal VALID spin seed (>=148B, even) which drives a real
#                         loopback QUIC client+server connection through the packet/frame state
#                         machine for a bounded spin, then tears down clean. Asserts: binary exits 0
#                         AND stderr contains "Done: <seed>". Crash/sanitizer abort/missing marker = FAIL.
#
# ANTI-REWARD-HACKING: the "Done: <file>" assertion is emitted by StandaloneFuzzTargetMain ONLY after
# successfully calling LLVMFuzzerTestOneInput and reading the seed file. A no-op stub (exit(0)) or a
# neutered binary (LD_PRELOAD _exit(0)) skips the driver loop entirely — the marker never appears, so
# this test FAILS. Exit-code-only checks are insufficient and MUST NOT be used.
#
# Leak detection is disabled IN THE BINARY (detect_leaks=0, see mayhem/harnesses/asan_default_options.c)
# so benign teardown-race leaks don't mask real faults.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${OUT:=/mayhem}"
cd "${SRC:-/mayhem}"

PASSED=0; FAILED=0

# emit_ctrf <tool> <passed> <failed> [skipped]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}"
  local tests=$(( passed + failed + skipped ))
  cat > "${CTRF_REPORT:-$PWD/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": { "tests": $tests, "passed": $passed, "failed": $failed, "pending": 0, "skipped": $skipped, "other": 0 }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":0,"skipped":%d,"other":0}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$skipped"
}

# run_standalone <bin> <seed>
#   Runs <bin> <seed>, captures stderr. PASSES iff:
#     (a) exit code == 0  AND
#     (b) stderr contains "Done:" — the StandaloneFuzzTargetMain per-input completion line.
#   A neutered binary (LD_PRELOAD _exit(0)) exits 0 but never prints "Done:" → FAIL.
run_standalone() {
  local bin="$1" seed="$2" label
  label="$(basename "$bin") < $(basename "$seed")"
  local tmplog
  tmplog="$(mktemp /tmp/oracle_XXXXXX.log)"
  local rc=0
  "$bin" "$seed" >"$tmplog" 2>&1 || rc=$?
  # Assert behavioral marker: StandaloneFuzzTargetMain prints "Done:    <path>:" after each input.
  if [ "$rc" -eq 0 ] && grep -q "Done:" "$tmplog"; then
    echo "PASS $label"
    PASSED=$((PASSED+1))
  else
    if [ "$rc" -ne 0 ]; then
      echo "FAIL $label (exit $rc)"
    else
      echo "FAIL $label (exit 0 but 'Done:' marker absent — binary did not execute harness)"
    fi
    FAILED=$((FAILED+1))
  fi
  rm -f "$tmplog"
}

FUZZ_BIN="$OUT/fuzz-standalone"
SPIN_BIN="$OUT/spinquic-standalone"

# ── 1) fuzz-standalone over the whole golden corpus (one replay per seed) ──────────────────────────
if [ -x "$FUZZ_BIN" ]; then
  for seed in mayhem/fuzz/testsuite/*; do
    [ -f "$seed" ] || continue
    run_standalone "$FUZZ_BIN" "$seed"
  done
else
  echo "FAIL: $FUZZ_BIN missing — build.sh did not produce it" >&2; FAILED=$((FAILED+1))
fi

# ── 2) spinquic-standalone over one minimal VALID seed (bounded; it spins a real connection ~10s) ──
if [ -x "$SPIN_BIN" ]; then
  spin_seed="mayhem/spinquic/testsuite/spin_min_148"
  [ -f "$spin_seed" ] || spin_seed="$(ls mayhem/spinquic/testsuite/* 2>/dev/null | head -1)"
  if [ -n "$spin_seed" ] && [ -f "$spin_seed" ]; then
    # 90s wall-clock guard around the harness's own 10s spin. timeout 124 = killed by us (treat as
    # a hang/fail); 0 = clean spin+teardown.
    tmplog="$(mktemp /tmp/oracle_spin_XXXXXX.log)"
    spin_rc=0
    timeout 90 "$SPIN_BIN" "$spin_seed" >"$tmplog" 2>&1 || spin_rc=$?
    label="spinquic-standalone < $(basename "$spin_seed")"
    if [ "$spin_rc" -eq 0 ] && grep -q "Done:" "$tmplog"; then
      echo "PASS $label"
      PASSED=$((PASSED+1))
    else
      if [ "$spin_rc" -ne 0 ]; then
        echo "FAIL $label (exit $spin_rc)"
      else
        echo "FAIL $label (exit 0 but 'Done:' marker absent — binary did not execute harness)"
      fi
      FAILED=$((FAILED+1))
    fi
    rm -f "$tmplog"
  else
    echo "FAIL: no spinquic seed found" >&2; FAILED=$((FAILED+1))
  fi
else
  echo "FAIL: $SPIN_BIN missing — build.sh did not produce it" >&2; FAILED=$((FAILED+1))
fi

echo "=== golden oracle: $PASSED passed, $FAILED failed ==="
emit_ctrf "msquic-standalone-oracle" "$PASSED" "$FAILED" 0
[ "$FAILED" -eq 0 ]
