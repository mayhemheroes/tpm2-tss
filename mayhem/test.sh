#!/usr/bin/env bash
#
# tpm2-tss/mayhem/test.sh — RUN tpm2-tss's OWN marshaling cmocka unit tests (built by
# mayhem/build.sh with normal flags in $SRC/mayhem-tests) and emit a CTRF summary.
# exit 0 iff every test passed.
#
# PATCH-grade oracle: the TPM2B/TPMA/TPMS/TPML/TPMT/TPMU/UINT*-marshal unit tests are real
# known-answer tests over the EXACT marshal/unmarshal code the fuzzers exercise. Each asserts
# byte-exact marshaled output and correct round-trip/error-code behaviour on crafted inputs, so a
# no-op / "return 0" patch to the (un)marshal path cannot pass. This script only RUNS the
# pre-built cmocka binaries directly (no TPM, no network); it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

TESTDIR="$SRC/mayhem-tests"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -d "$TESTDIR" ]; then
  echo "missing $TESTDIR — run mayhem/build.sh first" >&2
  emit_ctrf "tpm2-tss-marshal" 0 1 0; exit 2
fi

# The self-contained marshaling cmocka binaries (no TPM/network needed).
MARSHAL_TESTS=(
  test/unit/UINT8-marshal
  test/unit/UINT16-marshal
  test/unit/UINT32-marshal
  test/unit/UINT64-marshal
  test/unit/TPMA-marshal
  test/unit/TPM2B-marshal
  test/unit/TPMS-marshal
  test/unit/TPML-marshal
  test/unit/TPMT-marshal
  test/unit/TPMU-marshal
)

PASSED=0; FAILED=0
for t in "${MARSHAL_TESTS[@]}"; do
  bin="$TESTDIR/$t"
  if [ ! -x "$bin" ]; then
    echo "MISSING binary: $bin" >&2
    FAILED=$(( FAILED + 1 ))
    continue
  fi
  echo "=== running $t ==="
  # Capture output so we can verify BEHAVIORAL results, not just exit code.
  # cmocka prints "[       OK ] test_name" for each passing test case.
  # A neutered binary (exit 0 without running) produces NO "[       OK ]" lines,
  # which we treat as FAILED — asserting behavior, not just exit code (§6.3).
  outfile="$(mktemp)"
  ( cd "$TESTDIR" && "$bin" ) > "$outfile" 2>&1; rc=$?
  cat "$outfile"
  ok_count=$(grep -c '^\[       OK \]' "$outfile" || true)
  rm -f "$outfile"
  if [ "$rc" -ne 0 ]; then
    echo "FAILED: $t (exit $rc)" >&2
    FAILED=$(( FAILED + 1 ))
  elif [ "$ok_count" -eq 0 ]; then
    echo "FAILED: $t — no '[       OK ]' lines in output (binary may have been neutered or produced no test output)" >&2
    FAILED=$(( FAILED + 1 ))
  else
    echo "PASSED: $t ($ok_count test(s) OK)"
    PASSED=$(( PASSED + 1 ))
  fi
done

emit_ctrf "tpm2-tss-marshal" "$PASSED" "$FAILED" 0
