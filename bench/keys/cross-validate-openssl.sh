#!/bin/bash
# Cross-validation: crypto-gost <-> OpenSSL
# GOST R 34.10-2012 key DER structure validation via openssl asn1parse
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$BENCH_DIR/target/benchmarks.jar"
JAVA_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED \
           --add-opens java.base/java.util=ALL-UNNAMED \
           --add-opens java.base/java.io=ALL-UNNAMED \
           --add-opens java.base/java.text=ALL-UNNAMED \
           --add-opens java.base/jdk.internal.misc=ALL-UNNAMED"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0
TOTAL=0

# ---------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------
check_prereqs() {
  if ! command -v openssl &>/dev/null; then
    echo "ERROR: openssl not found."
    exit 1
  fi

  echo "OpenSSL version: $(openssl version | awk '{print $2}')"

  if ! openssl asn1parse --help &>/dev/null; then
    echo "ERROR: openssl asn1parse not available."
    exit 1
  fi

  if [ ! -f "$JAR" ]; then
    echo "ERROR: $JAR not found. Run 'make build' first."
    exit 1
  fi

  echo "All prerequisites met."
  echo
}

run_test() {
  local curve="$1"
  local sign_alg="$2"

  TOTAL=$((TOTAL + 1))

  local pub_der="$TMPDIR/${curve}_pub.der"
  local priv_der="$TMPDIR/${curve}_priv.der"

  java $JAVA_OPTS -cp "$JAR" org.rssys.bench.KeyTool genkey "$curve" "$pub_der" "$priv_der" > /dev/null 2>&1

  local curve_ok=true

  # Must parse successfully as DER
  if ! openssl asn1parse -inform DER -in "$pub_der" &>/dev/null; then
    curve_ok=false
  fi

  if ! openssl asn1parse -inform DER -in "$priv_der" &>/dev/null; then
    curve_ok=false
  fi

  # Must contain GOST sign algorithm OID (resolved to friendly name by OpenSSL)
  if ! openssl asn1parse -inform DER -in "$pub_der" 2>/dev/null | grep -qi "GOST R 34.10-2012\|gost.*3410\|id-tc26-gost-3410"; then
    curve_ok=false
  fi

  if ! openssl asn1parse -inform DER -in "$priv_der" 2>/dev/null | grep -qi "GOST R 34.10-2012\|gost.*3410\|id-tc26-gost-3410"; then
    curve_ok=false
  fi

  # Must contain the sign algorithm bit length
  if ! openssl asn1parse -inform DER -in "$pub_der" 2>/dev/null | grep -qi "$sign_alg"; then
    curve_ok=false
  fi

  if [ "$curve_ok" = true ]; then
    PASS=$((PASS + 1))
    printf "  %-18s ossl->der=OK\n" "$curve"
  else
    FAIL=$((FAIL + 1))
    printf "  %-18s ossl->der=FAIL  <<<\n" "$curve"
  fi
}

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
check_prereqs

echo "============================================================"
echo "  Cross-validation: crypto-gost <-> OpenSSL"
echo "  Keys: GOST R 34.10-2012 (DER structure)"
echo "============================================================"
echo

echo "--- 256-bit curves ---"
run_test "cryptopro-A"     "256 bit"
run_test "cryptopro-B"     "256 bit"
run_test "cryptopro-C"     "256 bit"
run_test "tc26-gost-A-256" "256 bit"
echo

echo "--- 512-bit curves ---"
run_test "tc26-gost-A-512" "512 bit"
run_test "tc26-gost-B-512" "512 bit"
run_test "tc26-gost-C-512" "512 bit"
echo

echo "============================================================"
echo "  Summary:"
echo "    Total checks:  $TOTAL"
echo "    Passed:        $PASS"
echo "    Failed:        $FAIL"
echo "    Status:        $([ $FAIL -eq 0 ] && echo "SUCCESS" || echo "FAILED")"
echo "============================================================"

exit $(( FAIL > 0 ? 1 : 0 ))
