#!/usr/bin/env bash
#
# Integration test suite for GhidraMCP HTTP endpoints.
#
# Setup:
#   1. Open Ghidra, import test/fixtures/test_6502.bin as raw 6502 (language:
#      6502, base address 0x0000).
#   2. In the CodeBrowser, create functions at: $0600, $060A, $0613, $0622
#      (select address, press F). Or use "Auto Analyze" — Ghidra should
#      discover the subroutines via the reset vector at $FFFC.
#   3. Enable the GhidraMCPPlugin (File > Configure > Developer).
#   4. Run this script.
#
set -euo pipefail

BASE_URL="${GHIDRA_MCP_URL:-http://localhost:8080}"
PASS=0
FAIL=0
ERRORS=""

# --- helpers ----------------------------------------------------------------

pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); ERRORS+="  FAIL: $1 — $2"$'\n'; printf "  \033[31mFAIL\033[0m %s — %s\n" "$1" "$2"; }

assert_get() {
  local endpoint=$1 expected=$2 label=${3:-"GET $1"}
  local resp
  resp=$(curl -sf "$BASE_URL$endpoint" 2>&1) || { fail "$label" "curl error"; return; }
  if [[ "$resp" == *"$expected"* ]]; then pass "$label"
  else fail "$label" "expected '$expected', got: ${resp:0:120}"; fi
}

assert_get_nonempty() {
  local endpoint=$1 label=${2:-"GET $1"}
  local resp
  resp=$(curl -sf "$BASE_URL$endpoint" 2>&1) || { fail "$label" "curl error"; return; }
  if [[ -n "$resp" ]]; then pass "$label"
  else fail "$label" "empty response"; fi
}

assert_post() {
  local endpoint=$1 data=$2 expected=$3 label=${4:-"POST $1"}
  local resp
  resp=$(curl -sf -X POST -d "$data" "$BASE_URL$endpoint" 2>&1) || { fail "$label" "curl error"; return; }
  if [[ "$resp" == *"$expected"* ]]; then pass "$label"
  else fail "$label" "expected '$expected', got: ${resp:0:120}"; fi
}

# --- preflight --------------------------------------------------------------

echo "=== Preflight ==="
FUNCTIONS=$(curl -sf "$BASE_URL/list_functions" 2>&1) || {
  echo "ERROR: Cannot reach $BASE_URL — is Ghidra running with the plugin enabled?"; exit 1
}
if [[ -z "$FUNCTIONS" ]]; then
  echo "ERROR: No functions defined. Create at least one function in the test binary."; exit 1
fi

FUNC_LINE=$(echo "$FUNCTIONS" | head -1)
FUNC_NAME=${FUNC_LINE%% at *}
FUNC_ADDR=${FUNC_LINE##* at }
ORIG_FUNC_NAME=$FUNC_NAME
echo "  Using function: $FUNC_NAME @ $FUNC_ADDR"
echo

# --- READ endpoints ---------------------------------------------------------

echo "=== Read endpoints ==="

assert_get "/list_functions" "$FUNC_NAME" "list_functions"
assert_get "/get_function_by_address?address=$FUNC_ADDR" "$FUNC_NAME" "get_function_by_address"
assert_get_nonempty "/get_current_address" "get_current_address"
assert_get_nonempty "/decompile_function?address=$FUNC_ADDR" "decompile_function"
assert_get_nonempty "/disassemble_function?address=$FUNC_ADDR" "disassemble_function"
assert_get "/searchFunctions?query=${FUNC_NAME:0:3}" "$FUNC_NAME" "searchFunctions"
assert_get_nonempty "/segments" "segments"
assert_get_nonempty "/data" "data"

# These may legitimately be empty — just verify no HTTP error.
for ep in /methods /classes /imports /exports /namespaces /strings; do
  curl -sf "$BASE_URL$ep" >/dev/null 2>&1 && pass "GET $ep (no error)" || fail "GET $ep" "curl error"
done

# xrefs
assert_get "/xrefs_to?address=$FUNC_ADDR" "" "xrefs_to (no error)"
assert_get "/xrefs_from?address=$FUNC_ADDR" "" "xrefs_from (no error)"
assert_get "/function_xrefs?name=$FUNC_NAME" "" "function_xrefs (no error)"

# pagination
assert_get "/data?offset=0&limit=2" "" "data with pagination"
echo

# --- WRITE endpoints --------------------------------------------------------

echo "=== Write endpoints ==="

# Rename function by address
TEST_NAME="test_rename_$$"
assert_post "/rename_function_by_address" \
  "function_address=$FUNC_ADDR&new_name=$TEST_NAME" \
  "successfully" "rename_function_by_address"
assert_get "/list_functions" "$TEST_NAME" "verify rename visible"

# Rename function by name (restore original)
assert_post "/renameFunction" \
  "oldName=$TEST_NAME&newName=$ORIG_FUNC_NAME" \
  "successfully" "renameFunction (restore)"

# Comments
assert_post "/set_disassembly_comment" \
  "address=$FUNC_ADDR&comment=Test+disasm+comment" \
  "successfully" "set_disassembly_comment"

assert_post "/set_decompiler_comment" \
  "address=$FUNC_ADDR&comment=Test+decompiler+comment" \
  "successfully" "set_decompiler_comment"

assert_get "/decompile_function?address=$FUNC_ADDR" "Test decompiler comment" \
  "verify decompiler comment in output"

# Function prototype
assert_post "/set_function_prototype" \
  "function_address=$FUNC_ADDR&prototype=void ${ORIG_FUNC_NAME}(void)" \
  "successfully" "set_function_prototype"

# Rename data
DATA_ADDR=$(curl -sf "$BASE_URL/data?offset=0&limit=1" 2>/dev/null | head -1 | cut -d: -f1 | tr -d ' ')
if [[ -n "$DATA_ADDR" ]]; then
  DATA_TEST_NAME="test_data_$$"
  assert_post "/renameData" \
    "address=$DATA_ADDR&newName=$DATA_TEST_NAME" \
    "attempted" "renameData"
  assert_get "/data?offset=0&limit=5" "$DATA_TEST_NAME" "verify renameData"
else
  echo "  SKIP renameData — no data found"
fi

# Rename variable (needs decompiled locals)
DECOMP=$(curl -sf "$BASE_URL/decompile_function?address=$FUNC_ADDR" 2>/dev/null)
# Try to find a local variable name from decompile output (e.g. bVar1, uVar1)
LOCAL_VAR=$(echo "$DECOMP" | grep -oE '\b[a-z]Var[0-9]+' | head -1 || true)
if [[ -n "$LOCAL_VAR" ]]; then
  assert_post "/renameVariable" \
    "functionName=$ORIG_FUNC_NAME&oldName=$LOCAL_VAR&newName=test_var" \
    "renamed" "renameVariable"

  # set_local_variable_type
  assert_post "/set_local_variable_type" \
    "function_address=$FUNC_ADDR&variable_name=test_var&new_type=byte" \
    "successfully" "set_local_variable_type"
else
  echo "  SKIP renameVariable / set_local_variable_type — no local variables"
fi
echo

# --- summary ----------------------------------------------------------------

echo "=== Results: $PASS passed, $FAIL failed ==="
if [[ $FAIL -gt 0 ]]; then
  printf "%s" "$ERRORS"
  exit 1
fi
