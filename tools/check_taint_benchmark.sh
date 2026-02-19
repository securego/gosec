#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_FILE="${ROOT_DIR}/.github/benchmarks/taint_benchmark_baseline.env"
BENCH_NAME="BenchmarkTaintPackageAnalyzers_SharedCache"
BENCH_COUNT="${BENCH_COUNT:-5}"

if [[ ! -f "${BASELINE_FILE}" ]]; then
  echo "Baseline file not found: ${BASELINE_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${BASELINE_FILE}"

extract_metrics() {
  local json_file="$1"

  awk -v bench="${BENCH_NAME}" '
    BEGIN {
      count = 0
      ns_sum = 0
      b_sum = 0
      allocs_sum = 0
    }
    {
      if (index($0, "\"Output\":\"") == 0) {
        next
      }

      line = $0
      sub(/^.*"Output":"/, "", line)
      sub(/".*$/, "", line)

      gsub(/\\t/, "\t", line)
      gsub(/\\n/, "", line)

      if (line !~ ("^" bench "-[0-9]+")) {
        next
      }

      split(line, fields, "\t")
      if (length(fields) < 5) {
        next
      }

      ns = fields[3]
      b = fields[4]
      allocs = fields[5]

      gsub(/ ns\/op/, "", ns)
      gsub(/ B\/op/, "", b)
      gsub(/ allocs\/op/, "", allocs)
      gsub(/ /, "", ns)
      gsub(/ /, "", b)
      gsub(/ /, "", allocs)

      if (ns == "" || b == "" || allocs == "") {
        next
      }

      ns_sum += ns + 0
      b_sum += b + 0
      allocs_sum += allocs + 0
      count++
    }
    END {
      if (count == 0) {
        exit 1
      }
      printf "%d %d %d %d\n", int(ns_sum / count), int(b_sum / count), int(allocs_sum / count), count
    }
  ' "${json_file}"
}

run_benchmark() {
  local json_file="$1"
  go test -run '^$' -bench "^${BENCH_NAME}$" -benchmem -count="${BENCH_COUNT}" -json ./ > "${json_file}"
}

update_baseline() {
  local json_file
  json_file="$(mktemp)"

  echo "Running benchmark ${BENCH_NAME} to refresh baseline (count=${BENCH_COUNT})..."
  run_benchmark "${json_file}"

  read -r ns b allocs count < <(extract_metrics "${json_file}")

  awk -v ns="${ns}" -v b="${b}" -v allocs="${allocs}" '
    /^BASE_NS_OP=/ { print "BASE_NS_OP=" ns; next }
    /^BASE_B_PER_OP=/ { print "BASE_B_PER_OP=" b; next }
    /^BASE_ALLOCS_PER_OP=/ { print "BASE_ALLOCS_PER_OP=" allocs; next }
    { print }
  ' "${BASELINE_FILE}" > "${BASELINE_FILE}.tmp"
  mv "${BASELINE_FILE}.tmp" "${BASELINE_FILE}"

  echo "Baseline updated from ${count} samples:"
  echo "  BASE_NS_OP=${ns}"
  echo "  BASE_B_PER_OP=${b}"
  echo "  BASE_ALLOCS_PER_OP=${allocs}"

  rm -f "${json_file}"
}

check_regression() {
  local json_file
  json_file="$(mktemp)"

  echo "Running benchmark ${BENCH_NAME} (count=${BENCH_COUNT})..."
  run_benchmark "${json_file}"

  read -r ns b allocs count < <(extract_metrics "${json_file}")

  local ns_limit b_limit allocs_limit
  ns_limit=$(( BASE_NS_OP + (BASE_NS_OP * NS_OP_REGRESSION_PCT / 100) ))
  b_limit=$(( BASE_B_PER_OP + (BASE_B_PER_OP * B_PER_OP_REGRESSION_PCT / 100) ))
  allocs_limit=$(( BASE_ALLOCS_PER_OP + (BASE_ALLOCS_PER_OP * ALLOCS_PER_OP_REGRESSION_PCT / 100) ))

  echo "Averaged over ${count} samples:"
  echo "  ns/op:     ${ns} (baseline ${BASE_NS_OP}, limit ${ns_limit})"
  echo "  B/op:      ${b} (baseline ${BASE_B_PER_OP}, limit ${b_limit})"
  echo "  allocs/op: ${allocs} (baseline ${BASE_ALLOCS_PER_OP}, limit ${allocs_limit})"

  local failed=0
  if (( ns > ns_limit )); then
    echo "Regression detected: ns/op exceeded threshold" >&2
    failed=1
  fi
  if (( b > b_limit )); then
    echo "Regression detected: B/op exceeded threshold" >&2
    failed=1
  fi
  if (( allocs > allocs_limit )); then
    echo "Regression detected: allocs/op exceeded threshold" >&2
    failed=1
  fi

  if (( failed != 0 )); then
    rm -f "${json_file}"
    exit 1
  fi

  rm -f "${json_file}"
}

case "${1:-}" in
  --update-baseline)
    update_baseline
    ;;
  "")
    check_regression
    ;;
  *)
    echo "Usage: $0 [--update-baseline]" >&2
    exit 2
    ;;
esac
