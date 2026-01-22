#!/bin/bash
set -euo pipefail

# Usage: ./compare-benchmarks.sh <base-file> <pr-file>
# Outputs markdown comparison table

# Validate arguments
if [[ $# -ne 2 ]]; then
    echo "Error: Expected 2 arguments, got $#"
    echo "Usage: $0 <base-file> <pr-file>"
    exit 1
fi

BASE_FILE="${1}"
PR_FILE="${2}"

if [[ ! -f "${PR_FILE}" ]]; then
    echo "Error: PR benchmark file not found: ${PR_FILE}"
    exit 1
fi

if [[ ! -f "${BASE_FILE}" ]]; then
    echo "## ⏸️ Benchmark Comparison Skipped"
    echo ""
    echo "⚠️ Baseline benchmark results not found."
    echo ""
    echo "The base branch benchmarks haven't run yet. Please:"
    echo "- Rebase your PR on the latest master branch, or"
    echo "- Wait for the baseline benchmarks to complete on master"
    echo ""
    echo "<!-- benchmark-action-comment -->"
    exit 0
fi

# Install benchstat if not available
if ! command -v benchstat &> /dev/null; then
    echo "Installing benchstat..." >&2
    if ! go install golang.org/x/perf/cmd/benchstat@latest; then
        echo "Error: Failed to install benchstat" >&2
        exit 1
    fi
    BENCHSTAT_CMD="$(go env GOPATH)/bin/benchstat"
else
    BENCHSTAT_CMD="benchstat"
fi

# Verify benchstat is executable
if ! command -v "${BENCHSTAT_CMD}" &> /dev/null && [[ ! -x "${BENCHSTAT_CMD}" ]]; then
    echo "Error: benchstat not found or not executable"
    exit 1
fi

# Generate comparison
echo "## 📊 Benchmark Comparison"
echo ""
echo "<details>"
echo "<summary>View Results</summary>"
echo ""
echo "\`\`\`"
"${BENCHSTAT_CMD}" "${BASE_FILE}" "${PR_FILE}" || {
    echo "Error running benchstat comparison"
    exit 1
}
echo "\`\`\`"
echo ""
echo "</details>"
echo ""
echo "---"
echo ""
echo "_Baseline: master branch_"
echo ""
echo "<!-- benchmark-action-comment -->"
