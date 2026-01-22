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
    echo "Error: benchstat not found or not executable" >&2
    exit 1
fi

# Run benchstat and capture output
BENCHSTAT_OUTPUT=$("${BENCHSTAT_CMD}" "${BASE_FILE}" "${PR_FILE}" 2>&1) || {
    echo "Error running benchstat comparison" >&2
    exit 1
}

# Output markdown header
echo "## 📊 Benchmark Comparison"
echo ""
echo "Comparing baseline (master) vs PR changes:"
echo ""

# Check if there are any benchmark differences
if echo "${BENCHSTAT_OUTPUT}" | grep -q "vs base"; then
    # Output the benchstat comparison in a collapsible section
    echo "<details>"
    echo "<summary>View Full Comparison</summary>"
    echo ""
    echo "\`\`\`"
    echo "${BENCHSTAT_OUTPUT}"
    echo "\`\`\`"
    echo ""
    echo "</details>"
    echo ""

    # Extract and highlight significant changes
    echo "### Significant Changes"
    echo ""
    if echo "${BENCHSTAT_OUTPUT}" | grep -E '\+[0-9]+\.[0-9]+%|\-[0-9]+\.[0-9]+%' | grep -v '~' > /dev/null; then
        echo "| Benchmark | Change | Note |"
        echo "|-----------|--------|------|"

        # Parse lines with percentage changes
        echo "${BENCHSTAT_OUTPUT}" | grep -E 'sec/op.*vs base' -A 1000 | grep -E '^[A-Za-z]' | while IFS= read -r line; do
            # Extract benchmark name (first column)
            benchmark=$(echo "$line" | awk '{print $1}')

            # Extract percentage change if it exists
            if echo "$line" | grep -qE '\+[0-9]+\.[0-9]+%|\-[0-9]+\.[0-9]+%'; then
                change=$(echo "$line" | grep -oE '[-+][0-9]+\.[0-9]+%' | head -1)

                # Determine if it's a regression or improvement
                if [[ "$change" == -* ]]; then
                    note="✅ Faster"
                else
                    note="⚠️ Slower"
                fi

                echo "| $benchmark | $change | $note |"
            fi
        done || echo "_No significant performance changes detected_"
    else
        echo "_No significant performance changes detected (all changes within noise threshold)_"
    fi
else
    # No baseline comparison, just show new benchmarks
    echo "_New benchmarks added (no baseline for comparison)_"
    echo ""
    echo "<details>"
    echo "<summary>View Results</summary>"
    echo ""
    echo "\`\`\`"
    echo "${BENCHSTAT_OUTPUT}"
    echo "\`\`\`"
    echo ""
    echo "</details>"
fi

echo ""
echo "---"
echo ""
echo "_Baseline: master branch_"
echo ""
echo "<!-- benchmark-action-comment -->"
