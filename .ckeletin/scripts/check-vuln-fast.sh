#!/usr/bin/env bash
# Fast vulnerability scan for pre-commit hooks
# Uses caching to avoid repeated scans within a time window
set -eo pipefail

# Source standard output functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/check-output.sh
source "${SCRIPT_DIR}/lib/check-output.sh"

# Cache configuration
CACHE_DIR="${TMPDIR:-/tmp}/ckeletin-go-vuln-cache"
CACHE_FILE="${CACHE_DIR}/last-scan"
CACHE_RESULT="${CACHE_DIR}/result"
CACHE_TTL=300  # 5 minutes - skip if scanned recently

# Allow skipping for offline work
if [[ "${SKIP_VULN_CHECK:-}" == "1" ]]; then
    echo "  Skipping vulnerability check (SKIP_VULN_CHECK=1)"
    exit 0
fi

check_header "Fast vulnerability scan"

# Create cache directory
mkdir -p "$CACHE_DIR"

# Check if we have a recent scan result
if [[ -f "$CACHE_FILE" ]]; then
    LAST_SCAN=$(cat "$CACHE_FILE")
    NOW=$(date +%s)
    AGE=$((NOW - LAST_SCAN))

    if [[ $AGE -lt $CACHE_TTL ]]; then
        # Check cached result
        if [[ -f "$CACHE_RESULT" ]] && [[ "$(cat "$CACHE_RESULT")" == "0" ]]; then
            check_success "No vulnerabilities (cached ${AGE}s ago)"
            exit 0
        elif [[ -f "$CACHE_RESULT" ]]; then
            check_failure \
                "Vulnerabilities found (cached ${AGE}s ago)" \
                "Previous scan detected issues" \
                "Run: task check:vuln for details"
            exit 1
        fi
    fi
fi

# Run govulncheck. Its exit status is the verdict, never its output: findings
# print call traces, and a symbol such as http2bufferedWriterTimeoutWriter
# reads like a network error to a text search.
#   0 = no vulnerability affects the code
#   3 = vulnerabilities affect the code
#   anything else = the scan did not complete (vulnerability database
#   unreachable, packages failed to load)
GOVULNCHECK_EXIT=0
run_check "govulncheck ./... 2>&1" || GOVULNCHECK_EXIT=$?

case $GOVULNCHECK_EXIT in
    0)
        date +%s > "$CACHE_FILE"
        echo "0" > "$CACHE_RESULT"
        check_success "No vulnerabilities found"
        exit 0
        ;;
    3)
        date +%s > "$CACHE_FILE"
        echo "1" > "$CACHE_RESULT"
        check_failure \
            "Security vulnerabilities detected" \
            "$CHECK_OUTPUT" \
            "Run: task check:vuln for details"$'\n'"Update vulnerable dependencies before committing"
        exit 1
        ;;
    *)
        # Nothing was scanned, so this cannot pass. Not cached: the next run retries.
        check_failure \
            "Vulnerability scan did not complete (govulncheck exit ${GOVULNCHECK_EXIT})" \
            "$CHECK_OUTPUT" \
            "Fix the error above and retry"$'\n'"Offline: set SKIP_VULN_CHECK=1 to skip this scan, then run 'task check:vuln' once online"
        exit 1
        ;;
esac
