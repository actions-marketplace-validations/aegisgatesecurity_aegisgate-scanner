#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# AegisGate Scanner — GitHub Action entrypoint
# Handles conditional CLI flags that Docker actions can't express natively.

set -e

ARGS="scan ${INPUT_PATH:-.}"

# Format
if [ -n "${INPUT_FORMAT}" ]; then
  ARGS="$ARGS --format ${INPUT_FORMAT}"
fi

# Severity
if [ -n "${INPUT_SEVERITY}" ]; then
  ARGS="$ARGS --severity ${INPUT_SEVERITY}"
fi

# Output file (always write to /github/workspace for artifact access)
OUTPUT_FILE="/github/workspace/aegisgate-report.${INPUT_FORMAT:-sarif}"
ARGS="$ARGS --output ${OUTPUT_FILE}"

# No-ML mode
if [ "${INPUT_NO_ML}" = "true" ]; then
  ARGS="$ARGS --no-ml"
fi

# Diff scanning
if [ -n "${INPUT_DIFF}" ]; then
  ARGS="$ARGS --diff ${INPUT_DIFF}"
fi

# Baseline
if [ -n "${INPUT_BASELINE}" ]; then
  ARGS="$ARGS --baseline ${INPUT_BASELINE}"
fi

# Disable rules (comma-separated)
if [ -n "${INPUT_DISABLE_RULE}" ]; then
  for rule in $(echo "${INPUT_DISABLE_RULE}" | tr ',' ' '); do
    ARGS="$ARGS --disable-rule ${rule}"
  done
fi

# Concurrency
if [ -n "${INPUT_CONCURRENCY}" ]; then
  ARGS="$ARGS --concurrency ${INPUT_CONCURRENCY}"
fi

# No extract archives
if [ "${INPUT_NO_EXTRACT_ARCHIVES}" = "true" ]; then
  ARGS="$ARGS --no-extract-archives"
fi

# Quiet mode (exit code only, no output to stdout)
if [ "${INPUT_QUIET}" = "true" ]; then
  ARGS="$ARGS --quiet"
fi

echo "Running: aegisgate-scanner $ARGS"
aegisgate-scanner $ARGS
EXIT_CODE=$?

# Report the output file location
echo "Report written to: ${OUTPUT_FILE}"

exit ${EXIT_CODE}