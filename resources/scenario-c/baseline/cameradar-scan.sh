#!/bin/sh
# Baseline Cameradar scan for RTSP cameras
# Specialized RTSP security scanner - no safety constraints

set -eu

TARGETS="${1:-172.30.0.10,172.30.0.11,172.30.0.12}"
OUTPUT_DIR="${2:-/results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "${OUTPUT_DIR}"

echo "=== Baseline Cameradar RTSP Scan ==="
echo "Targets: ${TARGETS}"
echo "Output: ${OUTPUT_DIR}"
echo ""

# Cameradar scans for:
# - RTSP service discovery
# - Path brute-forcing (common stream URLs)
# - Credential brute-forcing
# - Thumbnail capture (proof of access)

/app/cameradar/cameradar \
    -t "${TARGETS}" \
    -p 554 \
    -s 4 \
    -T 3s \
    --output "${OUTPUT_DIR}/cameradar_${TIMESTAMP}.m3u" \
    --debug 2>&1 | tee "${OUTPUT_DIR}/cameradar_${TIMESTAMP}.log"

echo ""
echo "=== Scan Complete ==="
echo "Results: ${OUTPUT_DIR}/cameradar_${TIMESTAMP}.m3u"
echo "Log: ${OUTPUT_DIR}/cameradar_${TIMESTAMP}.log"
cat "${OUTPUT_DIR}/cameradar_${TIMESTAMP}.m3u" 2>/dev/null || echo "(no streams found)"
