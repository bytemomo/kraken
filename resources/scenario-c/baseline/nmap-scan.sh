#!/bin/bash
# Baseline nmap+NSE scan for RTSP cameras
# This script runs standalone nmap to compare against Kraken's orchestrated approach

set -euo pipefail

TARGETS="${1:-172.30.0.10-12}"
OUTPUT_DIR="${2:-/results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "${OUTPUT_DIR}"

echo "=== Baseline RTSP Security Scan ==="
echo "Targets: ${TARGETS}"
echo "Output: ${OUTPUT_DIR}"
echo ""

# Phase 1: Service discovery
echo "[1/3] Service discovery..."
nmap -sV -p 554,8554 \
    --open \
    -oX "${OUTPUT_DIR}/discovery_${TIMESTAMP}.xml" \
    -oN "${OUTPUT_DIR}/discovery_${TIMESTAMP}.txt" \
    ${TARGETS}

# Phase 2: RTSP method enumeration
echo "[2/3] RTSP method enumeration..."
nmap -p 554 \
    --script rtsp-methods \
    -oX "${OUTPUT_DIR}/rtsp-methods_${TIMESTAMP}.xml" \
    -oN "${OUTPUT_DIR}/rtsp-methods_${TIMESTAMP}.txt" \
    ${TARGETS}

# Phase 3: RTSP URL brute-force (path discovery)
echo "[3/3] RTSP URL discovery..."
nmap -p 554 \
    --script rtsp-url-brute \
    -oX "${OUTPUT_DIR}/rtsp-url-brute_${TIMESTAMP}.xml" \
    -oN "${OUTPUT_DIR}/rtsp-url-brute_${TIMESTAMP}.txt" \
    ${TARGETS}

echo ""
echo "=== Scan Complete ==="
echo "Results saved to ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}"
