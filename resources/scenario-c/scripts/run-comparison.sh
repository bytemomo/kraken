#!/bin/bash
# Run baseline tools vs Kraken comparison for scenario-c

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(dirname "${SCRIPT_DIR}")"

cd "${SCENARIO_DIR}"

echo "=============================================="
echo "Scenario C: RTSP Security Assessment Comparison"
echo "=============================================="
echo ""

# Ensure results directories exist
mkdir -p results/nmap results/cameradar results/kraken

# Build and start target environment
echo "[1/5] Starting target environment..."
podman compose up -d camera-1 camera-2 camera-3

# Wait for cameras to initialize
echo "[2/5] Waiting for cameras to initialize..."
sleep 5

# Run nmap baseline
echo "[3/5] Running nmap+NSE baseline..."
podman compose --profile nmap up nmap-baseline
echo "nmap scan complete."

# Run cameradar baseline
echo "[4/5] Running Cameradar baseline..."
podman compose --profile cameradar up cameradar-baseline
echo "Cameradar scan complete."

# Run Kraken
echo "[5/5] Running Kraken..."
podman compose --profile kraken up kraken
echo "Kraken scan complete."

echo ""
echo "=============================================="
echo "Results:"
echo "  nmap:      results/nmap/"
echo "  Cameradar: results/cameradar/"
echo "  Kraken:    results/kraken/"
echo "=============================================="
