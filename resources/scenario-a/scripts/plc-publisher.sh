#!/bin/sh

# PLC Publisher Simulator for Scenario A
#
# Topics published:
#   ot/plc/telemetry/temperature
#   ot/plc/telemetry/pressure
#   ot/plc/status/online
#   ot/plc/alarm/critical

set -e

BROKER="${MQTT_BROKER:-mqtt-broker}"
PORT="${MQTT_PORT:-8883}"
CLIENT_ID="${CLIENT_ID:-plc-01}"
USERNAME="plc"
PASSWORD="plc123"

# TLS options
TLS_OPTS="--cafile /certs/ca.crt --insecure"

echo "=== PLC Publisher Starting ==="
echo "Broker: $BROKER:$PORT"
echo "Client ID: $CLIENT_ID"

# Wait for broker to be ready
sleep 5

# Function to publish telemetry
publish_telemetry() {
    local topic=$1
    local message=$2
    local retain=${3:-false}

    if [ "$retain" = "true" ]; then
        mosquitto_pub -h "$BROKER" -p "$PORT" \
            -u "$USERNAME" -P "$PASSWORD" \
            $TLS_OPTS \
            -i "${CLIENT_ID}-pub" \
            -t "$topic" -m "$message" -r -q 1
    else
        mosquitto_pub -h "$BROKER" -p "$PORT" \
            -u "$USERNAME" -P "$PASSWORD" \
            $TLS_OPTS \
            -i "${CLIENT_ID}-pub" \
            -t "$topic" -m "$message" -q 1
    fi
}

# Publish initial status (retained)
echo "Publishing initial status..."
publish_telemetry "ot/plc/status/online" "{\"device\":\"$CLIENT_ID\",\"status\":\"online\",\"timestamp\":$(date +%s)}" true

# Subscribe to commands in background
echo "Subscribing to commands..."
mosquitto_sub -h "$BROKER" -p "$PORT" \
    -u "$USERNAME" -P "$PASSWORD" \
    $TLS_OPTS \
    -i "${CLIENT_ID}-sub" \
    -t "ot/plc/command/#" -v &

SUB_PID=$!

# Continuous telemetry loop
echo "Starting telemetry publishing loop..."
COUNTER=0

while true; do
    COUNTER=$((COUNTER + 1))
    TIMESTAMP=$(date +%s)

    # Simulate temperature reading (20-30 degrees with noise)
    TEMP=$(awk "BEGIN {printf \"%.2f\", 25 + (rand() * 10 - 5)}")

    # Simulate pressure reading (1.0-1.5 bar with noise)
    PRESSURE=$(awk "BEGIN {printf \"%.3f\", 1.25 + (rand() * 0.5 - 0.25)}")

    # Publish telemetry
    publish_telemetry "ot/plc/telemetry/temperature" \
        "{\"device\":\"$CLIENT_ID\",\"value\":$TEMP,\"unit\":\"celsius\",\"timestamp\":$TIMESTAMP}"

    publish_telemetry "ot/plc/telemetry/pressure" \
        "{\"device\":\"$CLIENT_ID\",\"value\":$PRESSURE,\"unit\":\"bar\",\"timestamp\":$TIMESTAMP}"

    # Periodic status update
    if [ $((COUNTER % 10)) -eq 0 ]; then
        publish_telemetry "ot/plc/status/online" \
            "{\"device\":\"$CLIENT_ID\",\"status\":\"online\",\"uptime\":$COUNTER,\"timestamp\":$TIMESTAMP}" true
    fi

    # Simulate occasional alarm (every ~50 iterations)
    if [ $((COUNTER % 50)) -eq 0 ]; then
        echo "Simulating alarm condition..."
        publish_telemetry "ot/plc/alarm/warning" \
            "{\"device\":\"$CLIENT_ID\",\"alarm\":\"high_temperature\",\"value\":$TEMP,\"timestamp\":$TIMESTAMP}"
    fi

    sleep 5
done

# Cleanup (if we ever exit)
kill $SUB_PID 2>/dev/null || true
