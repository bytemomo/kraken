#!/bin/sh

# Simulates an RTU field device that publishes sensor data
# to the MQTT broker on the OT network.
#
# Topics published:
#   ot/rtu/telemetry/flow
#   ot/rtu/telemetry/level
#   ot/rtu/status/online
#   ot/rtu/alarm/critical

set -e

BROKER="${MQTT_BROKER:-mqtt-broker}"
PORT="${MQTT_PORT:-8883}"
CLIENT_ID="${CLIENT_ID:-rtu-01}"
USERNAME="rtu"
PASSWORD="rtu123"

# TLS options
TLS_OPTS="--cafile /certs/ca.crt --insecure"

echo "=== RTU Publisher Starting ==="
echo "Broker: $BROKER:$PORT"
echo "Client ID: $CLIENT_ID"

# Wait for broker to be ready
sleep 7

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
publish_telemetry "ot/rtu/status/online" "{\"device\":\"$CLIENT_ID\",\"status\":\"online\",\"timestamp\":$(date +%s)}" true

# Subscribe to commands in background
echo "Subscribing to commands..."
mosquitto_sub -h "$BROKER" -p "$PORT" \
    -u "$USERNAME" -P "$PASSWORD" \
    $TLS_OPTS \
    -i "${CLIENT_ID}-sub" \
    -t "ot/rtu/command/#" -v &

SUB_PID=$!

# Continuous telemetry loop
echo "Starting telemetry publishing loop..."
COUNTER=0
TANK_LEVEL=50  # Start at 50%

while true; do
    COUNTER=$((COUNTER + 1))
    TIMESTAMP=$(date +%s)

    # Simulate flow reading (100-200 L/min with noise)
    FLOW=$(awk "BEGIN {printf \"%.1f\", 150 + (rand() * 100 - 50)}")

    # Simulate tank level (slowly changing)
    TANK_LEVEL=$(awk -v level="$TANK_LEVEL" "BEGIN {
        new_level = level + (rand() * 2 - 1);
        if (new_level < 10) new_level = 10;
        if (new_level > 90) new_level = 90;
        printf \"%.1f\", new_level
    }")

    # Publish telemetry
    publish_telemetry "ot/rtu/telemetry/flow" \
        "{\"device\":\"$CLIENT_ID\",\"value\":$FLOW,\"unit\":\"L/min\",\"timestamp\":$TIMESTAMP}"

    publish_telemetry "ot/rtu/telemetry/level" \
        "{\"device\":\"$CLIENT_ID\",\"value\":$TANK_LEVEL,\"unit\":\"percent\",\"timestamp\":$TIMESTAMP}"

    # Periodic status update
    if [ $((COUNTER % 10)) -eq 0 ]; then
        publish_telemetry "ot/rtu/status/online" \
            "{\"device\":\"$CLIENT_ID\",\"status\":\"online\",\"uptime\":$COUNTER,\"timestamp\":$TIMESTAMP}" true
    fi

    # Check for alarm conditions
    if [ "$(echo "$TANK_LEVEL < 15" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
        echo "Low level alarm!"
        publish_telemetry "ot/rtu/alarm/warning" \
            "{\"device\":\"$CLIENT_ID\",\"alarm\":\"low_level\",\"value\":$TANK_LEVEL,\"timestamp\":$TIMESTAMP}"
    elif [ "$(echo "$TANK_LEVEL > 85" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
        echo "High level alarm!"
        publish_telemetry "ot/rtu/alarm/warning" \
            "{\"device\":\"$CLIENT_ID\",\"alarm\":\"high_level\",\"value\":$TANK_LEVEL,\"timestamp\":$TIMESTAMP}"
    fi

    sleep 6
done

# Cleanup (if we ever exit)
kill $SUB_PID 2>/dev/null || true
