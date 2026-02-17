#!/bin/sh

# Simulates a SCADA system that subscribes to telemetry
# from field devices and can issue commands.
#
# Topics subscribed:
#   ot/+/telemetry/#
#   ot/+/status/#
#   ot/+/alarm/#
#
# Topics published:
#   ot/+/command/#

set -e

BROKER="${MQTT_BROKER:-mqtt-broker}"
PORT="${MQTT_PORT:-8883}"
CLIENT_ID="${CLIENT_ID:-scada-01}"
USERNAME="scada"
PASSWORD="scada123"

# TLS options
TLS_OPTS="--cafile /certs/ca.crt --insecure"

echo "=== SCADA Subscriber Starting ==="
echo "Broker: $BROKER:$PORT"
echo "Client ID: $CLIENT_ID"

# Wait for broker and publishers to be ready
sleep 10

# Function to publish commands
publish_command() {
    local device=$1
    local command=$2
    local payload=$3

    mosquitto_pub -h "$BROKER" -p "$PORT" \
        -u "$USERNAME" -P "$PASSWORD" \
        $TLS_OPTS \
        -i "${CLIENT_ID}-cmd" \
        -t "ot/$device/command/$command" -m "$payload" -q 1

    echo "Command sent: ot/$device/command/$command"
}

# Subscribe to all OT topics
echo "Subscribing to OT telemetry, status, and alarms..."

# Create a named pipe for processing messages
FIFO="/tmp/scada_messages"
rm -f "$FIFO"
mkfifo "$FIFO"

# Start subscriber in background
mosquitto_sub -h "$BROKER" -p "$PORT" \
    -u "$USERNAME" -P "$PASSWORD" \
    $TLS_OPTS \
    -i "${CLIENT_ID}-sub" \
    -t "ot/+/telemetry/#" \
    -t "ot/+/status/#" \
    -t "ot/+/alarm/#" \
    -t "system/health/#" \
    -v > "$FIFO" &

SUB_PID=$!

# Process messages
echo "Processing incoming messages..."
ALARM_COUNT=0
COMMAND_INTERVAL=60
LAST_COMMAND=0

while read -r line < "$FIFO"; do
    TOPIC=$(echo "$line" | cut -d' ' -f1)
    PAYLOAD=$(echo "$line" | cut -d' ' -f2-)
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    # Log message
    echo "[$TIMESTAMP] $TOPIC: $PAYLOAD"

    # Process alarms
    if echo "$TOPIC" | grep -q "/alarm/"; then
        ALARM_COUNT=$((ALARM_COUNT + 1))
        echo ">>> ALARM #$ALARM_COUNT received on $TOPIC"

        # Auto-acknowledge alarms by sending command
        DEVICE=$(echo "$TOPIC" | cut -d'/' -f2)
        publish_command "$DEVICE" "ack_alarm" "{\"ack\":true,\"operator\":\"scada-auto\",\"timestamp\":$(date +%s)}"
    fi

    # Periodic command sending (every COMMAND_INTERVAL seconds)
    CURRENT_TIME=$(date +%s)
    if [ $((CURRENT_TIME - LAST_COMMAND)) -gt $COMMAND_INTERVAL ]; then
        echo ">>> Sending periodic status request..."
        publish_command "plc" "status_request" "{\"request\":\"full_status\",\"timestamp\":$CURRENT_TIME}"
        publish_command "rtu" "status_request" "{\"request\":\"full_status\",\"timestamp\":$CURRENT_TIME}"
        LAST_COMMAND=$CURRENT_TIME
    fi
done

# Cleanup
kill $SUB_PID 2>/dev/null || true
rm -f "$FIFO"
