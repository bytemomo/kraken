#!/bin/sh

# Seeds the broker with initial retained messages and topic structure
# to simulate a realistic OT environment for testing.
#
# This includes:
# - Retained status messages
# - System health topics
# - Some intentionally insecure retained messages (for T-2 testing)

set -e

BROKER="${MQTT_BROKER:-mqtt-broker}"
PORT="${MQTT_PORT:-1883}"
USERNAME="${MQTT_USER:-admin}"
PASSWORD="${MQTT_PASS:-admin123}"
USE_TLS="${MQTT_TLS:-false}"

echo "=== Topic Seeder Starting ==="
echo "Broker: $BROKER:$PORT"
echo "User: $USERNAME"

# Wait for broker to be ready
sleep 3

# Build connection options
CONN_OPTS="-h $BROKER -p $PORT -u $USERNAME -P $PASSWORD"
if [ "$USE_TLS" = "true" ]; then
    CONN_OPTS="$CONN_OPTS --cafile /certs/ca.crt --insecure"
fi

# Function to publish retained message
seed_topic() {
    local topic=$1
    local message=$2

    mosquitto_pub $CONN_OPTS -t "$topic" -m "$message" -r -q 1

    echo "Seeded: $topic"
}

echo "Seeding system health topics..."

TIMESTAMP=$(date +%s)

seed_topic "system/health/broker" \
    "{\"status\":\"healthy\",\"version\":\"2.0\",\"uptime\":0,\"timestamp\":$TIMESTAMP}"

seed_topic "system/health/network" \
    "{\"status\":\"healthy\",\"latency_ms\":5,\"packet_loss\":0,\"timestamp\":$TIMESTAMP}"

echo "Seeding device status topics..."

seed_topic "ot/plc/status/config" \
    "{\"device\":\"plc-01\",\"firmware\":\"v2.3.1\",\"model\":\"SimPLC-1000\",\"last_config\":$TIMESTAMP}"

seed_topic "ot/rtu/status/config" \
    "{\"device\":\"rtu-01\",\"firmware\":\"v1.8.5\",\"model\":\"SimRTU-500\",\"last_config\":$TIMESTAMP}"

echo "Seeding vulnerable retained messages (for testing)..."

# Retained message on a command topic (T-2: Abuse of retained messages)
seed_topic "ot/plc/command/startup" \
    "{\"command\":\"initialize\",\"params\":{\"mode\":\"normal\"},\"source\":\"system\",\"timestamp\":$TIMESTAMP}"

# Retained message with sensitive information
seed_topic "ot/config/credentials" \
    "{\"warning\":\"test_data\",\"default_user\":\"admin\",\"note\":\"Change in production\"}"

echo "Seeding test topics..."

seed_topic "test/public/info" \
    "{\"message\":\"This is a public test topic\",\"timestamp\":$TIMESTAMP}"

seed_topic "test/sensitive/data" \
    "{\"data\":\"This should be protected by ACLs\",\"timestamp\":$TIMESTAMP}"

echo "Seeding historical alarm data..."

seed_topic "ot/plc/alarm/history/last" \
    "{\"device\":\"plc-01\",\"alarm\":\"high_temperature\",\"value\":32.5,\"cleared\":true,\"timestamp\":$((TIMESTAMP - 3600))}"

seed_topic "ot/rtu/alarm/history/last" \
    "{\"device\":\"rtu-01\",\"alarm\":\"low_level\",\"value\":12.3,\"cleared\":true,\"timestamp\":$((TIMESTAMP - 7200))}"

echo "=== Topic seeding complete ==="

# Keep container running briefly to ensure messages are delivered
sleep 2
echo "Seeder exiting."
