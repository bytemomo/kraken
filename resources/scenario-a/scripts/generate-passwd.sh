#!/bin/sh

# Generates a hashed Mosquitto password file.
# Run this before starting the environment if passwd file doesn't exist.

SCRIPT_DIR="$(dirname "$0")"
PASSWD_FILE="${1:-$SCRIPT_DIR/config/passwd}"

echo "Generating Mosquitto password file..."

# Create empty file
> "$PASSWD_FILE"

# Add users with mosquitto_passwd
mosquitto_passwd -b "$PASSWD_FILE" admin admin123
mosquitto_passwd -b "$PASSWD_FILE" scada scada123
mosquitto_passwd -b "$PASSWD_FILE" plc plc123
mosquitto_passwd -b "$PASSWD_FILE" rtu rtu123
mosquitto_passwd -b "$PASSWD_FILE" operator operator
mosquitto_passwd -b "$PASSWD_FILE" guest guest

echo "Password file generated: $PASSWD_FILE"
cat "$PASSWD_FILE"
