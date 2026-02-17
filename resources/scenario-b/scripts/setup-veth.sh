#!/bin/bash
# Setup virtual ethernet pair for KickCAT simulation

set -e

CMD=${1:-help}
NAME=${2:-ecat}

case "$CMD" in
    create)
        echo "Creating veth pair ${NAME}A <-> ${NAME}B..."
        sudo ip link add ${NAME}A type veth peer name ${NAME}B
        sudo ip link set ${NAME}A up promisc on
        sudo ip link set ${NAME}B up promisc on
        echo "Done. Master uses ${NAME}A, simulator uses ${NAME}B"
        ;;
    delete)
        echo "Deleting veth pair ${NAME}A <-> ${NAME}B..."
        sudo ip link del ${NAME}A 2>/dev/null || true
        echo "Done."
        ;;
    status)
        ip link show ${NAME}A 2>/dev/null && ip link show ${NAME}B 2>/dev/null || echo "veth pair not found"
        ;;
    *)
        echo "Usage: $0 {create|delete|status} [name]"
        echo "  create ecat  - Create ecatA <-> ecatB veth pair"
        echo "  delete ecat  - Delete the veth pair"
        echo "  status ecat  - Show veth status"
        exit 1
        ;;
esac
