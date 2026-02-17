#!/usr/bin/env python3
"""KickCAT EtherCAT master - based on easycat.py example."""

import kickcat
from kickcat import State
from kickcat.mailbox.request import MessageStatus
import time
import argparse
import sys

def log(msg):
    print(msg, flush=True)


def main():
    parser = argparse.ArgumentParser(description="EtherCAT master")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface")
    args = parser.parse_args()

    print(f"Initializing on {args.interface}...")

    link = kickcat.create_link(args.interface, "")
    bus = kickcat.Bus(link)

    print("Scanning bus...")
    bus.init(0.1)

    slaves = bus.slaves()
    print(f"Found {len(slaves)} slave(s)")
    for s in slaves:
        print(f"  - Slave {s.address}")

    if len(slaves) == 0:
        print("No slaves found, exiting")
        sys.exit(1)

    bus.create_mapping()

    print("Switching to SAFE_OP...")
    bus.request_state(State.SAFE_OP)
    bus.wait_for_state(State.SAFE_OP, 1.0)

    for slave in slaves:
        if slave.output_size > 0:
            slave.set_output_bytes(b"\xaa" * slave.output_size)

    print("Switching to OPERATIONAL...")
    bus.request_state(State.OPERATIONAL)

    def cyclic_callback():
        bus.process_data()

    bus.wait_for_state(State.OPERATIONAL, 1.0, cyclic_callback)

    print("Running cyclic exchange...")
    cycle = 0
    lost_count = 0
    try:
        while True:
            try:
                bus.process_data()
            except RuntimeError as e:
                if "LOST" in str(e):
                    lost_count += 1
                    if lost_count % 10 == 1:
                        print(f"[{cycle}] Warning: datagram lost (total: {lost_count})")
                    continue
                raise
            cycle += 1
            if cycle % 250 == 0:
                print(f"[{cycle}] Active slaves: {len(slaves)}, lost: {lost_count}")
            time.sleep(0.004)
    except KeyboardInterrupt:
        print("\nStopping...")


if __name__ == "__main__":
    main()
