#!/usr/bin/env python3

import argparse
import os
import sys
from scapy.all import sniff, TCP, IP, Packet

# --- Global State (simpler for Scapy's sniff callback) ---
covert_message_bits = []
receiving_message = False
bit_count = 0
covert_port_global = 0 # To pass port argument to handler
src_ip_global = ""     # To pass source IP to handler
# ---------------------------------------------------------

def bits_to_text(bits, encoding='utf-8', errors='ignore'):
    """Converts a string of bits back to text."""
    if not bits:
        return ""
    try:
        n = int(bits, 2)
        byte_length = (len(bits) + 7) // 8
        return n.to_bytes(byte_length, 'big').decode(encoding, errors)
    except Exception as e:
        print(f"\n[Error] Could not decode bits '{bits}': {e}", file=sys.stderr)
        return "[Decoding Error]"

def packet_handler(packet):
    """Callback function for Scapy's sniff(). Processes incoming packets."""
    global receiving_message, covert_message_bits, bit_count

    # Filter check: ensure it's TCP and destined for our covert port from the expected source
    # (BPF filter already does most of this, but double-check layer existence)
    if TCP in packet and IP in packet and \
       packet[TCP].dport == covert_port_global and \
       packet[IP].src == src_ip_global:

        flags = packet[TCP].flags

        # --- State Machine ---
        # State: Waiting for Start
        if not receiving_message:
            if flags == 'SA': # SoM ('SA') detected
                print("\n[Receiver] Start of Message detected (SA). Receiving data...")
                receiving_message = True
                covert_message_bits = []
                bit_count = 0
            # Ignore other packets if not started

        # State: Receiving Data
        else: # Already receiving_message is True
            if flags == 'FA': # EoM ('FA') detected
                print(f"\n[Receiver] End of Message detected (FA). Total bits received: {bit_count}")
                receiving_message = False
                final_bits = "".join(covert_message_bits)
                if final_bits:
                    decoded_message = bits_to_text(final_bits)
                    print(f"[Receiver] Final bits: {final_bits}")
                    print(f"[Receiver] Decoded message: '{decoded_message}'")
                else:
                    print("[Receiver] No data bits were captured.")
                print("[Receiver] Waiting for next message...") # Reset for potential next message
                covert_message_bits = []
                bit_count = 0

            elif flags == 'UA': # Bit '1' (URG+ACK)
                covert_message_bits.append('1')
                bit_count += 1
                print(f"1", end="", flush=True) # Print bits compactly as they arrive

            elif flags == 'PA': # Bit '0' (PSH+ACK)
                covert_message_bits.append('0')
                bit_count += 1
                print(f"0", end="", flush=True)

            # Potentially handle unexpected flags during transmission if needed
            # else:
            #     print(f"\n[Receiver] Unexpected flags '{flags}' received during transmission.", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Channel Receiver using TCP Flags")
    parser.add_argument("-p", "--port", type=int, default=31337, help="Covert port to listen on (default: 31337).")
    parser.add_argument("--iface", default="eth0", help="Network interface to sniff on (default: eth0).")

    args = parser.parse_args()

    # --- Configuration ---
    COVERT_PORT = args.port
    INTERFACE = args.iface

    # Set globals for handler
    covert_port_global = COVERT_PORT

    # Get expected source IP from environment variables
    src_ip = os.getenv('SECURENET_HOST_IP')
    if not src_ip:
        print("Error: SECURENET_HOST_IP environment variable not set.", file=sys.stderr)
        sys.exit(1)
    src_ip_global = src_ip

    # Define BPF filter for Scapy
    # Capture TCP packets specifically destined for our port coming from the sender's IP
    bpf_filter = f"tcp and dst port {COVERT_PORT} and src host {src_ip_global}"

    print(f"Receiver Config:")
    print(f"  Listening on:   {INTERFACE}")
    print(f"  Covert Port:    {COVERT_PORT}")
    print(f"  Expected Src IP:{src_ip_global}")
    print(f"  BPF Filter:     '{bpf_filter}'")
    print("-" * 20)
    print("Starting covert receiver...")
    print("Waiting for Start of Message (SA)...")

    # --- Start Sniffing ---
    try:
        sniff(iface=INTERFACE, filter=bpf_filter, prn=packet_handler, store=0)
    except PermissionError:
        print(f"\nError: Insufficient privileges to sniff on {INTERFACE}. Try running with sudo or as root.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
         print(f"\nError sniffing on {INTERFACE}: {e}. Interface might not exist or be up.", file=sys.stderr)
         sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    # --- Sniffing Stopped (usually by Ctrl+C) ---

    print("\nReceiver stopped.")