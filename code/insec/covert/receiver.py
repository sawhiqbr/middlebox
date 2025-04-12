import argparse
import os
import sys
import time
from scapy.all import sniff, TCP, IP, Packet

covert_message_bits = []
receiving_message = False
bit_count = 0
covert_port_global = 0 
src_ip_global = ""     


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

    if TCP in packet and IP in packet and \
       packet[TCP].dport == covert_port_global and \
       packet[IP].src == src_ip_global:

        flags = packet[TCP].flags

        # State: Waiting for Start
        if not receiving_message:
            if flags == 'SA': # SoM ('SA') detected
                print("\n[Receiver] Start of Message detected (SA). Receiving data...")
                receiving_message = True
                covert_message_bits = []
                bit_count = 0

        # State: Receiving Data
        else: 
            if flags == 'FA': # EoM ('FA') detected
                receiver_end_timestamp = time.time()
                print(f"\n[RECEIVER_TIMESTAMP_END] {receiver_end_timestamp:.6f}")

                print(f"\n[Receiver] End of Message detected (FA). Total bits received: {bit_count}")
                receiving_message = False
                final_bits = "".join(covert_message_bits)
                if final_bits:
                    decoded_message = bits_to_text(final_bits)
                    print(f"[Receiver] Final bits: {final_bits}")
                    print(f"[RECEIVER_DECODE_SUCCESS] {decoded_message}")
                else:
                    print("[RECEIVER_DECODE_EMPTY]")

                sys.stdout.flush() 
                print("[Receiver] Waiting for next message...") 
                covert_message_bits = []
                bit_count = 0

            elif flags == 'UA': # Bit '1' (URG+ACK)
                covert_message_bits.append('1')
                bit_count += 1
                print(f"1", end="", flush=True) 

            elif flags == 'PA': # Bit '0' (PSH+ACK)
                covert_message_bits.append('0')
                bit_count += 1
                print(f"0", end="", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Channel Receiver using TCP Flags")
    parser.add_argument("-p", "--port", type=int, default=31337, help="Covert port to listen on (default: 31337).")
    parser.add_argument("--iface", default="eth0", help="Network interface to sniff on (default: eth0).")

    args = parser.parse_args()

    COVERT_PORT = args.port
    INTERFACE = args.iface

    covert_port_global = COVERT_PORT

    src_ip = os.getenv('SECURENET_HOST_IP')
    if not src_ip:
        print("Error: SECURENET_HOST_IP environment variable not set.", file=sys.stderr)
        sys.exit(1)
    src_ip_global = src_ip

    bpf_filter = f"tcp and dst port {COVERT_PORT} and src host {src_ip_global}"

    print(f"Receiver Config:")
    print(f"  Listening on:   {INTERFACE}")
    print(f"  Covert Port:    {COVERT_PORT}")
    print(f"  Expected Src IP:{src_ip_global}")
    print(f"  BPF Filter:     '{bpf_filter}'")
    print("-" * 20)
    print("Starting covert receiver...")
    print("Waiting for Start of Message (SA)...")

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

    print("\nReceiver stopped.")