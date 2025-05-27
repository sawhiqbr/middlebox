"""
Manual test traffic generator for detector validation
"""
from scapy.all import IP, TCP, send
import time
import argparse

def send_normal_traffic():
    """Send normal TCP traffic"""
    print("Sending normal TCP traffic...")
    
    # Normal SYN
    pkt = IP(dst="10.0.0.21")/TCP(dport=80, flags="S")
    send(pkt, verbose=0)
    time.sleep(0.5)
    
    # Normal ACK
    pkt = IP(dst="10.0.0.21")/TCP(dport=80, flags="A")
    send(pkt, verbose=0)
    time.sleep(0.5)
    
    # Normal FIN+ACK
    pkt = IP(dst="10.0.0.21")/TCP(dport=80, flags="FA")
    send(pkt, verbose=0)
    time.sleep(0.5)
    
    print("Normal traffic sent")

def send_covert_pattern():
    """Send covert channel pattern"""
    print("Sending covert channel pattern...")
    
    # Start session (SA)
    pkt = IP(dst="10.0.0.21")/TCP(dport=31337, flags="SA")
    send(pkt, verbose=0)
    time.sleep(0.2)
    
    # Send some bits (UA = 1, PA = 0)
    bits = "1011"  # Example bit pattern
    for bit in bits:
        if bit == '1':
            pkt = IP(dst="10.0.0.21")/TCP(dport=31337, flags="UA")
        else:
            pkt = IP(dst="10.0.0.21")/TCP(dport=31337, flags="PA")
        send(pkt, verbose=0)
        time.sleep(0.1)
    
    # End session (FA)
    pkt = IP(dst="10.0.0.21")/TCP(dport=31337, flags="FA")
    send(pkt, verbose=0)
    
    print("Covert pattern sent")

def send_suspicious_traffic():
    """Send various suspicious patterns"""
    print("Sending suspicious traffic patterns...")
    
    # Burst of unusual flags
    unusual_flags = ["UA", "PA", "U", "P"]
    
    for flags in unusual_flags:
        for i in range(3):
            pkt = IP(dst="10.0.0.21")/TCP(dport=31338, flags=flags)
            send(pkt, verbose=0)
            time.sleep(0.05)
    
    print("Suspicious traffic sent")

def main():
    parser = argparse.ArgumentParser(description='Test traffic generator')
    parser.add_argument('--type', choices=['normal', 'covert', 'suspicious', 'all'], 
                       default='all', help='Type of traffic to generate')
    
    args = parser.parse_args()
    
    print("Manual Test Traffic Generator")
    print("=" * 30)
    
    if args.type in ['normal', 'all']:
        send_normal_traffic()
        time.sleep(1)
    
    if args.type in ['covert', 'all']:
        send_covert_pattern()
        time.sleep(1)
    
    if args.type in ['suspicious', 'all']:
        send_suspicious_traffic()
    
    print("\nTest traffic generation completed!")
    print("Check detector logs and alerts for results.")

if __name__ == "__main__":
    main()