import os
import time
import random
import json
from scapy.all import Ether, IP, ICMP
import nats
import asyncio
import matplotlib.pyplot as plt
from collections import defaultdict

# Configuration
NATS_SERVER = os.getenv('NATS_SURVEYOR_SERVERS', 'nats://nats:4222')
DELAY_RANGE = (0, 0.1)  # Delay range in seconds
MEASUREMENT_DURATION = 60  # Duration to collect measurements in seconds
DELAY_CATEGORIES = [0.02, 0.04, 0.06, 0.08, 0.10]  # Fixed delay categories

class DelayProcessor:
    def __init__(self):
        self.rtt_measurements = defaultdict(list)
        self.delay_measurements = defaultdict(list)
        self.start_time = time.time()
        self.last_plot_time = time.time()
        self.packet_count = 0
        
    def get_delay_category(self, delay):
        """Get the nearest delay category."""
        return min(DELAY_CATEGORIES, key=lambda x: abs(x - delay))
        
    async def process_packet(self, msg):
        try:
            print(f"\nReceived packet on topic: {msg.subject}")
            
            # Parse the Ethernet frame
            eth_frame = Ether(msg.data)
            print(f"Ethernet frame type: 0x{eth_frame.type:04x}")
            
            if eth_frame.type == 0x0800:  # IPv4
                ip_pkt = eth_frame.payload
                print(f"IP protocol: {ip_pkt.proto}")
                if ip_pkt.proto == 1:  # ICMP
                    icmp_pkt = ip_pkt.payload
                    print(f"ICMP type: {icmp_pkt.type}")
            
            # Add random delay
            random_delay = random.uniform(DELAY_RANGE[0], DELAY_RANGE[1])
            delay_category = self.get_delay_category(random_delay)
            print(f"Adding delay of {random_delay:.3f} seconds (category: {delay_category:.3f})")
            # await asyncio.sleep(random_delay)
            
            # Determine output topic based on input topic
            if msg.subject == 'inpktsec':
                output_topic = 'outpktinsec'
            else:
                output_topic = 'outpktsec'
            
            print(f"Publishing to topic: {output_topic}")
            
            # Publish the delayed frame
            await self.nc.publish(output_topic, bytes(eth_frame))
            
            # Record measurements
            self.packet_count += 1
            self.delay_measurements[delay_category].append(random_delay)
            
            # If this is a ping packet, measure RTT
            if eth_frame.type == 0x0800:  # IPv4
                ip_packet = eth_frame.payload
                if ip_packet.proto == 1:  # ICMP
                    self.rtt_measurements[delay_category].append(random_delay * 2)  # RTT is twice the one-way delay
                    print(f"Recorded RTT measurement for delay category {delay_category:.3f}")
            
            print(f"Total packets processed: {self.packet_count}")
            
        except Exception as e:
            print(f"Error processing packet: {str(e)}")
    
    async def plot_results(self):
        if not self.delay_measurements:
            print("No measurements to plot yet")
            return
            
        # Calculate means for categories that have measurements
        delays = []
        mean_rtts = []
        for delay in DELAY_CATEGORIES:
            if delay in self.rtt_measurements and len(self.rtt_measurements[delay]) > 0:
                delays.append(delay)
                mean_rtts.append(sum(self.rtt_measurements[delay]) / len(self.rtt_measurements[delay]))
        
        if not delays:
            print("No RTT measurements collected yet")
            return
            
        # Create plot
        plt.figure(figsize=(10, 6))
        plt.plot(delays, mean_rtts, 'b-', marker='o')
        plt.xlabel('Mean Random Delay (seconds)')
        plt.ylabel('Average RTT (seconds)')
        plt.title('RTT vs Random Delay')
        plt.grid(True)
        plt.savefig('/code/delay-processor/results.png')
        plt.close()
        
        # Save data to JSON
        with open('/code/delay-processor/measurements.json', 'w') as f:
            json.dump({
                'delays': delays,
                'mean_rtts': mean_rtts,
                'raw_measurements': {
                    f"{d:.3f}": {
                        'rtts': self.rtt_measurements[d],
                        'delays': self.delay_measurements[d]
                    } for d in delays
                }
            }, f, indent=2)
        
        print(f"Results updated at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total measurements: {sum(len(rtts) for rtts in self.rtt_measurements.values())} RTTs")
        print("Current measurements:")
        for d in delays:
            print(f"  Delay {d:.3f}s: {len(self.rtt_measurements[d])} RTTs, mean: {sum(self.rtt_measurements[d]) / len(self.rtt_measurements[d]):.3f}s")
        
        # Reset measurements for next period
        self.rtt_measurements = defaultdict(list)
        self.delay_measurements = defaultdict(list)
        self.last_plot_time = time.time()

    async def main(self):
        # Connect to NATS
        self.nc = await nats.connect(NATS_SERVER)
        print(f"Connected to NATS at {NATS_SERVER}")
        
        # Subscribe to input topics (without wildcards)
        await self.nc.subscribe("inpktsec", cb=self.process_packet)
        await self.nc.subscribe("inpktinsec", cb=self.process_packet)
        
        print("Subscribed to input topics: inpktsec, inpktinsec")
        print("Processor is running. Press Ctrl+C to stop.")
        print(f"Using delay categories: {[f'{d:.3f}' for d in DELAY_CATEGORIES]}")
        
        # Run continuously
        try:
            while True:
                current_time = time.time()
                if current_time - self.last_plot_time >= MEASUREMENT_DURATION:
                    await self.plot_results()
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            # Plot final results
            await self.plot_results()
        
        # Close NATS connection
        await self.nc.close()

if __name__ == "__main__":
    processor = DelayProcessor()
    asyncio.run(processor.main()) 