"""
Main detector orchestrator for TCP flags covert channel detection
"""
import os
import asyncio
import json
import logging
import time
import random
import matplotlib.pyplot as plt
from datetime import datetime
from collections import defaultdict
import nats
from scapy.all import Ether, IP, TCP

from config.detection_config import *
from tcp_flags_analyzer import TCPFlagsAnalyzer
from pattern_detector import PatternDetector
from behavior_analyzer import BehaviorAnalyzer
from statistical_engine import StatisticalEngine
from alert_manager import AlertManager

# Delay Configuration
DELAY_RANGE = (0, 0.1)  # Delay range in seconds
MEASUREMENT_DURATION = 60  # Duration to collect measurements
DELAY_CATEGORIES = [0.02, 0.04, 0.06, 0.08, 0.10]  # Fixed delay categories


class CovertChannelDetector:
  def __init__(self):
    self.setup_logging()

    # Initialize detection modules
    self.tcp_flags_analyzer = TCPFlagsAnalyzer()
    self.pattern_detector = PatternDetector()
    self.behavior_analyzer = BehaviorAnalyzer()
    self.statistical_engine = StatisticalEngine()
    self.alert_manager = AlertManager()

    # Statistics
    self.packets_processed = 0
    self.alerts_generated = 0
    self.start_time = datetime.now()

    # Delay processing statistics
    self.rtt_measurements = defaultdict(list)
    self.delay_measurements = defaultdict(list)
    self.last_plot_time = time.time()

    self.logger.info("Covert Channel Detector initialized")

  def setup_logging(self):
    """Setup logging configuration"""
    # Enhanced logging setup with debug level
    logging.basicConfig(
        level=logging.DEBUG,  # Set to DEBUG for detailed logs
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/results/detector.log'),
            logging.StreamHandler()
        ]
    )
    self.logger = logging.getLogger('CovertDetector')
    self.logger.info("Logging system initialized")

  def get_delay_category(self, delay):
    """Get the nearest delay category"""
    return min(DELAY_CATEGORIES, key=lambda x: abs(x - delay))

  async def process_packet(self, msg):
    """Main packet processing pipeline"""
    try:
      self.packets_processed += 1

      # Log every packet received (first 20 packets for debugging)
      if self.packets_processed <= 20:
        self.logger.info(f"Received packet #{self.packets_processed} on topic: {msg.subject}")
        self.logger.debug(f"Raw data length: {len(msg.data)} bytes")

      # Parse Ethernet frame
      try:
        eth_frame = Ether(msg.data)
        if self.packets_processed <= 5:
          self.logger.debug(f"   Ethernet type: 0x{eth_frame.type:04x}")
      except Exception as e:
        self.logger.error(f"Failed to parse Ethernet frame: {e}")
        await self.forward_packet_with_delay(msg, eth_frame)
        return

      # Generate random delay for this packet
      random_delay = random.uniform(DELAY_RANGE[0], DELAY_RANGE[1])
      delay_category = self.get_delay_category(random_delay)

      if self.packets_processed <= 10:
        self.logger.debug(f"Adding delay: {random_delay:.3f}s (category: {delay_category:.3f})")

      # Record delay measurements
      self.delay_measurements[delay_category].append(random_delay)

      # Only process IPv4 TCP packets for detection
      if eth_frame.type != 0x0800:  # Not IPv4
        if self.packets_processed <= 5:
          self.logger.debug(f"Skipping non-IPv4 packet (type: 0x{eth_frame.type:04x})")
        await self.forward_packet_with_delay(msg, eth_frame, random_delay)
        return

      try:
        ip_packet = eth_frame.payload
        if not isinstance(ip_packet, IP):
          self.logger.debug(f"Payload is not IP packet")
          await self.forward_packet_with_delay(msg, eth_frame, random_delay)
          return

        # Record RTT for ICMP (ping) packets
        if ip_packet.proto == 1:  # ICMP
          self.rtt_measurements[delay_category].append(random_delay * 2)
          if self.packets_processed <= 10:
            self.logger.debug(f"Recorded RTT measurement for category {delay_category:.3f}")

        if ip_packet.proto != 6:  # Not TCP
          if self.packets_processed <= 5:
            self.logger.debug(f"Skipping non-TCP packet (proto: {ip_packet.proto})")
          await self.forward_packet_with_delay(msg, eth_frame, random_delay)
          return
      except Exception as e:
        self.logger.error(f"Failed to parse IP packet: {e}")
        await self.forward_packet_with_delay(msg, eth_frame, random_delay)
        return

      try:
        tcp_packet = ip_packet.payload
        if not isinstance(tcp_packet, TCP):
          self.logger.debug(f"TCP payload parsing failed")
          await self.forward_packet_with_delay(msg, eth_frame, random_delay)
          return
      except Exception as e:
        self.logger.error(f"Failed to parse TCP packet: {e}")
        await self.forward_packet_with_delay(msg, eth_frame, random_delay)
        return

      # Log TCP packet details
      self.logger.info(
          f"Processing TCP packet: {ip_packet.src}:{tcp_packet.sport} -> {ip_packet.dst}:{tcp_packet.dport}")

      # Extract TCP flags
      flags = self.extract_tcp_flags(tcp_packet)
      self.logger.info(f"TCP Flags: {flags}")

      # Extract packet metadata
      packet_info = {
          'timestamp': datetime.now(),
          'src_ip': ip_packet.src,
          'dst_ip': ip_packet.dst,
          'src_port': tcp_packet.sport,
          'dst_port': tcp_packet.dport,
          'flags': flags,
          'payload_size': len(tcp_packet.payload) if tcp_packet.payload else 0,
          'direction': 'sec_to_insec' if msg.subject == 'inpktsec' else 'insec_to_sec',
          'delay_applied': random_delay,
          'delay_category': delay_category
      }

      # Log packet analysis start
      self.logger.debug(f"Starting detection analysis...")

      # Run detection algorithms
      detection_scores = await self.run_detection_analysis(packet_info)
      self.logger.debug(f"Detection scores: {detection_scores}")

      # Calculate combined score
      combined_score = self.calculate_combined_score(detection_scores)
      self.logger.info(f"Combined score: {combined_score:.3f}")

      # Check if alert should be generated
      threshold = DETECTION_THRESHOLDS['combined_score']
      if combined_score >= threshold:
        self.logger.warning(
            f"ALERT TRIGGERED! Score {combined_score:.3f} >= threshold {threshold}")
        await self.generate_alert(packet_info, detection_scores, combined_score)
      else:
        self.logger.debug(f"No alert (score {combined_score:.3f} < {threshold})")

      MITIGATION_THRESHOLD = DETECTION_THRESHOLDS['mitigation_score']
      if combined_score > MITIGATION_THRESHOLD and MITIGATION_ENABLED:
        self.logger.warning(
            f"DROPPING packet - Score: {combined_score:.3f} > {MITIGATION_THRESHOLD}")
        return  # Drop packet

      # Forward the packet with delay (detector works inline)
      await self.forward_packet_with_delay(msg, eth_frame, random_delay)
      self.logger.debug(f"Packet forwarded with {random_delay:.3f}s delay")

      # Log periodic statistics
      if self.packets_processed % 10 == 0:
        self.log_statistics()

    except Exception as e:
      self.logger.error(f"Error processing packet: {str(e)}")
      import traceback
      self.logger.error(f"Traceback: {traceback.format_exc()}")
      # Still forward the packet even if detection fails
      await self.forward_packet_with_delay(msg, None, 0.0)

  async def forward_packet_with_delay(self, msg, eth_frame=None, delay=0.0):
    """Forward packet with random delay injection"""
    try:
      # Apply the delay
      if delay > 0:
        await asyncio.sleep(delay)

      # Determine output topic
      if msg.subject == 'inpktsec':
        output_topic = 'outpktinsec'
      else:
        output_topic = 'outpktsec'

      # Forward the packet
      if eth_frame is not None:
        await self.nc.publish(output_topic, bytes(eth_frame))
      else:
        await self.nc.publish(output_topic, msg.data)

      if self.packets_processed <= 5:
        self.logger.debug(f"Forwarded {msg.subject} -> {output_topic}")

    except Exception as e:
      self.logger.error(f"Failed to forward packet: {e}")

  def extract_tcp_flags(self, tcp_packet):
    """Extract TCP flags as string list"""
    flags = []
    try:
      if tcp_packet.flags.S:
        flags.append('S')  # SYN
      if tcp_packet.flags.A:
        flags.append('A')  # ACK
      if tcp_packet.flags.F:
        flags.append('F')  # FIN
      if tcp_packet.flags.R:
        flags.append('R')  # RST
      if tcp_packet.flags.P:
        flags.append('P')  # PSH
      if tcp_packet.flags.U:
        flags.append('U')  # URG

      self.logger.debug(f"Flag details: S={tcp_packet.flags.S}, A={tcp_packet.flags.A}, "
                        f"F={tcp_packet.flags.F}, R={tcp_packet.flags.R}, "
                        f"P={tcp_packet.flags.P}, U={tcp_packet.flags.U}")
    except Exception as e:
      self.logger.error(f"Error extracting flags: {e}")

    return flags

  async def run_detection_analysis(self, packet_info):
    """Run all detection algorithms and return scores"""
    scores = {}

    try:
      # TCP Flags Analysis
      self.logger.debug("Running TCP flags analysis...")
      scores['tcp_flags'] = await self.tcp_flags_analyzer.analyze(packet_info)
      self.logger.debug(f"TCP flags score: {scores['tcp_flags']:.3f}")

      # Pattern Detection
      self.logger.debug("Running pattern detection...")
      scores['pattern'] = await self.pattern_detector.analyze(packet_info)
      self.logger.debug(f"Pattern score: {scores['pattern']:.3f}")

      # Behavior Analysis
      self.logger.debug("Running behavior analysis...")
      scores['behavior'] = await self.behavior_analyzer.analyze(packet_info)
      self.logger.debug(f"Behavior score: {scores['behavior']:.3f}")

      # Statistical Analysis
      self.logger.debug("Running statistical analysis...")
      scores['statistical'] = await self.statistical_engine.analyze(packet_info)
      self.logger.debug(f"Statistical score: {scores['statistical']:.3f}")

    except Exception as e:
      self.logger.error(f"Error in detection analysis: {e}")
      # Set default scores if analysis fails
      scores = {'tcp_flags': 0.0, 'pattern': 0.0, 'behavior': 0.0, 'statistical': 0.0}

    return scores

  def calculate_combined_score(self, scores):
    """Calculate weighted combined detection score"""
    weights = {
        'tcp_flags': 0.4,
        'pattern': 0.3,
        'behavior': 0.2,
        'statistical': 0.1
    }

    combined = sum(scores[key] * weights[key] for key in weights if key in scores)
    combined = min(combined, 1.0)  # Cap at 1.0

    self.logger.debug(f"      Score calculation: "
                      f"TCP({scores.get('tcp_flags', 0):.3f})*0.4 + "
                      f"Pattern({scores.get('pattern', 0):.3f})*0.3 + "
                      f"Behavior({scores.get('behavior', 0):.3f})*0.2 + "
                      f"Statistical({scores.get('statistical', 0):.3f})*0.1 = {combined:.3f}")

    return combined

  async def generate_alert(self, packet_info, scores, combined_score):
    """Generate and publish detection alert"""
    self.alerts_generated += 1
    self.logger.warning(f"GENERATING ALERT #{self.alerts_generated}")
    await self.alert_manager.generate_alert(packet_info, scores, combined_score)

  async def plot_delay_results(self):
    """Plot delay analysis results (from Phase 2)"""
    if not self.delay_measurements:
      self.logger.info("No delay measurements to plot yet")
      return

    # Calculate means for categories that have measurements
    delays = []
    mean_values = []

    for delay in DELAY_CATEGORIES:
      if delay in self.rtt_measurements and len(self.rtt_measurements[delay]) > 0:
        delays.append(delay)
        mean_values.append(sum(self.rtt_measurements[delay]) / len(self.rtt_measurements[delay]))
      elif delay in self.delay_measurements and len(self.delay_measurements[delay]) > 0:
        delays.append(delay)
        # For delay measurements, use the actual delay values
        mean_values.append(
            sum(self.delay_measurements[delay]) / len(self.delay_measurements[delay]))
        measurement_type = "Delay"

    if not delays:
      self.logger.info("No RTT measurements collected yet")
      return

    # Create plot
    plt.figure(figsize=(10, 6))
    plt.plot(delays, mean_values, 'b-', marker='o')
    plt.xlabel('Mean Random Delay (seconds)')
    plt.ylabel(f'Average {measurement_type} (seconds)')
    plt.title(f'{measurement_type} vs Random Delay Categories (Covert Channel Detector)')
    plt.grid(True)
    plt.savefig('/results/delay_analysis.png')
    plt.close()

    # Save data to JSON
    with open('/results/delay_measurements.json', 'w') as f:
      json.dump({
          'delays': delays,
          f'mean_{measurement_type.lower()}s': mean_values,
          'detection_stats': {
              'packets_processed': self.packets_processed,
              'alerts_generated': self.alerts_generated
          },
          'raw_measurements': {
              f"{d:.3f}": {
                  'rtts': self.rtt_measurements[d],
                  'delays': self.delay_measurements[d]
              } for d in delays
          }
      }, f, indent=2)

    self.logger.info(f"Delay analysis updated: {len(delays)} categories, "
                     f"{sum(len(self.rtt_measurements.get(d, [])) for d in delays)} RTT measurements, "
                     f"{sum(len(self.delay_measurements.get(d, [])) for d in delays)} delay measurements")

    # Reset measurements for next period
    self.rtt_measurements = defaultdict(list)
    self.delay_measurements = defaultdict(list)
    self.last_plot_time = time.time()

  def log_statistics(self):
    """Log periodic statistics"""
    uptime = (datetime.now() - self.start_time).total_seconds()
    rate = self.packets_processed/uptime if uptime > 0 else 0
    self.logger.info(
        f"Stats: {self.packets_processed} packets, "
        f"{self.alerts_generated} alerts, "
        f"{uptime:.1f}s uptime, "
        f"{rate:.2f} pkt/s"
    )

  def should_drop_packet(self, packet_info):
    """Simple mitigation: drop covert packets"""
    if (packet_info.get('dst_port') == 31337 and
            packet_info.get('flags') in [['S', 'A'], ['U', 'A'], ['P', 'A'], ['F', 'A']]):
      return True
    return False

  async def main(self):
    """Main detector loop"""
    try:
      self.logger.info("Starting NATS connection...")

      # Connect to NATS
      nats_server = os.getenv('NATS_SURVEYOR_SERVERS', NATS_SERVER)
      self.logger.info(f"Connecting to: {nats_server}")

      self.nc = await nats.connect(nats_server)
      self.logger.info(f"Connected to NATS at {nats_server}")

      # Subscribe to input topics
      self.logger.info("Setting up subscriptions...")
      await self.nc.subscribe("inpktsec", cb=self.process_packet)
      await self.nc.subscribe("inpktinsec", cb=self.process_packet)

      self.logger.info("Subscribed to input topics: inpktsec, inpktinsec")
      self.logger.info("Covert Channel Detector is running and ready!")
      self.logger.info("Waiting for packets...")

      # Main loop
      try:
        while True:
          await asyncio.sleep(10)

          if self.packets_processed == 0:
            self.logger.info("Detector alive, waiting for packets...")

          # Periodic delay analysis
          # current_time = time.time()
          # if current_time - self.last_plot_time >= MEASUREMENT_DURATION:
          #   await self.plot_delay_results()

      except KeyboardInterrupt:
        self.logger.info("Detector stopping...")
        # Plot final delay results
        # await self.plot_delay_results()

    except Exception as e:
      self.logger.error(f"Detector error: {str(e)}")
      import traceback
      self.logger.error(f"Traceback: {traceback.format_exc()}")
    finally:
      # await self.plot_delay_results()
      if hasattr(self, 'nc'):
        await self.nc.close()
        self.logger.info("NATS connection closed")


if __name__ == "__main__":
  print("Starting Covert Channel Detector...")
  detector = CovertChannelDetector()
  asyncio.run(detector.main())
