"""
Main detector orchestrator for TCP flags covert channel detection
"""
import os
import asyncio
import json
import logging
from datetime import datetime
import nats
from scapy.all import Ether, IP, TCP

from config.detection_config import *
from tcp_flags_analyzer import TCPFlagsAnalyzer
from pattern_detector import PatternDetector
from behavior_analyzer import BehaviorAnalyzer
from statistical_engine import StatisticalEngine
from alert_manager import AlertManager


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

    self.logger.info("Covert Channel Detector initialized")

  def setup_logging(self):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, LOG_CONFIG['level']),
        format=LOG_CONFIG['format'],
        handlers=[
            logging.FileHandler(LOG_CONFIG['file']),
            logging.StreamHandler()
        ]
    )
    self.logger = logging.getLogger('CovertDetector')

  async def process_packet(self, msg):
    """Main packet processing pipeline"""
    try:
      self.packets_processed += 1

      # Parse Ethernet frame
      eth_frame = Ether(msg.data)

      # Only process IPv4 TCP packets
      if eth_frame.type != 0x0800:  # Not IPv4
        await self.forward_packet(msg)
        return

      ip_packet = eth_frame.payload
      if not isinstance(ip_packet, IP) or ip_packet.proto != 6:  # Not TCP
        await self.forward_packet(msg)
        return

      tcp_packet = ip_packet.payload
      if not isinstance(tcp_packet, TCP):
        await self.forward_packet(msg)
        return

      self.logger.debug(
          f"Processing TCP packet: {ip_packet.src}:{tcp_packet.sport} -> {ip_packet.dst}:{tcp_packet.dport}")

      # Extract packet metadata
      packet_info = {
          'timestamp': datetime.now(),
          'src_ip': ip_packet.src,
          'dst_ip': ip_packet.dst,
          'src_port': tcp_packet.sport,
          'dst_port': tcp_packet.dport,
          'flags': self.extract_tcp_flags(tcp_packet),
          'payload_size': len(tcp_packet.payload) if tcp_packet.payload else 0,
          'direction': 'sec_to_insec' if msg.subject == 'inpktsec' else 'insec_to_sec'
      }

      # Run detection algorithms
      detection_scores = await self.run_detection_analysis(packet_info)

      # Calculate combined score
      combined_score = self.calculate_combined_score(detection_scores)

      # Check if alert should be generated
      if combined_score >= DETECTION_THRESHOLDS['combined_score']:
        await self.generate_alert(packet_info, detection_scores, combined_score)

      # Forward the packet (detector works inline)
      await self.forward_packet(msg)

      # Log periodic statistics
      if self.packets_processed % 100 == 0:
        self.log_statistics()

    except Exception as e:
      self.logger.error(f"Error processing packet: {str(e)}")
      # Still forward the packet even if detection fails
      await self.forward_packet(msg)

  def extract_tcp_flags(self, tcp_packet):
    """Extract TCP flags as string list"""
    flags = []
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
    return flags

  async def run_detection_analysis(self, packet_info):
    """Run all detection algorithms and return scores"""
    scores = {}

    # TCP Flags Analysis
    scores['tcp_flags'] = await self.tcp_flags_analyzer.analyze(packet_info)

    # Pattern Detection
    scores['pattern'] = await self.pattern_detector.analyze(packet_info)

    # Behavior Analysis
    scores['behavior'] = await self.behavior_analyzer.analyze(packet_info)

    # Statistical Analysis
    scores['statistical'] = await self.statistical_engine.analyze(packet_info)

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
    return min(combined, 1.0)  # Cap at 1.0

  async def generate_alert(self, packet_info, scores, combined_score):
    """Generate and publish detection alert"""
    self.alerts_generated += 1
    await self.alert_manager.generate_alert(packet_info, scores, combined_score)

  async def forward_packet(self, msg):
    """Forward packet to appropriate output topic"""
    if msg.subject == 'inpktsec':
      output_topic = 'outpktinsec'
    else:
      output_topic = 'outpktsec'

    await self.nc.publish(output_topic, msg.data)

  def log_statistics(self):
    """Log periodic statistics"""
    uptime = (datetime.now() - self.start_time).total_seconds()
    self.logger.info(
        f"Stats: {self.packets_processed} packets, "
        f"{self.alerts_generated} alerts, "
        f"{uptime:.1f}s uptime, "
        f"{self.packets_processed/uptime:.2f} pkt/s"
    )

  async def main(self):
    """Main detector loop"""
    try:
      # Connect to NATS
      nats_server = os.getenv('NATS_SURVEYOR_SERVERS', NATS_SERVER)
      self.nc = await nats.connect(nats_server)
      self.logger.info(f"Connected to NATS at {nats_server}")

      # Subscribe to input topics
      await self.nc.subscribe("inpktsec", cb=self.process_packet)
      await self.nc.subscribe("inpktinsec", cb=self.process_packet)

      self.logger.info("Subscribed to input topics: inpktsec, inpktinsec")
      self.logger.info("Covert Channel Detector is running...")

      # Keep running
      while True:
        await asyncio.sleep(1)

    except KeyboardInterrupt:
      self.logger.info("Detector stopping...")
    except Exception as e:
      self.logger.error(f"Detector error: {str(e)}")
    finally:
      if hasattr(self, 'nc'):
        await self.nc.close()


if __name__ == "__main__":
  detector = CovertChannelDetector()
  asyncio.run(detector.main())
