"""
TCP Flags Anomaly Detection Module
"""
import time
from collections import defaultdict, deque
from config.detection_config import COVERT_FLAGS, NORMAL_FLAGS, DETECTION_THRESHOLDS


class TCPFlagsAnalyzer:
  def __init__(self):
    # Flag statistics tracking
    self.flag_counts = defaultdict(int)
    self.total_packets = 0

    # Covert flag patterns tracking
    self.covert_flag_sequences = defaultdict(int)
    self.suspicious_ports = defaultdict(int)

    # Time-based analysis
    self.recent_flags = deque(maxlen=1000)  # Keep recent 1000 packets
    self.analysis_window = 60  # seconds

    # Baseline establishment
    self.baseline_period = 300  # 5 minutes to establish baseline
    self.start_time = time.time()
    self.baseline_flag_ratios = {}
    self.baseline_established = False

  async def analyze(self, packet_info):
    """Main analysis function for TCP flags"""
    flags = packet_info['flags']
    timestamp = time.time()

    # Update statistics
    self.total_packets += 1
    flag_combination = ''.join(sorted(flags))
    self.flag_counts[flag_combination] += 1

    # Add to recent packets for time-based analysis
    self.recent_flags.append({
        'flags': flags,
        'timestamp': timestamp,
        'port': packet_info['dst_port'],
        'src_ip': packet_info['src_ip'],
        'dst_ip': packet_info['dst_ip']
    })

    # Establish baseline if needed
    if not self.baseline_established and timestamp - self.start_time > self.baseline_period:
      self._establish_baseline()

    # Calculate suspicion scores
    covert_flag_score = self._analyze_covert_flags(flags)
    unusual_flag_score = self._analyze_unusual_flags(flag_combination)
    port_suspicion_score = self._analyze_suspicious_ports(packet_info)
    frequency_score = self._analyze_flag_frequency()

    # Combine scores with weights
    final_score = (
        0.4 * covert_flag_score +
        0.3 * unusual_flag_score +
        0.2 * port_suspicion_score +
        0.1 * frequency_score
    )

    return min(final_score, 1.0)

  def _analyze_covert_flags(self, flags):
    """Detect known covert channel flag combinations"""
    flag_set = set(flags)

    # Check for exact covert channel signatures
    if flag_set == {'S', 'A'}:  # Start session
      return 0.9
    elif flag_set == {'F', 'A'}:  # End session
      return 0.9
    elif flag_set == {'U', 'A'}:  # Bit 1
      return 0.95
    elif flag_set == {'P', 'A'}:  # Bit 0
      return 0.95

    # Check for partial matches or suspicious combinations
    if 'U' in flags and len(flags) == 2:  # URG with one other flag
      return 0.7
    elif 'P' in flags and 'A' in flags and len(flags) == 2:  # PSH+ACK only
      return 0.6

    return 0.0

  def _analyze_unusual_flags(self, flag_combination):
    """Analyze how unusual this flag combination is"""
    if not self.baseline_established:
      return 0.0

    # Compare against baseline
    current_ratio = self.flag_counts[flag_combination] / self.total_packets
    baseline_ratio = self.baseline_flag_ratios.get(flag_combination, 0)

    # If this combination is much more frequent than baseline
    if baseline_ratio == 0 and current_ratio > 0.01:  # New unusual pattern
      return 0.8
    elif baseline_ratio > 0 and current_ratio > baseline_ratio * 5:  # 5x increase
      return 0.6

    return 0.0

  def _analyze_suspicious_ports(self, packet_info):
    """Analyze if the destination port shows suspicious patterns"""
    port = packet_info['dst_port']

    # Track unusual flag usage per port
    self.suspicious_ports[port] += 1

    # High-numbered ports with unusual flags are suspicious
    if port > 30000:
      recent_port_packets = [p for p in self.recent_flags
                             if p['port'] == port and
                             time.time() - p['timestamp'] < 300]  # Last 5 minutes

      if len(recent_port_packets) > 10:  # Many packets to this port
        covert_flag_count = sum(1 for p in recent_port_packets
                                if set(p['flags']) in [{'U', 'A'}, {'P', 'A'}, {'S', 'A'}, {'F', 'A'}])

        if covert_flag_count / len(recent_port_packets) > 0.5:  # >50% covert flags
          return 0.8

    return 0.0

  def _analyze_flag_frequency(self):
    """Analyze frequency patterns of flag usage"""
    if len(self.recent_flags) < 50:  # Need enough data
      return 0.0

    # Calculate entropy of flag combinations in recent window
    recent_window = [p for p in self.recent_flags
                     if time.time() - p['timestamp'] < self.analysis_window]

    if len(recent_window) < 10:
      return 0.0

    # Count flag combinations in recent window
    flag_counts = defaultdict(int)
    for packet in recent_window:
      flag_combo = ''.join(sorted(packet['flags']))
      flag_counts[flag_combo] += 1

    # Calculate entropy (lower entropy = more repetitive = more suspicious)
    total = len(recent_window)
    entropy = 0
    for count in flag_counts.values():
      p = count / total
      if p > 0:
        entropy -= p * (p.bit_length() - 1)  # Simple entropy calculation

    # Low entropy (repetitive patterns) is suspicious
    if entropy < 1.0:  # Very repetitive
      return 0.7
    elif entropy < 2.0:  # Somewhat repetitive
      return 0.4

    return 0.0

  def _establish_baseline(self):
    """Establish baseline flag distribution"""
    if self.total_packets < 100:  # Need minimum packets
      return

    # Calculate baseline ratios
    for flag_combo, count in self.flag_counts.items():
      self.baseline_flag_ratios[flag_combo] = count / self.total_packets

    self.baseline_established = True
    print(f"TCP Flags baseline established with {self.total_packets} packets")
    print(f"Baseline flag ratios: {dict(self.baseline_flag_ratios)}")
