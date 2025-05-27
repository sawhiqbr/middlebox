"""
Statistical Analysis Engine
"""
import time
import math
from collections import defaultdict, deque


class StatisticalEngine:
  def __init__(self):
    # Statistical tracking
    self.flag_statistics = defaultdict(lambda: deque(maxlen=1000))
    self.port_statistics = defaultdict(lambda: deque(maxlen=500))
    self.timing_statistics = deque(maxlen=2000)

    # Baseline establishment
    self.baseline_window = 300  # 5 minutes
    self.start_time = time.time()
    self.baseline_established = False
    self.baseline_stats = {}

    # Current window tracking
    self.current_window = deque(maxlen=100)
    self.window_duration = 60  # 1 minute windows

  async def analyze(self, packet_info):
    """Perform statistical analysis on traffic patterns"""
    timestamp = time.time()
    flags = packet_info['flags']

    # Update current window
    self.current_window.append({
        'timestamp': timestamp,
        'flags': flags,
        'port': packet_info['dst_port'],
        'payload_size': packet_info['payload_size']
    })

    # Update statistics
    flag_combo = ''.join(sorted(flags))
    self.flag_statistics[flag_combo].append(timestamp)
    self.port_statistics[packet_info['dst_port']].append(timestamp)
    self.timing_statistics.append(timestamp)

    # Establish baseline if enough time has passed
    if not self.baseline_established and timestamp - self.start_time > self.baseline_window:
      self._establish_baseline()

    if not self.baseline_established:
      return 0.0  # Can't analyze without baseline

    # Perform various statistical analyses
    entropy_score = self._analyze_entropy_anomaly()
    frequency_score = self._analyze_frequency_anomaly(flag_combo)
    distribution_score = self._analyze_distribution_anomaly()
    burst_score = self._analyze_burst_patterns()

    # Combine statistical scores
    final_score = max(
        entropy_score * 0.8,
        frequency_score * 0.7,
        distribution_score * 0.6,
        burst_score * 0.5
    )

    return min(final_score, 1.0)

  def _establish_baseline(self):
    """Establish baseline statistical patterns"""
    current_time = time.time()

    # Calculate baseline flag distribution
    flag_counts = defaultdict(int)
    total_packets = 0

    for flag_combo, timestamps in self.flag_statistics.items():
      count = len([t for t in timestamps if current_time - t < self.baseline_window])
      flag_counts[flag_combo] = count
      total_packets += count

    if total_packets < 50:  # Need minimum data
      return

    # Calculate baseline ratios and entropy
    self.baseline_stats['flag_ratios'] = {
        flag: count / total_packets
        for flag, count in flag_counts.items()
    }

    # Calculate baseline entropy
    entropy = 0
    for ratio in self.baseline_stats['flag_ratios'].values():
      if ratio > 0:
        entropy -= ratio * math.log2(ratio)

    self.baseline_stats['entropy'] = entropy
    self.baseline_stats['total_packets'] = total_packets

    # Calculate baseline port distribution
    port_counts = defaultdict(int)
    for port, timestamps in self.port_statistics.items():
      count = len([t for t in timestamps if current_time - t < self.baseline_window])
      port_counts[port] = count

    self.baseline_stats['port_counts'] = dict(port_counts)

    self.baseline_established = True
    print(f"Statistical baseline established: {len(flag_counts)} flag types, entropy={entropy:.2f}")

  def _analyze_entropy_anomaly(self):
    """Detect entropy anomalies in flag distribution"""
    if len(self.current_window) < 20:
      return 0.0

    # Calculate current entropy
    flag_counts = defaultdict(int)
    for packet in self.current_window:
      flag_combo = ''.join(sorted(packet['flags']))
      flag_counts[flag_combo] += 1

    total = len(self.current_window)
    current_entropy = 0

    for count in flag_counts.values():
      ratio = count / total
      if ratio > 0:
        current_entropy -= ratio * math.log2(ratio)

    baseline_entropy = self.baseline_stats['entropy']

    # Low entropy suggests repetitive patterns (suspicious)
    entropy_ratio = current_entropy / baseline_entropy if baseline_entropy > 0 else 1.0

    if entropy_ratio < 0.3:  # Very low entropy
      return 0.8
    elif entropy_ratio < 0.5:  # Low entropy
      return 0.6
    elif entropy_ratio < 0.7:  # Somewhat low entropy
      return 0.3

    return 0.0

  def _analyze_frequency_anomaly(self, current_flag_combo):
    """Detect frequency anomalies for specific flag combinations"""
    baseline_ratios = self.baseline_stats['flag_ratios']

    # Count current occurrences in recent window
    current_time = time.time()
    recent_timestamps = self.flag_statistics[current_flag_combo]

    recent_count = len([t for t in recent_timestamps if current_time - t < 60])  # Last minute

    if recent_count < 3:
      return 0.0

    current_rate = recent_count / 60.0  # per second
    baseline_ratio = baseline_ratios.get(current_flag_combo, 0)
    baseline_rate = baseline_ratio * self.baseline_stats['total_packets'] / self.baseline_window

    # Check for significant increase
    if baseline_rate == 0 and current_rate > 0.05:  # New pattern appearing frequently
      return 0.9
    elif baseline_rate > 0:
      rate_increase = current_rate / baseline_rate
      if rate_increase > 10:  # 10x increase
        return 0.8
      elif rate_increase > 5:  # 5x increase
        return 0.6
      elif rate_increase > 3:  # 3x increase
        return 0.4

    return 0.0

  def _analyze_distribution_anomaly(self):
    """Detect anomalies in overall traffic distribution"""
    if len(self.current_window) < 30:
      return 0.0

    # Analyze port distribution in current window
    current_ports = defaultdict(int)
    for packet in self.current_window:
      current_ports[packet['port']] += 1

    # Check for concentration on unusual ports
    high_ports = {port: count for port, count in current_ports.items() if port > 30000}

    if high_ports:
      high_port_packets = sum(high_ports.values())
      concentration = high_port_packets / len(self.current_window)

      if concentration > 0.7:  # >70% traffic to high ports
        return 0.7
      elif concentration > 0.5:  # >50% traffic to high ports
        return 0.5

    return 0.0

  def _analyze_burst_patterns(self):
    """Detect artificial burst patterns"""
    if len(self.timing_statistics) < 10:
      return 0.0

    # Analyze recent packet timings
    recent_times = list(self.timing_statistics)[-50:]  # Last 50 packets

    if len(recent_times) < 10:
      return 0.0

    # Calculate inter-arrival times
    intervals = []
    for i in range(1, len(recent_times)):
      interval = recent_times[i] - recent_times[i-1]
      intervals.append(interval)

    if not intervals:
      return 0.0

    # Check for artificially regular timing
    avg_interval = sum(intervals) / len(intervals)
    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)

    # Low variance suggests artificial timing
    if avg_interval > 0.01 and std_dev / avg_interval < 0.3:  # Low coefficient of variation
      # Check if this is part of a burst
      burst_packets = len([interval for interval in intervals if interval < avg_interval * 2])

      if burst_packets / len(intervals) > 0.8:  # >80% of packets in burst pattern
        return 0.6

    return 0.0
