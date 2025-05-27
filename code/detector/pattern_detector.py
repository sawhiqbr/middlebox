"""
Sequence Pattern Detection Module
"""
import time
from collections import deque, defaultdict
from config.detection_config import ANALYSIS_WINDOWS


class PatternDetector:
  def __init__(self):
    # Packet sequence tracking per connection
    self.connection_sequences = defaultdict(lambda: deque(maxlen=100))
    self.active_sessions = {}  # Track potential covert sessions

    # Pattern definitions
    self.covert_patterns = {
        'session_start': ['S', 'A'],     # SA
        'session_end': ['F', 'A'],       # FA
        'bit_one': ['U', 'A'],           # UA
        'bit_zero': ['P', 'A']           # PA
    }

    # Timing analysis
    self.pattern_timings = defaultdict(list)
    self.max_session_gap = 30  # seconds

  async def analyze(self, packet_info):
    """Analyze packet sequences for covert patterns"""
    flags = packet_info['flags']
    timestamp = time.time()

    # Create connection identifier
    conn_id = f"{packet_info['src_ip']}:{packet_info['src_port']}->{packet_info['dst_ip']}:{packet_info['dst_port']}"

    # Add packet to sequence
    packet_data = {
        'flags': flags,
        'timestamp': timestamp,
        'pattern_type': self._classify_packet(flags)
    }

    self.connection_sequences[conn_id].append(packet_data)

    # Analyze patterns
    session_score = self._analyze_session_patterns(conn_id)
    sequence_score = self._analyze_bit_sequences(conn_id)
    timing_score = self._analyze_timing_patterns(conn_id)

    # Combine pattern scores
    final_score = max(session_score, sequence_score * 0.8, timing_score * 0.6)

    return min(final_score, 1.0)

  def _classify_packet(self, flags):
    """Classify packet based on flag combination"""
    flag_set = set(flags)

    for pattern_name, pattern_flags in self.covert_patterns.items():
      if flag_set == set(pattern_flags):
        return pattern_name

    return 'normal'

  def _analyze_session_patterns(self, conn_id):
    """Look for complete covert channel sessions (SA...FA)"""
    sequence = list(self.connection_sequences[conn_id])

    if len(sequence) < 3:  # Need at least start, data, end
      return 0.0

    # Look for session start
    session_starts = [i for i, pkt in enumerate(sequence)
                      if pkt['pattern_type'] == 'session_start']

    if not session_starts:
      return 0.0

    max_score = 0.0

    for start_idx in session_starts:
      # Look for session end after start
      end_indices = [i for i in range(start_idx + 1, len(sequence))
                     if sequence[i]['pattern_type'] == 'session_end']

      if not end_indices:
        continue

      end_idx = end_indices[0]  # First end after start
      session_packets = sequence[start_idx:end_idx + 1]

      # Analyze session content
      data_packets = [pkt for pkt in session_packets
                      if pkt['pattern_type'] in ['bit_one', 'bit_zero']]

      if len(data_packets) >= 2:  # At least 2 data bits
        # Check timing consistency
        session_duration = session_packets[-1]['timestamp'] - session_packets[0]['timestamp']

        if 0.1 < session_duration < 30:  # Reasonable session duration
          score = 0.9  # High confidence for complete session

          # Bonus for more data bits
          if len(data_packets) >= 8:  # Full byte or more
            score = 0.95

          max_score = max(max_score, score)

    return max_score

  def _analyze_bit_sequences(self, conn_id):
    """Look for sequences of bit encoding patterns"""
    sequence = list(self.connection_sequences[conn_id])

    # Look for consecutive bit patterns
    bit_sequences = []
    current_sequence = []

    for packet in sequence:
      if packet['pattern_type'] in ['bit_one', 'bit_zero']:
        current_sequence.append(packet)
      else:
        if len(current_sequence) >= 3:  # At least 3 bits
          bit_sequences.append(current_sequence)
        current_sequence = []

    # Check last sequence
    if len(current_sequence) >= 3:
      bit_sequences.append(current_sequence)

    if not bit_sequences:
      return 0.0

    max_score = 0.0

    for bit_seq in bit_sequences:
      # Check timing regularity
      if len(bit_seq) >= 3:
        intervals = []
        for i in range(1, len(bit_seq)):
          interval = bit_seq[i]['timestamp'] - bit_seq[i-1]['timestamp']
          intervals.append(interval)

        # Check if intervals are relatively consistent (covert channels often have regular timing)
        if intervals:
          avg_interval = sum(intervals) / len(intervals)
          variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)

          # Low variance suggests artificial timing
          if avg_interval > 0.01 and variance < (avg_interval * 0.5) ** 2:
            score = 0.7 + (len(bit_seq) - 3) * 0.05  # More bits = higher score
            max_score = max(max_score, min(score, 0.9))

    return max_score

  def _analyze_timing_patterns(self, conn_id):
    """Analyze timing patterns for artificial regularity"""
    sequence = list(self.connection_sequences[conn_id])

    if len(sequence) < 5:
      return 0.0

    # Get timestamps of covert-pattern packets
    covert_packets = [pkt for pkt in sequence
                      if pkt['pattern_type'] != 'normal']

    if len(covert_packets) < 3:
      return 0.0

    # Calculate inter-arrival times
    intervals = []
    for i in range(1, len(covert_packets)):
      interval = covert_packets[i]['timestamp'] - covert_packets[i-1]['timestamp']
      intervals.append(interval)

    if not intervals:
      return 0.0

    # Check for regular timing (sign of artificial traffic)
    avg_interval = sum(intervals) / len(intervals)

    # Count how many intervals are close to average
    tolerance = avg_interval * 0.3  # 30% tolerance
    regular_intervals = sum(1 for interval in intervals
                            if abs(interval - avg_interval) < tolerance)

    regularity_ratio = regular_intervals / len(intervals)

    # High regularity is suspicious
    if regularity_ratio > 0.7 and avg_interval > 0.01:  # >70% regular and not too fast
      return 0.6
    elif regularity_ratio > 0.5:
      return 0.4

    return 0.0
