"""
Protocol Behavior Analysis Module
"""
import time
from collections import defaultdict
from config.detection_config import ANALYSIS_WINDOWS


class BehaviorAnalyzer:
  def __init__(self):
    # Connection state tracking
    self.connections = defaultdict(lambda: {
        'state': 'INIT',
        'packets': [],
        'handshake_complete': False,
        'data_transferred': 0,
        'flags_seen': set(),
        'start_time': time.time(),
        'last_packet': time.time()
    })

    # Cleanup old connections periodically
    self.last_cleanup = time.time()
    self.cleanup_interval = 300  # 5 minutes

  async def analyze(self, packet_info):
    """Analyze TCP connection behavior for anomalies"""
    flags = packet_info['flags']
    timestamp = time.time()

    # Create connection identifier (bidirectional)
    conn_key = self._get_connection_key(packet_info)

    # Cleanup old connections
    if timestamp - self.last_cleanup > self.cleanup_interval:
      self._cleanup_old_connections(timestamp)
      self.last_cleanup = timestamp

    # Update connection state
    conn = self.connections[conn_key]
    conn['packets'].append({
        'flags': flags,
        'timestamp': timestamp,
        'payload_size': packet_info['payload_size'],
        'direction': packet_info['direction']
    })
    conn['flags_seen'].update(flags)
    conn['last_packet'] = timestamp
    conn['data_transferred'] += packet_info['payload_size']

    # Analyze various behavioral aspects
    handshake_score = self._analyze_handshake_behavior(conn, flags)
    payload_score = self._analyze_payload_behavior(conn)
    flag_usage_score = self._analyze_flag_usage_behavior(conn)
    connection_pattern_score = self._analyze_connection_patterns(conn)

    # Combine behavior scores
    final_score = max(
        handshake_score * 0.8,
        payload_score * 0.7,
        flag_usage_score * 0.9,
        connection_pattern_score * 0.6
    )

    return min(final_score, 1.0)

  def _get_connection_key(self, packet_info):
    """Create bidirectional connection key"""
    src = f"{packet_info['src_ip']}:{packet_info['src_port']}"
    dst = f"{packet_info['dst_ip']}:{packet_info['dst_port']}"

    # Normalize to make bidirectional
    if src < dst:
      return f"{src}<->{dst}"
    else:
      return f"{dst}<->{src}"

  def _analyze_handshake_behavior(self, conn, current_flags):
    """Analyze TCP handshake compliance"""
    packets = conn['packets']

    if len(packets) < 2:
      return 0.0

    # Check for proper TCP handshake
    if len(packets) >= 3:
      first_flags = set(packets[0]['flags'])
      second_flags = set(packets[1]['flags'])
      third_flags = set(packets[2]['flags'])

      # Normal handshake: SYN -> SYN+ACK -> ACK
      expected_handshake = (
          first_flags == {'S'} and
          second_flags == {'S', 'A'} and
          third_flags == {'A'}
      )

      if expected_handshake:
        conn['handshake_complete'] = True
        return 0.0  # Normal behavior

    # Check for suspicious patterns
    flag_set = set(current_flags)

    # Unusual flag combinations that skip handshake
    if flag_set in [{'U', 'A'}, {'P', 'A'}] and not conn['handshake_complete']:
      return 0.8  # High suspicion - data flags without handshake

    # SA flags without proper handshake sequence
    if flag_set == {'S', 'A'} and len(packets) > 1:
      # Check if this looks like a proper SYN+ACK response
      if packets[0]['flags'] != ['S']:  # First packet wasn't SYN
        return 0.7

    return 0.0

  def _analyze_payload_behavior(self, conn):
    """Analyze payload patterns for suspicious behavior"""
    packets = conn['packets']

    if len(packets) < 5:
      return 0.0

    # Count packets with actual payload
    payload_packets = [p for p in packets if p['payload_size'] > 0]
    control_packets = [p for p in packets if p['payload_size'] == 0]

    total_packets = len(packets)

    # Suspicious: many control packets with unusual flags but no data
    if total_packets > 10:
      control_ratio = len(control_packets) / total_packets

      # Count unusual flag packets
      unusual_flag_packets = [
          p for p in control_packets
          if set(p['flags']) in [{'U', 'A'}, {'P', 'A'}, {'S', 'A'}, {'F', 'A'}]
      ]

      if len(unusual_flag_packets) > 5 and control_ratio > 0.8:
        return 0.8  # Many control packets with unusual flags

    # Check for consistent zero-payload patterns
    recent_packets = packets[-20:]  # Last 20 packets
    if len(recent_packets) >= 10:
      zero_payload_count = sum(1 for p in recent_packets if p['payload_size'] == 0)
      if zero_payload_count / len(recent_packets) > 0.9:  # >90% zero payload
        return 0.6

    return 0.0

  def _analyze_flag_usage_behavior(self, conn):
    """Analyze unusual flag usage patterns"""
    packets = conn['packets']
    flags_seen = conn['flags_seen']

    # Suspicious flag combinations
    suspicious_flags = {'U', 'P'}  # URG and PSH flags

    if suspicious_flags.issubset(flags_seen):
      # Both URG and PSH seen - unusual for normal traffic
      urg_count = sum(1 for p in packets if 'U' in p['flags'])
      psh_count = sum(1 for p in packets if 'P' in p['flags'])

      if urg_count > 2 or psh_count > 5:  # Frequent unusual flag usage
        return 0.7

    # Check for flags that rarely appear together in normal traffic
    if 'U' in flags_seen and len(packets) > 3:
      urg_packets = [p for p in packets if 'U' in p['flags']]
      # URG flag with only ACK (UA combination)
      ua_packets = [p for p in urg_packets if set(p['flags']) == {'U', 'A'}]

      if len(ua_packets) > 2:  # Multiple UA combinations
        return 0.8

    return 0.0

  def _analyze_connection_patterns(self, conn):
    """Analyze overall connection patterns"""
    packets = conn['packets']

    if len(packets) < 3:
      return 0.0

    # Check for short-lived connections with unusual activity
    connection_duration = conn['last_packet'] - conn['start_time']

    if connection_duration < 60:  # Short connection
      # Count different flag types used
      unique_flag_combinations = set()
      for p in packets:
        flag_combo = tuple(sorted(p['flags']))
        unique_flag_combinations.add(flag_combo)

      # Many different flag combinations in short time = suspicious
      if len(unique_flag_combinations) > 4 and len(packets) > 10:
        return 0.7

    # Check for burst patterns (many packets in short time)
    if len(packets) >= 10:
      recent_packets = packets[-10:]
      time_span = recent_packets[-1]['timestamp'] - recent_packets[0]['timestamp']

      if time_span < 5:  # 10 packets in less than 5 seconds
        # Check if they're unusual flags
        unusual_count = sum(
            1 for p in recent_packets
            if set(p['flags']) in [{'U', 'A'}, {'P', 'A'}, {'S', 'A'}, {'F', 'A'}]
        )

        if unusual_count > 5:  # >50% unusual flags in burst
          return 0.6

    return 0.0

  def _cleanup_old_connections(self, current_time):
    """Remove old inactive connections"""
    timeout = 600  # 10 minutes

    old_connections = [
        conn_key for conn_key, conn in self.connections.items()
        if current_time - conn['last_packet'] > timeout
    ]

    for conn_key in old_connections:
      del self.connections[conn_key]

    if old_connections:
      print(f"Cleaned up {len(old_connections)} old connections")
