"""
Sequence Pattern Detection Module
"""
from collections import deque, defaultdict


class PatternDetector:
  def __init__(self):
    # Packet sequence tracking per connection
    self.connection_sequences = defaultdict(lambda: deque(maxlen=100))
    self.active_sessions = {}

  async def analyze(self, packet_info):
    """Analyze packet patterns for covert sequences"""
    conn_id = f"{packet_info['src_ip']}:{packet_info['src_port']}->{packet_info['dst_ip']}:{packet_info['dst_port']}"
    flags = packet_info.get('flags', [])

    # Add to sequence
    self.connection_sequences[conn_id].append(flags)

    score = 0.0

    # Check for covert session patterns
    if packet_info.get('dst_port') == 31337:
      sequence = list(self.connection_sequences[conn_id])

      # Look for covert channel session start (SA)
      if flags == ['S', 'A'] or flags == ['A', 'S']:
        score += 0.6
        print(f"COVERT SESSION START: {flags}")

      # Look for covert data transmission (UA, PA)
      if flags == ['U', 'A'] or flags == ['P', 'A']:
        score += 0.7
        print(f"COVERT DATA: {flags}")

      # Look for session end (FA)
      if flags == ['F', 'A'] or flags == ['A', 'F']:
        score += 0.5
        print(f"COVERT SESSION END: {flags}")

    return min(score, 1.0)
