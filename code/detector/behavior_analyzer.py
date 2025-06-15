"""
Protocol Behavior Analysis Module
"""
from collections import defaultdict


class BehaviorAnalyzer:
  def __init__(self):
    # Connection state tracking
    self.connections = defaultdict(dict)

  async def analyze(self, packet_info):
    """Analyze protocol behavior for anomalies"""
    score = 0.0

    # Check for suspicious port usage
    if packet_info.get('dst_port') == 31337:
      score += 0.4

    # Check for unusual flag usage patterns
    flags = packet_info.get('flags', [])
    if 'U' in flags:  # URG flag is rarely used
      score += 0.3

    return min(score, 1.0)
