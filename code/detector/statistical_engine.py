"""
Statistical Analysis Engine
"""
from collections import defaultdict, deque
import math


class StatisticalEngine:
  def __init__(self):
    # Statistical tracking
    self.flag_statistics = defaultdict(lambda: deque(maxlen=1000))
    self.port_statistics = defaultdict(lambda: deque(maxlen=500))
    self.timing_statistics = deque(maxlen=100)

  async def analyze(self, packet_info):
    """Perform statistical analysis"""
    score = 0.0

    # Track timing
    self.timing_statistics.append(packet_info['timestamp'])

    # Simple frequency analysis
    flags = packet_info.get('flags', [])
    flag_combo = ''.join(sorted(flags))

    # Unusual flag frequency
    if flag_combo in ['AU', 'AP']:  # Covert flags
      score += 0.4

    return min(score, 1.0)
