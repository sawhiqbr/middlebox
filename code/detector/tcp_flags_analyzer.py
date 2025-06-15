"""
TCP Flags Anomaly Detection Module
"""
from collections import defaultdict, deque


class TCPFlagsAnalyzer:
  def __init__(self):
    # Flag statistics tracking
    self.flag_counts = defaultdict(int)
    self.recent_flags = deque(maxlen=100)

  async def analyze(self, packet_info):
    """Analyze TCP flags for covert channel patterns"""
    flags = packet_info.get('flags', [])
    flag_combo = ''.join(sorted(flags))

    # Track this flag combination
    self.flag_counts[flag_combo] += 1
    self.recent_flags.append((flag_combo, packet_info.get('dst_port')))

    score = 0.0

    # Check for covert flag combinations
    if self._is_covert_flag_combo(flag_combo):
      score += 0.8
      print(f"COVERT FLAG DETECTED: {flag_combo}")

    # Check for suspicious ports
    if packet_info.get('dst_port') == 31337:
      score += 0.3
      print(f"SUSPICIOUS PORT: {packet_info.get('dst_port')}")

    # Check for unusual flag combinations
    if self._is_unusual_flag_combo(flag_combo):
      score += 0.5
      print(f"UNUSUAL FLAG: {flag_combo}")

    return min(score, 1.0)

  def _is_covert_flag_combo(self, flag_combo):
    """Check if flag combination is used by covert channel"""
    # Your covert channel uses: SA, UA, PA, FA
    covert_combinations = ['AS', 'AU', 'AP', 'AF']  # Sorted versions
    return flag_combo in covert_combinations

  def _is_unusual_flag_combo(self, flag_combo):
    """Check if flag combination is unusual"""
    unusual_combinations = ['AU', 'AP', 'U', 'P']  # URG, PSH without standard flags
    return flag_combo in unusual_combinations
