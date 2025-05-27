"""
Alert Management and Publishing Module
"""
import json
from datetime import datetime


class AlertManager:
  def __init__(self):
    self.alert_count = 0

  async def generate_alert(self, packet_info, scores, combined_score):
    """Generate and log detection alerts"""
    self.alert_count += 1

    alert = {
        'alert_id': self.alert_count,
        'timestamp': datetime.now().isoformat(),
        'packet_info': {
            'src': f"{packet_info['src_ip']}:{packet_info['src_port']}",
            'dst': f"{packet_info['dst_ip']}:{packet_info['dst_port']}",
            'flags': packet_info['flags'],
            'direction': packet_info['direction']
        },
        'detection_scores': scores,
        'combined_score': combined_score,
        'severity': 'HIGH' if combined_score > 0.8 else 'MEDIUM'
    }

    # Log alert
    print(f"🚨 COVERT CHANNEL ALERT #{self.alert_count}")
    print(f"   Score: {combined_score:.3f}")
    print(f"   Packet: {alert['packet_info']['src']} -> {alert['packet_info']['dst']}")
    print(f"   Flags: {alert['packet_info']['flags']}")
    print(f"   Scores: {scores}")

    # Save to file
    with open('/results/alerts.jsonl', 'a') as f:
      f.write(json.dumps(alert) + '\n')
