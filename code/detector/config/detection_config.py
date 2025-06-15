"""
Detection configuration parameters
"""

# NATS Configuration
NATS_SERVER = 'nats://nats:4222'
INPUT_TOPICS = ['inpktsec', 'inpktinsec']
ALERT_TOPICS = ['covert_alert_sec', 'covert_alert_insec']

# Detection Thresholds
DETECTION_THRESHOLDS = {
    'tcp_flags_anomaly': 0.7,      # Threshold for unusual flag combinations
    'pattern_detection': 0.8,       # Threshold for sequence patterns
    'behavior_analysis': 0.6,       # Threshold for protocol behavior
    'statistical_analysis': 0.5,    # Threshold for statistical anomalies
    'combined_score': 0.6,          # 0.4 for phase 4
    'mitigation_score': 0.7,        # 0.45 for phase 4
}

MITIGATION_ENABLED = False  # Enable or disable mitigation actions
