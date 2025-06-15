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
    'combined_score': 0.60          # Final threshold for alert generation
}

# Analysis Windows
ANALYSIS_WINDOWS = {
    'pattern_window': 30,           # Seconds to look for patterns
    'statistical_window': 60,       # Seconds for statistical analysis
    'behavior_window': 45           # Seconds for behavior analysis
}

# Covert Channel Signatures
COVERT_FLAGS = {
    'start_session': ['S', 'A'],    # SA - Start session
    'end_session': ['F', 'A'],      # FA - End session
    'bit_one': ['U', 'A'],          # UA - Bit 1
    'bit_zero': ['P', 'A']          # PA - Bit 0
}

# Normal TCP Flags
NORMAL_FLAGS = {
    'syn': ['S'],
    'ack': ['A'],
    'fin': ['F'],
    'rst': ['R'],
    'syn_ack': ['S', 'A'],
    'fin_ack': ['F', 'A']
}

# Logging Configuration
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': '/results/detector.log'
}
