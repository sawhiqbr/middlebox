"""
Enhanced Testing Framework for Phase 3 - Statistical Analysis
"""
import asyncio
import time
import json
import subprocess
import threading
import statistics
import math
from datetime import datetime
import numpy as np


class Phase3TestFramework:
  def __init__(self):
    self.test_results = {}
    self.detection_metrics = {}
    self.statistical_results = {}
    self._ensure_realistic_services()

  def _ensure_realistic_services(self):
    """Start services that respond to connections"""
    services = [
        # HTTP server
        (['python3', '-m', 'http.server', '80'], 'HTTP'),
        # Simple TCP listener
        (['nc', '-l', '-k', '-p', '22'], 'TCP')
    ]

    for cmd, name in services:
      try:
        subprocess.Popen([
            'docker', 'exec', '-d', 'insec'] + cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen([
            'docker', 'exec', '-d', 'insec', 'python3', '-c',
            'import socket; s=socket.socket(); s.bind(("", 443)); s.listen(5); [s.accept()[0].close() for _ in iter(lambda: s.accept(), None)]'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print(f"Started {name} service")
      except Exception as e:
        print(f"Could not start {name}: {e}")

    time.sleep(1)  # Let services initialize

  def run_experimentation_campaign(self):
    """Run comprehensive experimentation campaign for Phase 3"""
    print("Phase 3 Experimentation Campaign")
    print("=" * 50)

    # Multiple test scenarios with statistical analysis
    self.test_detection_accuracy_campaign()
    self.generate_statistical_report()

  def test_detection_accuracy_campaign(self):
    """Enhanced testing with multiple scenarios"""
    print("\nDetection Accuracy Campaign (50 runs)")
    print("-" * 40)

    num_runs = 50
    covert_results = []
    normal_results = []

    for run in range(num_runs):
      print(f"Run {run+1:2d}/{num_runs}...", end=" ", flush=True)

      # Vary test scenarios
      scenario = run % 4  # 4 different scenarios

      if scenario == 0:
        # Standard covert test
        covert_detected = self._single_covert_test()
      elif scenario == 1:
        # Shorter covert message (might be missed)
        covert_detected = self._single_covert_test_short()
      elif scenario == 2:
        # Covert with noise (TCP traffic mixed in)
        covert_detected = self._single_covert_test_with_noise()
      else:
        covert_detected = self._single_covert_test_with_delay(0.05)

      print(f"Covert detected: {covert_detected}", end=", ", flush=True)
      covert_results.append(covert_detected)

      # Vary normal traffic too
      if run % 3 == 0:
        normal_alerts = self._single_normal_test()  # Ping
      elif run % 3 == 1:
        normal_alerts = self._single_tcp_test()    # HTTP-like
      else:
        normal_alerts = self._single_mixed_test()  # Mixed protocols

      normal_results.append(normal_alerts == 0)

      print("Done.")
      time.sleep(0.5)  # Shorter delay for 50 runs

    # Calculate detection metrics
    tp = sum(covert_results)  # True Positives
    fn = num_runs - tp        # False Negatives
    tn = sum(normal_results)  # True Negatives
    fp = num_runs - tn        # False Positives

    total_classifications = num_runs * 2  # Each run has covert + normal test

    self._calculate_detection_metrics(tp, tn, fp, fn, total_classifications)

  def _single_covert_test(self):
    """Single covert channel test - returns True if detected"""
    self._clear_alerts()

    try:
      # Start receiver
      receiver_proc = subprocess.Popen([
          'docker', 'exec', '-d', 'insec', 'python3',
          '/code/insec/covert/receiver.py'
      ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

      time.sleep(1)

      # Generate random short message
      import random
      import string

      # Random length between 10-20 characters
      length = random.randint(10, 20)

      # Generate random string with letters and digits
      message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

      # Send covert message
      subprocess.run([
          'docker', 'exec', 'sec', 'python3',
          '/code/sec/covert/sender.py', message
      ], timeout=15)

      time.sleep(1)
      receiver_proc.terminate()

      # Check if detected
      alert_count = self._count_alerts()
      print(f"Alerts generated: {alert_count}")
      return alert_count > 0

    except Exception:
      return False

  def _single_normal_test(self):
    """Single normal traffic test - returns number of alerts"""
    self._clear_alerts()

    try:
      # Send normal traffic
      subprocess.run([
          'docker', 'exec', 'sec', 'ping', '-c', '5', 'insec'
      ], timeout=10)

      time.sleep(1)
      return self._count_alerts()

    except Exception:
      return 0

  def _single_covert_test_short(self):
    """Short covert message (might be harder to detect)"""
    self._clear_alerts()

    try:
      receiver_proc = subprocess.Popen([
          'docker', 'exec', '-d', 'insec', 'python3',
          '/code/insec/covert/receiver.py'
      ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

      time.sleep(1)

      # Generate random short message
      import random
      import string

      # Random length between 1-4 characters
      length = random.randint(1, 4)

      # Generate random string with letters and digits
      message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

      # Send very short message (might not trigger pattern detection)
      result = subprocess.run([
          'docker', 'exec', 'sec', 'python3',
          '/code/sec/covert/sender.py', message
      ], timeout=15)

      time.sleep(1)
      subprocess.run(['docker', 'exec', 'insec', 'pkill', '-f', 'receiver'],)

      alert_count = self._count_alerts()
      print(f"Alerts generated: {alert_count}")
      return alert_count > 0

    except Exception:
      return False

  def _single_covert_test_with_noise(self):
    """Covert channel with background TCP noise"""
    self._clear_alerts()

    try:
      # Start receiver
      receiver_proc = subprocess.Popen([
          'docker', 'exec', '-d', 'insec', 'python3',
          '/code/insec/covert/receiver.py'
      ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

      # Generate background noise
      noise_proc = subprocess.Popen([
          'docker', 'exec', '-d', 'sec', 'nc', '-w', '1', 'insec', '80'
      ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

      time.sleep(1)

      # Generate random short message
      import random
      import string

      # Random length between 10-20 characters
      length = random.randint(10, 20)

      # Generate random string with letters and digits
      message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

      # Send covert message
      result = subprocess.run([
          'docker', 'exec', 'sec', 'python3',
          '/code/sec/covert/sender.py', message
      ], timeout=20)

      time.sleep(1)

      # Cleanup
      subprocess.run(['docker', 'exec', 'insec', 'pkill', '-f', 'receiver'],)
      noise_proc.terminate()

      return self._count_alerts() > 0

    except Exception:
      return False

  def _single_tcp_test(self):
    """Normal TCP connection test"""
    self._clear_alerts()

    try:
      # Try to connect to port 80 (normal HTTP-like behavior)
      subprocess.run([
          'docker', 'exec', 'sec', 'nc', '-w', '2', 'insec', '80'
      ], timeout=5)

      time.sleep(1)
      return self._count_alerts()

    except Exception:
      return 0

  def _single_mixed_test(self):
    """Mixed protocol normal traffic"""
    self._clear_alerts()

    try:
      # Generate mixed traffic
      subprocess.run([
          'docker', 'exec', 'sec', 'ping', '-c', '2', 'insec'
      ], timeout=5)

      subprocess.run([
          'docker', 'exec', 'sec', 'nc', '-w', '1', 'insec', '443'
      ], timeout=3)

      time.sleep(1)
      return self._count_alerts()

    except Exception:
      return 0

  def _single_covert_test_with_delay(self, delay):
    """Covert test with specific delay"""
    self._clear_alerts()

    try:
      receiver_proc = subprocess.Popen([
          'docker', 'exec', '-d', 'insec', 'python3',
          '/code/insec/covert/receiver.py'
      ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

      time.sleep(1)

      # Generate random short message
      import random
      import string

      # Random length between 10-20 characters
      length = random.randint(10, 20)

      # Generate random string with letters and digits
      message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

      subprocess.run([
          'docker', 'exec', 'sec', 'python3',
          '/code/sec/covert/sender.py', message,
          '--delay', str(delay)
      ], timeout=30)

      time.sleep(1)
      receiver_proc.terminate()
      print(f"Covert test with {delay}s delay completed. Checking alerts...")
      alert_count = self._count_alerts()
      print(f"Alerts generated: {alert_count}")
      return alert_count > 0

    except Exception:
      return False

  def _calculate_detection_metrics(self, tp, tn, fp, fn, total_runs):
    """Calculate comprehensive detection metrics"""
    # Basic metrics
    accuracy = (tp + tn) / total_runs if total_runs > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0

    # F-Score metrics
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    f2_score = 5 * (precision * recall) / (4 * precision +
                                           recall) if (4 * precision + recall) > 0 else 0

    # Store results
    self.detection_metrics = {
        'true_positives': tp,
        'true_negatives': tn,
        'false_positives': fp,
        'false_negatives': fn,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'specificity': specificity,
        'f1_score': f1_score,
        'f2_score': f2_score,
        'total_runs': total_runs
    }

    print(f"\nDetection Metrics (n={total_runs}):")
    print(f"  TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")
    print(f"  Accuracy:    {accuracy:.3f}")
    print(f"  Precision:   {precision:.3f}")
    print(f"  Recall:      {recall:.3f}")
    print(f"  Specificity: {specificity:.3f}")
    print(f"  F1-Score:    {f1_score:.3f}")
    print(f"  F2-Score:    {f2_score:.3f}")

  def _clear_alerts(self):
    """Clear alerts file"""
    try:
      subprocess.run(['docker', 'exec', 'detector', 'rm', '-f', '/results/alerts.jsonl'],)
      subprocess.run(['docker', 'exec', 'detector', 'touch', '/results/alerts.jsonl'],)
    except:
      pass

  def _count_alerts(self):
    """Count generated alerts"""
    try:
      result = subprocess.run([
          'docker', 'exec', 'detector', 'wc', '-l', '/results/alerts.jsonl'
      ], capture_output=True, text=True, timeout=5)

      if result.returncode == 0:
        return int(result.stdout.strip().split()[0])
    except:
      pass
    return 0

  def generate_statistical_report(self):
    """Generate comprehensive statistical report"""
    print("\n" + "=" * 60)
    print("PHASE 3 STATISTICAL ANALYSIS REPORT")
    print("=" * 60)

    # Detection Performance Summary
    if self.detection_metrics:
      print("\nDETECTION PERFORMANCE METRICS")
      print("-" * 35)

      dm = self.detection_metrics
      print(f"Sample Size: {dm['total_runs']} runs")
      print("")
      print("Confusion Matrix:")
      print("                 Predicted")
      print("              Covert  Normal")
      print(f"Actual Covert   {dm['true_positives']:<3}     {dm['false_negatives']:<3}")
      print(f"      Normal    {dm['false_positives']:<3}     {dm['true_negatives']:<3}")
      print("")
      print("Performance Metrics:")
      print(
          f"  Accuracy:  {dm['accuracy']:.3f} ± {self._calculate_ci(dm['accuracy'], dm['total_runs']):.3f}")
      print(f"  Precision: {dm['precision']:.3f}")
      print(f"  Recall:    {dm['recall']:.3f}")
      print(f"  F1-Score:  {dm['f1_score']:.3f}")
      print(f"  F2-Score:  {dm['f2_score']:.3f}")

    # ROC Analysis
    if 'roc_data' in self.statistical_results:
      print("\nROC ANALYSIS")
      print("-" * 15)

      roc_data = self.statistical_results['roc_data']
      print(f"{'Threshold':<10} {'TPR':<8} {'FPR':<8} {'Precision':<10}")
      print("-" * 40)

      for threshold, data in sorted(roc_data.items()):
        tpr = data['tp_rate']
        fpr = data['fp_rate']
        precision = tpr / (tpr + fpr) if (tpr + fpr) > 0 else 0
        print(f"{threshold:<10.1f} {tpr:<8.3f} {fpr:<8.3f} {precision:<10.3f}")

    # Delay Impact Analysis
    if 'delay_impact' in self.statistical_results:
      print("\nDELAY IMPACT ANALYSIS (95% Confidence Intervals)")
      print("-" * 55)

      delay_data = self.statistical_results['delay_impact']
      print(f"{'Delay(s)':<10} {'Detection':<12} {'Capacity (bps)':<25} {'95% CI':<15}")
      print("-" * 70)

      for delay, data in sorted(delay_data.items()):
        detection_rate = data['detection_rate']
        mean_cap = data['mean_capacity']
        ci_margin = data['ci_95_margin']
        ci_lower = data['capacity_ci_lower']
        ci_upper = data['capacity_ci_upper']

        print(
            f"{delay:<10.3f} {detection_rate:<12.3f} {mean_cap:<8.1f} ± {ci_margin:<6.1f}      [{ci_lower:.1f}, {ci_upper:.1f}]")

    # Save detailed results
    self._save_results_to_file()

    print(
        f"\nExperimentation campaign completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Detailed results saved to phase3_results.json")

  def _calculate_ci(self, proportion, n, confidence=0.95):
    """Calculate confidence interval for proportion"""
    if n == 0:
      return 0
    z_score = 1.96  # For 95% confidence
    se = math.sqrt((proportion * (1 - proportion)) / n)
    return z_score * se

  def _save_results_to_file(self):
    """Save all results to JSON file"""
    results = {
        'detection_metrics': self.detection_metrics,
        'statistical_results': self.statistical_results,
        'timestamp': datetime.now().isoformat(),
        'experiment_type': 'phase3_detection_analysis'
    }

    with open('phase3_results.json', 'w') as f:
      json.dump(results, f, indent=2)


if __name__ == "__main__":
  framework = Phase3TestFramework()
  framework.run_experimentation_campaign()
