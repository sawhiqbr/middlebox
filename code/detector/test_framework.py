"""
Testing framework for covert channel detection
"""
import asyncio
import time
import json
import subprocess
import threading
from datetime import datetime
import statistics

class DetectionTestFramework:
    def __init__(self):
        self.test_results = {}
        self.current_test = None
        
    def run_comprehensive_tests(self):
        """Run all detection tests"""
        print("🧪 Starting Comprehensive Detection Tests")
        print("=" * 50)
        
        # Test 1: Basic Infrastructure
        self.test_basic_infrastructure()
        
        # Test 2: Normal Traffic (should not alert)
        self.test_normal_traffic()
        
        # Test 3: Covert Channel Detection
        self.test_covert_channel_detection()
        
        # Test 4: Mixed Traffic
        self.test_mixed_traffic()
        
        # Test 5: False Positive Rate
        self.test_false_positive_rate()
        
        # Generate report
        self.generate_test_report()
    
    def test_basic_infrastructure(self):
        """Test 1: Basic infrastructure connectivity"""
        print("\n📡 Test 1: Basic Infrastructure")
        print("-" * 30)
        
        try:
            # Check if detector is running
            result = subprocess.run(['docker', 'logs', 'detector', '--tail', '10'], 
                                  capture_output=True, text=True, timeout=10)
            
            if "Covert Channel Detector is running" in result.stdout:
                print("✅ Detector is running")
                self.test_results['infrastructure'] = 'PASS'
            else:
                print("❌ Detector not running properly")
                self.test_results['infrastructure'] = 'FAIL'
                return
                
            # Test basic ping connectivity
            result = subprocess.run(['docker', 'exec', 'sec', 'ping', '-c', '3', 'insec'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                print("✅ Basic connectivity works")
            else:
                print("❌ Basic connectivity failed")
                self.test_results['infrastructure'] = 'FAIL'
                
        except Exception as e:
            print(f"❌ Infrastructure test failed: {e}")
            self.test_results['infrastructure'] = 'FAIL'
    
    def test_normal_traffic(self):
        """Test 2: Normal traffic should not trigger alerts"""
        print("\n🚦 Test 2: Normal Traffic (No Alerts Expected)")
        print("-" * 45)
        
        self.current_test = 'normal_traffic'
        
        # Clear previous alerts
        self._clear_alerts()
        
        # Generate normal traffic
        print("Generating normal traffic...")
        try:
            # ICMP ping
            subprocess.run(['docker', 'exec', 'sec', 'ping', '-c', '10', 'insec'], 
                          timeout=20, capture_output=True)
            
            # Normal TCP traffic (telnet attempt)
            subprocess.run(['docker', 'exec', 'sec', 'timeout', '5', 'telnet', 'insec', '80'], 
                          timeout=10, capture_output=True)
            
            time.sleep(3)  # Let detection process
            
            # Check alerts
            alert_count = self._count_alerts()
            print(f"Alerts generated: {alert_count}")
            
            if alert_count <= 2:  # Allow some tolerance
                print("✅ Normal traffic test passed")
                self.test_results['normal_traffic'] = 'PASS'
            else:
                print("❌ Too many false positives")
                self.test_results['normal_traffic'] = 'FAIL'
                
        except Exception as e:
            print(f"❌ Normal traffic test failed: {e}")
            self.test_results['normal_traffic'] = 'FAIL'
    
    def test_covert_channel_detection(self):
        """Test 3: Covert channel should be detected"""
        print("\n🔍 Test 3: Covert Channel Detection")
        print("-" * 35)
        
        self.current_test = 'covert_detection'
        
        # Clear previous alerts
        self._clear_alerts()
        
        try:
            # Start receiver in background
            print("Starting covert channel receiver...")
            receiver_proc = subprocess.Popen([
                'docker', 'exec', 'insec', 'python3', 
                '/code/insec/covert/receiver.py', '10.1.0.21', '31337'
            ])
            
            time.sleep(2)  # Let receiver start
            
            # Send covert message
            print("Sending covert message...")
            sender_result = subprocess.run([
                'docker', 'exec', 'sec', 'python3', 
                '/code/sec/covert/sender.py', '10.0.0.21', '31337', 'TEST', '0.1'
            ], timeout=30, capture_output=True, text=True)
            
            time.sleep(3)  # Let detection process
            
            # Stop receiver
            receiver_proc.terminate()
            
            # Check alerts
            alert_count = self._count_alerts()
            print(f"Alerts generated: {alert_count}")
            
            if alert_count >= 3:  # Should detect covert activity
                print("✅ Covert channel detected successfully")
                self.test_results['covert_detection'] = 'PASS'
                
                # Analyze alert quality
                self._analyze_alert_quality()
            else:
                print("❌ Failed to detect covert channel")
                self.test_results['covert_detection'] = 'FAIL'
                
        except Exception as e:
            print(f"❌ Covert detection test failed: {e}")
            self.test_results['covert_detection'] = 'FAIL'
    
    def test_mixed_traffic(self):
        """Test 4: Mixed normal and covert traffic"""
        print("\n🔀 Test 4: Mixed Traffic Detection")
        print("-" * 32)
        
        self.current_test = 'mixed_traffic'
        self._clear_alerts()
        
        try:
            # Start background normal traffic
            print("Starting background normal traffic...")
            ping_proc = subprocess.Popen([
                'docker', 'exec', 'sec', 'ping', '-i', '2', 'insec'
            ])
            
            time.sleep(3)
            
            # Start covert channel
            print("Starting covert channel in mixed environment...")
            receiver_proc = subprocess.Popen([
                'docker', 'exec', 'insec', 'python3',
                '/code/insec/covert/receiver.py', '10.1.0.21', '31337'
            ])
            
            time.sleep(2)
            
            # Send covert message
            sender_result = subprocess.run([
                'docker', 'exec', 'sec', 'python3',
                '/code/sec/covert/sender.py', '10.0.0.21', '31337', 'MIXED', '0.05'
            ], timeout=20, capture_output=True)
            
            time.sleep(3)
            
            # Stop processes
            ping_proc.terminate()
            receiver_proc.terminate()
            
            # Analyze results
            alert_count = self._count_alerts()
            print(f"Alerts generated in mixed traffic: {alert_count}")
            
            if alert_count >= 2:  # Should still detect covert
                print("✅ Covert channel detected in mixed traffic")
                self.test_results['mixed_traffic'] = 'PASS'
            else:
                print("❌ Failed to detect covert in mixed traffic")
                self.test_results['mixed_traffic'] = 'FAIL'
                
        except Exception as e:
            print(f"❌ Mixed traffic test failed: {e}")
            self.test_results['mixed_traffic'] = 'FAIL'
    
    def test_false_positive_rate(self):
        """Test 5: Measure false positive rate with sustained normal traffic"""
        print("\n📊 Test 5: False Positive Rate Analysis")
        print("-" * 38)
        
        self.current_test = 'false_positive'
        self._clear_alerts()
        
        try:
            print("Generating sustained normal traffic for 60 seconds...")
            
            # Multiple types of normal traffic
            processes = []
            
            # Continuous ping
            processes.append(subprocess.Popen([
                'docker', 'exec', 'sec', 'ping', '-i', '1', 'insec'
            ]))
            
            # Occasional TCP connections
            def generate_tcp_traffic():
                for i in range(10):
                    try:
                        subprocess.run([
                            'docker', 'exec', 'sec', 'timeout', '2', 
                            'nc', '-z', 'insec', str(80 + i)
                        ], timeout=5, capture_output=True)
                        time.sleep(5)
                    except:
                        pass
            
            tcp_thread = threading.Thread(target=generate_tcp_traffic)
            tcp_thread.start()
            
            # Let it run
            time.sleep(60)
            
            # Stop all processes
            for proc in processes:
                proc.terminate()
            
            tcp_thread.join(timeout=5)
            
            # Analyze false positives
            alert_count = self._count_alerts()
            duration = 60
            false_positive_rate = alert_count / duration
            
            print(f"False positive rate: {false_positive_rate:.3f} alerts/second")
            
            if false_positive_rate < 0.1:  # Less than 0.1 alerts per second
                print("✅ Acceptable false positive rate")
                self.test_results['false_positive'] = 'PASS'
            else:
                print("❌ High false positive rate")
                self.test_results['false_positive'] = 'FAIL'
                
        except Exception as e:
            print(f"❌ False positive test failed: {e}")
            self.test_results['false_positive'] = 'FAIL'
    
    def _clear_alerts(self):
        """Clear previous alerts file"""
        try:
            subprocess.run(['docker', 'exec', 'detector', 'rm', '-f', '/results/alerts.jsonl'], 
                          capture_output=True)
            subprocess.run(['docker', 'exec', 'detector', 'touch', '/results/alerts.jsonl'], 
                          capture_output=True)
        except:
            pass
    
    def _count_alerts(self):
        """Count number of alerts generated"""
        try:
            result = subprocess.run([
                'docker', 'exec', 'detector', 'wc', '-l', '/results/alerts.jsonl'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return int(result.stdout.strip().split()[0])
        except:
            pass
        return 0
    
    def _analyze_alert_quality(self):
        """Analyze the quality of generated alerts"""
        try:
            result = subprocess.run([
                'docker', 'exec', 'detector', 'cat', '/results/alerts.jsonl'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                alerts = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            alert = json.loads(line)
                            alerts.append(alert)
                        except:
                            continue
                
                if alerts:
                    scores = [alert.get('combined_score', 0) for alert in alerts]
                    avg_score = statistics.mean(scores)
                    max_score = max(scores)
                    
                    print(f"  Alert quality - Avg score: {avg_score:.3f}, Max score: {max_score:.3f}")
                    
                    # Count alerts by flag type
                    flag_types = {}
                    for alert in alerts:
                        flags = alert.get('packet_info', {}).get('flags', [])
                        flag_key = ''.join(sorted(flags))
                        flag_types[flag_key] = flag_types.get(flag_key, 0) + 1
                    
                    print(f"  Flag combinations detected: {flag_types}")
                    
        except Exception as e:
            print(f"  Could not analyze alert quality: {e}")
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 50)
        print("📋 DETECTION SYSTEM TEST REPORT")
        print("=" * 50)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result == 'PASS')
        
        print(f"\nOverall Results: {passed_tests}/{total_tests} tests passed")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%\n")
        
        for test_name, result in self.test_results.items():
            status_icon = "✅" if result == "PASS" else "❌"
            print(f"{status_icon} {test_name.replace('_', ' ').title()}: {result}")
        
        # Recommendations
        print("\n📝 Recommendations:")
        
        if self.test_results.get('infrastructure') == 'FAIL':
            print("- Fix basic infrastructure connectivity")
        
        if self.test_results.get('normal_traffic') == 'FAIL':
            print("- Tune detection thresholds to reduce false positives")
        
        if self.test_results.get('covert_detection') == 'FAIL':
            print("- Improve detection algorithms sensitivity")
            print("- Check TCP flags analysis logic")
        
        if self.test_results.get('mixed_traffic') == 'FAIL':
            print("- Enhance detection robustness in noisy environments")
        
        if self.test_results.get('false_positive') == 'FAIL':
            print("- Reduce false positive rate by improving baselines")
        
        if passed_tests == total_tests:
            print("🎉 All tests passed! Detection system is working well.")
        
        print(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    tester = DetectionTestFramework()
    tester.run_comprehensive_tests()