"""
Quick test script for immediate feedback
"""
import subprocess
import time
import json

def quick_test():
    print("🚀 Quick Detection Test")
    print("-" * 25)
    
    # Clear alerts
    print("1. Clearing previous alerts...")
    try:
        subprocess.run(['docker', 'exec', 'detector', 'rm', '-f', '/results/alerts.jsonl'], 
                      capture_output=True)
        subprocess.run(['docker', 'exec', 'detector', 'touch', '/results/alerts.jsonl'], 
                      capture_output=True)
    except:
        pass
    
    # Test detector responsiveness
    print("2. Testing detector logs...")
    try:
        result = subprocess.run(['docker', 'logs', 'detector', '--tail', '5'], 
                              capture_output=True, text=True, timeout=5)
        if "running" in result.stdout.lower():
            print("   ✅ Detector is active")
        else:
            print("   ⚠️  Detector may not be running properly")
    except:
        print("   ❌ Cannot access detector logs")
    
    # Send test covert traffic
    print("3. Sending test covert traffic...")
    try:
        # Start receiver
        receiver_proc = subprocess.Popen([
            'docker', 'exec', 'insec', 'python3', 
            '/code/insec/covert/receiver.py', '10.1.0.21', '31337'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(2)
        
        # Send short message
        sender_result = subprocess.run([
            'docker', 'exec', 'sec', 'python3', 
            '/code/sec/covert/sender.py', '10.0.0.21', '31337', 'HI', '0.1'
        ], timeout=15, capture_output=True, text=True)
        
        time.sleep(2)
        receiver_proc.terminate()
        
        print("   ✅ Covert traffic sent")
        
    except Exception as e:
        print(f"   ❌ Failed to send covert traffic: {e}")
    
    # Check detection results
    print("4. Checking detection results...")
    time.sleep(2)
    
    try:
        # Count alerts
        result = subprocess.run([
            'docker', 'exec', 'detector', 'wc', '-l', '/results/alerts.jsonl'
        ], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            alert_count = int(result.stdout.strip().split()[0])
            print(f"   📊 Alerts generated: {alert_count}")
            
            if alert_count > 0:
                print("   ✅ Detection is working!")
                
                # Show last alert
                result = subprocess.run([
                    'docker', 'exec', 'detector', 'tail', '-n', '1', '/results/alerts.jsonl'
                ], capture_output=True, text=True, timeout=5)
                
                if result.stdout.strip():
                    try:
                        alert = json.loads(result.stdout.strip())
                        score = alert.get('combined_score', 0)
                        flags = alert.get('packet_info', {}).get('flags', [])
                        print(f"   📋 Last alert: Score={score:.3f}, Flags={flags}")
                    except:
                        print("   📋 Alert generated (could not parse details)")
            else:
                print("   ⚠️  No alerts generated - detection may need tuning")
        else:
            print("   ❌ Could not check alerts")
            
    except Exception as e:
        print(f"   ❌ Error checking results: {e}")
    
    print("\n✨ Quick test completed!")

if __name__ == "__main__":
    quick_test()