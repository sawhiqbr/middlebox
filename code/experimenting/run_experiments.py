import subprocess
import time
import json
import os
import sys 


MESSAGE_TO_SEND = "CovertChannelTest"
COVERT_PORT = 31337
DELAYS_TO_TEST = [0.01, 0.02, 0.05]
RUNS_PER_DELAY = 10 
RECEIVER_START_WAIT = 3 
RECEIVER_LOG_FILE = "/tmp/receiver.log" 
RECEIVER_SCRIPT_PATH = "/code/insec/covert/receiver.py"
SENDER_SCRIPT_PATH = "/code/sec/covert/sender.py"
KEEP_LOG_ON_FAILURE = True 


all_results = {} 

def text_to_bits(text, encoding='utf-8'): 
    bits = bin(int.from_bytes(text.encode(encoding), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

try:
    num_bits = len(text_to_bits(MESSAGE_TO_SEND))
except Exception as e:
    print(f"Error converting message to bits: {e}", file=sys.stderr)
    sys.exit(1)


for delay in DELAYS_TO_TEST:
    print(f"\n--- Testing Delay: {delay:.3f}s ---")
    results_for_this_delay = []
    success_count = 0

    for i in range(RUNS_PER_DELAY):
        run_success = False 
        log_filename = f"./receiver_run_delay_{delay}_run_{i}.log" 
        print(f"\n  Run {i+1}/{RUNS_PER_DELAY}... ")

        
        
        cleanup_cmd = f"docker exec insec rm -f {RECEIVER_LOG_FILE}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True)
        
        if os.path.exists(log_filename):
            try:
                os.remove(log_filename)
            except OSError as e:
                 print(f"    DEBUG: Could not remove old local log {log_filename}: {e}", file=sys.stderr)
        

        # 1. Start Receiver
        print(f"    [1] Starting receiver...")
        receiver_cmd = f"docker exec -d insec bash -c 'python3 {RECEIVER_SCRIPT_PATH} --port {COVERT_PORT} > {RECEIVER_LOG_FILE} 2>&1'"
        try:
            subprocess.run(receiver_cmd, shell=True, check=True, timeout=10)
            print(f"    [1] Receiver start command executed. Waiting {RECEIVER_START_WAIT}s...")
            time.sleep(RECEIVER_START_WAIT)
        except subprocess.CalledProcessError as e:
            print(f"    [FAIL] Failed to start receiver: {e}", file=sys.stderr)
            continue
        except subprocess.TimeoutExpired:
             print(f"    [FAIL] Timeout starting receiver.", file=sys.stderr)
             continue

        # 2. Run Sender
        print(f"    [2] Starting sender (Delay={delay}s)...")
        sender_start_ts = None
        sender_cmd = f"docker exec sec python3 {SENDER_SCRIPT_PATH} '{MESSAGE_TO_SEND}' --port {COVERT_PORT} --delay {delay}"
        try:
            sender_timeout = (num_bits + 5) * delay + 10 
            sender_proc = subprocess.run(sender_cmd, shell=True, capture_output=True, text=True, check=True, timeout=sender_timeout)
            print(f"    [2] Sender finished.")
            # Parse sender output for start time
            for line in sender_proc.stdout.splitlines():
                 if "[SENDER_TIMESTAMP_START]" in line:
                     try:
                         sender_start_ts = float(line.split()[-1])
                         print(f"    [DEBUG] Found sender start timestamp: {sender_start_ts}")
                         break
                     except (IndexError, ValueError) as parse_err:
                         print(f"    [WARN] Could not parse sender start timestamp line: '{line}': {parse_err}", file=sys.stderr)
            if sender_start_ts is None:
                print(f"    [WARN] Sender start timestamp marker not found in sender output.", file=sys.stderr)


        except subprocess.CalledProcessError as e:
            print(f"    [FAIL] Sender command failed (retcode {e.returncode}):", file=sys.stderr)
            print(f"      Sender stdout:\n{e.stdout}", file=sys.stderr)
            print(f"      Sender stderr:\n{e.stderr}", file=sys.stderr)
            kill_cmd = f"docker exec insec pkill -f '{RECEIVER_SCRIPT_PATH}'"
            subprocess.run(kill_cmd, shell=True, capture_output=True)
            continue
        except subprocess.TimeoutExpired:
             print(f"    [FAIL] Timeout waiting for sender (limit: {sender_timeout}s).", file=sys.stderr)
             kill_cmd = f"docker exec insec pkill -f '{RECEIVER_SCRIPT_PATH}'"
             subprocess.run(kill_cmd, shell=True, capture_output=True)
             continue

        # 3. Wait for receiver to process final packet
        print(f"    [+] Waiting 2 seconds for receiver to process final packet...")
        time.sleep(2)
        
        # 4. Stop Receiver
        print(f"    [3] Stopping receiver...")
        kill_cmd = f"docker exec insec pkill -f '{RECEIVER_SCRIPT_PATH}'"
        kill_proc = subprocess.run(kill_cmd, shell=True, capture_output=True, timeout=10)
        if kill_proc.returncode != 0 and "no process found" not in kill_proc.stderr.decode(errors='ignore').lower():
             print(f"    [WARN] pkill command for receiver might have failed (retcode {kill_proc.returncode}): {kill_proc.stderr.decode(errors='ignore')}", file=sys.stderr)
        else:
             print(f"    [3] Receiver stop command executed.")
        time.sleep(0.5) 

        # 5. Get Receiver Log
        print(f"    [4] Copying receiver log to {log_filename}...")
        copy_log_cmd = f"docker cp insec:{RECEIVER_LOG_FILE} {log_filename}"
        rm_log_cmd = f"docker exec insec rm -f {RECEIVER_LOG_FILE}" 
        copy_retcode = subprocess.run(copy_log_cmd, shell=True, capture_output=True, timeout=10).returncode
        subprocess.run(rm_log_cmd, shell=True, capture_output=True, timeout=10) 

        if copy_retcode != 0:
            print(f"    [FAIL] Failed to copy receiver log {RECEIVER_LOG_FILE} from container.", file=sys.stderr)
            continue

        # 6. Parse Receiver Log
        print(f"    [5] Parsing receiver log {log_filename}...")
        receiver_end_ts = None
        decoded_message = None
        parse_success = False 
        log_found = False
        try:
            with open(log_filename, "r") as f:
                log_found = True
                log_content = [] 
                for line in f:
                    log_content.append(line.strip()) 
                    if "[RECEIVER_TIMESTAMP_END]" in line:
                         try:
                             receiver_end_ts = float(line.split()[-1])
                             print(f"    [DEBUG] Found receiver end timestamp: {receiver_end_ts}")
                         except (IndexError, ValueError) as parse_err:
                             print(f"    [WARN] Could not parse receiver end timestamp line: '{line}': {parse_err}", file=sys.stderr)

                    elif "[RECEIVER_DECODE_SUCCESS]" in line:
                         try:
                             decoded_message = line.split("[RECEIVER_DECODE_SUCCESS]", 1)[1].strip()
                             print(f"    [DEBUG] Found decoded message: '{decoded_message}'")
                             if decoded_message == MESSAGE_TO_SEND:
                                 parse_success = True 
                             else:
                                 print(f"    [WARN] Decoded message mismatch: Expected '{MESSAGE_TO_SEND}', Got '{decoded_message}'", file=sys.stderr)
                         except IndexError as parse_err:
                              print(f"    [WARN] Could not parse decoded message line: '{line}': {parse_err}", file=sys.stderr)

            if not receiver_end_ts:
                 print(f"    [WARN] Receiver end timestamp marker not found in log.", file=sys.stderr)
            if not decoded_message:
                 print(f"    [WARN] Receiver decode success/empty marker not found in log.", file=sys.stderr)

        except FileNotFoundError:
            print(f"    [FAIL] Local receiver log file {log_filename} not found after copy attempt!", file=sys.stderr)
            continue
        except Exception as e:
             print(f"    [FAIL] Error reading log file {log_filename}: {e}", file=sys.stderr)
             continue


        # 7. Calculate and Store Results
        print(f"    [6] Calculating results...")
        run_success = parse_success 
        if run_success and sender_start_ts and receiver_end_ts and receiver_end_ts > sender_start_ts:
            transmission_time = receiver_end_ts - sender_start_ts
            capacity_bps = num_bits / transmission_time
            results_for_this_delay.append(capacity_bps)
            success_count += 1
            print(f"    [OK] Success! Time: {transmission_time:.3f}s, Capacity: {capacity_bps:.2f} bps")
        else:
            results_for_this_delay.append(0.0) 
            print(f"    [FAIL] Failed! Run Success Flag: {run_success}, Decoded Msg: '{decoded_message}', SenderTS: {sender_start_ts}, ReceiverTS: {receiver_end_ts})")
            if log_found and KEEP_LOG_ON_FAILURE:
                 print(f"      ------ Receiver Log ({log_filename}) ------")
                 for log_line in log_content[-20:]: 
                     print(f"      | {log_line}")
                 print(f"      ------ End Receiver Log ------")


        # 8. Cleanup
        if log_found and os.path.exists(log_filename):
             if run_success or not KEEP_LOG_ON_FAILURE:
                 try:
                     os.remove(log_filename) 
                 except OSError as e:
                      print(f"    [WARN] Could not remove local log {log_filename}: {e}", file=sys.stderr)
             else:
                  print(f"    [INFO] Kept log file for failed run: {log_filename}")


    # 9. End of runs for this delay
    all_results[str(delay)] = results_for_this_delay 
    print(f"  --- Delay {delay:.3f}s Summary: Success rate {success_count}/{RUNS_PER_DELAY} ---")


# 10. Save results
results_file = "covert_channel_results.json"
print(f"\nExperiment complete. Saving results to {results_file}")
try:
    results_to_save = {str(k): v for k, v in all_results.items()}
    with open(results_file, 'w') as f:
        json.dump(results_to_save, f, indent=2)
    print("Results saved successfully.")
except Exception as e:
     print(f"Error saving results to JSON: {e}", file=sys.stderr)