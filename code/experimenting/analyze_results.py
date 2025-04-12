import json
import math
import statistics
import matplotlib.pyplot as plt

RESULTS_FILE = "covert_channel_results.json"


try:
    with open(RESULTS_FILE, 'r') as f:
        all_results = json.load(f)
except FileNotFoundError:
    print(f"Error: Results file '{RESULTS_FILE}' not found.")
    exit(1)

delays = []
mean_capacities = []
stdev_capacities = []
ci_95_margins = []
success_rates = []

print("--- Analysis Results ---")
print(f"{'Delay (s)':<10} | {'Mean Cap (bps)':<15} | {'Std Dev':<10} | {'95% CI Margin':<15} | {'Success Rate':<15}")
print("-" * 70)

sorted_delays = sorted(all_results.keys(), key=float)

for delay_str in sorted_delays:
    delay = float(delay_str)
    capacities = [c for c in all_results[delay_str] if c > 0] 
    total_runs = len(all_results[delay_str])
    successful_runs = len(capacities)

    if successful_runs > 1: 
        mean_cap = statistics.mean(capacities)
        stdev_cap = statistics.stdev(capacities)
        
        
        ci_margin = 1.96 * (stdev_cap / math.sqrt(successful_runs))
    elif successful_runs == 1:
        mean_cap = capacities[0]
        stdev_cap = 0
        ci_margin = 0 
    else: 
        mean_cap = 0
        stdev_cap = 0
        ci_margin = 0

    success_rate = successful_runs / total_runs if total_runs > 0 else 0

    delays.append(delay)
    mean_capacities.append(mean_cap)
    stdev_capacities.append(stdev_cap)
    ci_95_margins.append(ci_margin)
    success_rates.append(success_rate)

    print(f"{delay:<10.3f} | {mean_cap:<15.2f} | {stdev_cap:<10.2f} | {ci_margin:<15.2f} | {success_rate*100:<14.1f}% ({successful_runs}/{total_runs})")


plt.figure(figsize=(10, 6))
plt.errorbar(delays, mean_capacities, yerr=ci_95_margins, fmt='-o', capsize=5, label='Mean Capacity (95% CI)')
plt.xlabel("Inter-Packet Delay (seconds)")
plt.ylabel("Covert Channel Capacity (bps)")
plt.title("Covert Channel Capacity vs. Inter-Packet Delay (TCP Flags)")
plt.grid(True)
plt.legend()

plt.ylim(bottom=0) 

plot_filename = "capacity_vs_delay.png"
plt.savefig(plot_filename)
print(f"\nPlot saved to {plot_filename}")



plt.figure(figsize=(10, 6))
plt.plot(delays, [r*100 for r in success_rates], '-x')
plt.xlabel("Inter-Packet Delay (seconds)")
plt.ylabel("Success Rate (%)")
plt.title("Covert Channel Success Rate vs. Inter-Packet Delay")
plt.grid(True)
plt.ylim(0, 105)
plt.savefig("success_rate_vs_delay.png")
print(f"Success rate plot saved to success_rate_vs_delay.png")