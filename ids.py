from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import time
import signal
import sys
connection_count = defaultdict(int)
scan_tracker = defaultdict(set)
last_alert_time = {}
#  Cooldown system
def should_alert(src, cooldown=5):
    now = time.time()
    if src not in last_alert_time or now - last_alert_time[src] > cooldown:
        last_alert_time[src] = now
        return True
    return False
#  Logging function
def log_alert(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {msg}"
    print(full_msg)
    with open("alerts.log", "a") as f:
        f.write(full_msg + "\n")
#  Detection logic
def detect(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        # ICMP Detection
        if packet.haslayer(ICMP):
            if should_alert(src):
                log_alert(f"[ALERT] ICMP traffic detected from {src}")
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            connection_count[src] += 1
            scan_tracker[src].add(dst_port)
            # SYN Scan Detection
            if flags == "S" and should_alert(src):
                log_alert(f"[ALERT] SYN Scan from {src} to port {dst_port}")
            # Port Scan Detection (trigger once)
            if len(scan_tracker[src]) == 6:
                log_alert(f"[ALERT] Port Scan Detected from {src}")
            # Brute Force Detection
            if dst_port in [21, 22] and connection_count[src] > 10 and should_alert(src):
                log_alert(f"[ALERT] Brute Force Attempt from {src}")
            # Info logs (optional)
            if dst_port in [21, 22, 80] and should_alert(src, 10):
                log_alert(f"[INFO] Access to sensitive port {dst_port} from {src}")
#  Summary on exit
def summary(signal, frame):
    print("\n=== ATTACK SUMMARY ===")
    for ip in connection_count:
        print(f"{ip} -> {connection_count[ip]} packets, {len(scan_tracker[ip])} ports")
    sys.exit(0)
signal.signal(signal.SIGINT, summary)
print("=== Python IDS Started (Listening on enp0s8) ===")
#  IMPORTANT: correct interface
sniff(iface="enp0s8", filter="ip", prn=detect, store=0)