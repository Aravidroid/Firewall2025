import logging
import subprocess
import socket
import platform
import signal
import requests
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import psutil
import json
from collections import defaultdict
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import socketio

# Setup logging
log_file = "firewall_agent.log"
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format="%(asctime)s - %(processName)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
API_URL = "http://127.0.0.1:5000"

def get_policies():
    try:
        response = requests.get(f"{API_URL}/get_policies")
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        logging.error(f"Error fetching policies: {e}")
    return {"whitelist": {}, "blacklist": {}}

policies = get_policies()
# Cache for process lookup
port_process_cache = defaultdict(lambda: None)
resolved_domains_cache = defaultdict(set)

def resolve_domain_to_ips(domain):
    """Resolve domain name to IP addresses."""
    if domain in resolved_domains_cache:
        return resolved_domains_cache[domain]
    try:
        ips = set(socket.gethostbyname_ex(domain)[2])
        resolved_domains_cache[domain] = ips
        logging.debug(f"Resolved domain {domain} to IPs {ips}")
        return ips
    except socket.gaierror as e:
        logging.error(f"DNS resolution failed for domain {domain}: {e}")
        return set()

def get_process_by_port(port):
    """Get process name and path by port."""
    if port in port_process_cache:
        return port_process_cache[port]
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                process = psutil.Process(conn.pid)
                process_info = (process.name(), process.exe())
                port_process_cache[port] = process_info
                return process_info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return None, None
    return None, None

blocked_rules = []

def block_traffic_windows(app_path, ip_dst=None):
    """Block traffic on Windows."""
    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name=BlockedTraffic_{app_path}_{ip_dst}" if ip_dst else f"name=BlockedApp_{app_path}",
        "dir=out", "action=block", f"program={app_path}"
    ] + (["protocol=TCP", f"remoteip={ip_dst}"] if ip_dst else [])
    try:
        subprocess.run(command, check=True)
        logging.info(f"Blocked {app_path} {'to IP ' + ip_dst if ip_dst else 'entirely'}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block traffic on Windows: {e}")

def block_traffic_linux(app_path, ip_dst=None):
    """Block traffic on Linux using iptables."""
    try:
        if ip_dst:
            command = ["iptables", "-A", "OUTPUT", "-p", "tcp", "-d", ip_dst, "-j", "DROP"]
            subprocess.run(command, check=True)
            logging.info(f"Blocked {app_path} to IP {ip_dst} using iptables.")
        else:
            logging.warning("Blocking application traffic by path not supported on Linux with iptables.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block traffic on Linux: {e}")

def block_traffic(app_path, ip_dst=None):
    """Block traffic based on the operating system."""
    if platform.system() == "Windows":
        block_traffic_windows(app_path, ip_dst)
    elif platform.system() == "Linux":
        block_traffic_linux(app_path, ip_dst)
    else:
        logging.error("Unsupported platform for blocking traffic.")

def unblock_traffic_windows(app_path, ip_dst=None):
    """Unblock traffic on Windows."""
    rule_name = f"BlockedTraffic_{app_path}_{ip_dst}" if ip_dst else f"BlockedApp_{app_path}"
    command = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    try:
        subprocess.run(command, check=True)
        logging.info(f"Unblocked {app_path} {'from IP ' + ip_dst if ip_dst else 'entirely'}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to unblock traffic on Windows: {e}")

def unblock_traffic(app_path, ip_dst=None):
    """Unblock traffic based on the operating system."""
    if platform.system() == "Windows":
        unblock_traffic_windows(app_path, ip_dst)
    elif platform.system() == "Linux":
        logging.warning("Unblocking specific app by path not directly supported on Linux.")
    else:
        logging.error("Unsupported platform for unblocking traffic.")


def log_policy_action(action, app_name, ip_dst, protocol, domain=None):
    """Log policy actions concisely."""
    domain_info = f"(Domain: {domain})" if domain else ""
    log_message = f"{action.upper()} - App: {app_name} {domain_info}, IP: {ip_dst}, Protocol: {protocol}"
    logging.info(log_message)
    print(log_message)

def enforce_policy(packet, app_name, app_path, protocol):
    """Enforce firewall policies based on application name, IP, or domain."""
    ip_dst = packet[IP].dst
    action_taken = None

    if app_name in policies['blacklist']['applications']:
        block_traffic(app_path)
        action_taken = "blocked"
        log_policy_action(action_taken, app_name, ip_dst, protocol)
    elif ip_dst in policies['blacklist']['ips']:
        block_traffic(app_path, ip_dst)
        action_taken = "blocked"
        log_policy_action(action_taken, app_name, ip_dst, protocol)
    else:
        # Check blacklist domains
        for domain in policies['blacklist']['domains']:
            if ip_dst in resolve_domain_to_ips(domain):
                block_traffic(app_path, ip_dst)
                action_taken = "blocked"
                log_policy_action(action_taken, app_name, ip_dst, protocol, domain)
                break

    # Handle whitelist - unblocking
    if app_name in policies['whitelist']['applications']:
        unblock_traffic(app_path)
        action_taken = "unblocked"
        log_policy_action(action_taken, app_name, ip_dst, protocol)
    elif ip_dst in policies['whitelist']['ips']:
        unblock_traffic(app_path, ip_dst)
        action_taken = "unblocked"
        log_policy_action(action_taken, app_name, ip_dst, protocol)

    if not action_taken:
        action_taken = "allowed"
    
    log_policy_action(action_taken, app_name, ip_dst, protocol)

def packet_callback(packet):
    """Handle sniffed packets."""
    if packet.haslayer(IP):
        protocol, sport = None, None

        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = packet[TCP].sport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = packet[UDP].sport

        if protocol and sport:
            app_name, app_path = get_process_by_port(sport)
            if app_name:
                enforce_policy(packet, app_name, app_path, protocol)

# Suricata log monitoring using watchdog
eve_log_file = "C:/Program Files/Suricata/logs/eve.json"

class SuricataLogHandler(FileSystemEventHandler):
    """Custom handler for processing new log entries in Suricata's eve.json."""
    def __init__(self, log_file):
        self.log_file = log_file
        self.log_file_obj = open(log_file, 'r')
        self.log_file_obj.seek(0, os.SEEK_END)

    def process_new_log_entries(self):
        """Process new log entries."""
        for line in self.log_file_obj:
            try:
                alert_data = json.loads(line)
                if "alert" in alert_data:
                    print(f"Alert: {alert_data['alert']['signature']}")
                    print(f"Source IP: {alert_data['src_ip']}, Destination IP: {alert_data['dest_ip']}")
            except json.JSONDecodeError:
                continue

    def on_modified(self, event):
        """Called when the monitored file is modified."""
        if event.src_path == self.log_file:
            self.process_new_log_entries()

def monitor_suricata_alerts_with_watchdog(eve_log_file):
    """Monitor Suricata alerts using watchdog to watch file modifications."""
    event_handler = SuricataLogHandler(eve_log_file)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(eve_log_file), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()

def sniff_packets():
    """Run the packet sniffer."""
    sniff(filter="ip", prn=packet_callback, store=False)

def update_policies():
    """Simulate dynamic policy updates from the server."""
    while True:
        logging.info("Fetching updated policies...")
        global policies
        policies = get_policies()
        logging.info("Updated policies loaded.")
        time.sleep(60)

def cleanup_firewall_and_exit(sig, frame):
    """Clean up firewall rules and exit."""
    for rule in blocked_rules:
        unblock_traffic_windows(rule)
    os._exit(0)

# Register signal handlers for cleanup
signal.signal(signal.SIGINT, cleanup_firewall_and_exit)   # Handle Ctrl+C (SIGINT)
signal.signal(signal.SIGTERM, cleanup_firewall_and_exit)  # Handle termination signals (SIGTERM)

if __name__ == "__main__":
    print("Starting the firewall agent...")

    try:
        # Run sniffing in a separate thread
        sniffing_thread = threading.Thread(target=sniff_packets)
        sniffing_thread.start()

        # Run Suricata alert monitoring in a separate thread using watchdog
        suricata_monitoring_thread = threading.Thread(target=monitor_suricata_alerts_with_watchdog, args=(eve_log_file,))
        suricata_monitoring_thread.start()

        # Run policy updates in the main thread
        update_policies()

        # Join threads to wait for their completion
        sniffing_thread.join()
        suricata_monitoring_thread.join()

    except KeyboardInterrupt:
        print("\nStopping the firewall agent.")
    except Exception as e:
        logging.critical(f"Error occurred: {e}")