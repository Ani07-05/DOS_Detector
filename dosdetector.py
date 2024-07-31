
import argparse
from scapy.all import *
from scapy.layers.inet import ICMP, UDP, TCP,IP
from scapy.layers import dot11
from collections import defaultdict
import threading
import time
import sys
import logging


class NetworkAnalyzer:
    def __init__(self, interface, threshold=100, window=60, output_file=None):
        self.interface = interface
        self.threshold = threshold
        self.window = window
        self.output_file = output_file
        self.packet_counts = defaultdict(lambda: defaultdict(int))
        self.last_cleanup = time.time()
        self.lock = threading.Lock()
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            filename=self.output_file if self.output_file else None)
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet):
        with self.lock:
            current_time = time.time()
            
            if dot11.Dot11 in packet:
                if packet.type == 0 and packet.subtype == 12:  # Deauthentication
                    self.log_attack("Deauthentication", packet)
                elif packet.type == 0 and packet.subtype == 10:  # Disassociation
                    self.log_attack("Disassociation", packet)
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                
                self.packet_counts[src_ip][proto] += 1
                if self.packet_counts[src_ip][proto] > self.threshold:
                    self.log_attack(f"Potential DoS (IP Protocol {proto})", packet)
            
            if TCP in packet:
                src_ip = packet[IP].src
                flags = packet[TCP].flags
                
                if flags & 0x02:  # SYN flag
                    self.packet_counts[src_ip]["SYN"] += 1
                    if self.packet_counts[src_ip]["SYN"] > self.threshold:
                        self.log_attack("Potential SYN Flood", packet)
                
                if flags & 0x01:  # FIN flag
                    self.packet_counts[src_ip]["FIN"] += 1
                    if self.packet_counts[src_ip]["FIN"] > self.threshold:
                        self.log_attack("Potential FIN Flood", packet)
                
                if flags & 0x11:  # FIN-ACK flags
                    self.packet_counts[src_ip]["FINACK"] += 1
                    if self.packet_counts[src_ip]["FINACK"] > self.threshold:
                        self.log_attack("Potential FIN-ACK Flood", packet)
            
            if UDP in packet:
                src_ip = packet[IP].src
                self.packet_counts[src_ip]["UDP"] += 1
                if self.packet_counts[src_ip]["UDP"] > self.threshold:
                    self.log_attack("Potential UDP Flood", packet)
            
            if ICMP in packet:
                src_ip = packet[IP].src
                self.packet_counts[src_ip]["ICMP"] += 1
                if self.packet_counts[src_ip]["ICMP"] > self.threshold:
                    self.log_attack("Potential ICMP Flood", packet)
            
            if current_time - self.last_cleanup > self.window:
                self.cleanup_old_data()

    def log_attack(self, attack_type, packet):
        src_ip = packet[IP].src if IP in packet else packet.src
        dst_ip = packet[IP].dst if IP in packet else packet.dst
        log_message = f"{attack_type} detected from {src_ip} to {dst_ip}"
        self.logger.warning(log_message)

    def cleanup_old_data(self):
        with self.lock:
            self.packet_counts.clear()
            self.last_cleanup = time.time()

    def start_sniffing(self):
        self.logger.info(f"Starting network analysis on interface {self.interface}")
        sniff(iface=self.interface, prn=self.analyze_packet, store=0)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced DoS Attack Detector and Network Analyzer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to monitor")
    parser.add_argument("-t", "--threshold", type=int, default=100, help="Packet count threshold for DoS detection")
    parser.add_argument("-w", "--window", type=int, default=60, help="Time window for packet count (in seconds)")
    parser.add_argument("-o", "--output", help="Output file to save attack logs")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    try:
        analyzer = NetworkAnalyzer(args.interface, args.threshold, args.window, args.output)
        analyzer.start_sniffing()
    except KeyboardInterrupt:
        print("\n[*] Stopping network analysis...")
        sys.exit(0)
