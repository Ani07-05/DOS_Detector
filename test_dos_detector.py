import unittest
import os
import tempfile
from scapy.all import *
from dosdetector import NetworkAnalyzer
from scapy.layers.inet import IP, ICMP, UDP, TCP

class TestNetworkAnalyzer(unittest.TestCase):
    def setUp(self):
        # Create a temporary file for logging
        self.temp_log_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_log_file.close()
        self.analyzer = NetworkAnalyzer("test_iface", threshold=10, window=5, output_file=self.temp_log_file.name)

    def test_syn_flood(self):
        # Simulate SYN flood attack
        for _ in range(15):
            pkt = IP(src="192.168.1.100", dst="10.0.0.1")/TCP(sport=RandShort(), dport=80, flags="S")
            self.analyzer.analyze_packet(pkt)
        
        # Check if SYN flood was detected
        with open(self.temp_log_file.name, "r") as f:
            log_content = f.read()
            self.assertIn("Potential SYN Flood", log_content)

    def test_udp_flood(self):
        # Simulate UDP flood attack
        for _ in range(15):
            pkt = IP(src="192.168.1.101", dst="10.0.0.2")/UDP(sport=RandShort(), dport=53)/Raw(b"A"*100)
            self.analyzer.analyze_packet(pkt)
        
        # Check if UDP flood was detected
        with open(self.temp_log_file.name, "r") as f:
            log_content = f.read()
            self.assertIn("Potential UDP Flood", log_content)

    def test_icmp_flood(self):
        # Simulate ICMP flood attack
        for _ in range(15):
            pkt = IP(src="192.168.1.102", dst="10.0.0.3")/ICMP()
            self.analyzer.analyze_packet(pkt)
        
        # Check if ICMP flood was detected
        with open(self.temp_log_file.name, "r") as f:
            log_content = f.read()
            self.assertIn("Potential ICMP Flood", log_content)

    def test_fin_ack_flood(self):
        # Simulate FIN-ACK flood attack
        for _ in range(15):
            pkt = IP(src="192.168.1.103", dst="10.0.0.4")/TCP(sport=RandShort(), dport=80, flags="FA")
            self.analyzer.analyze_packet(pkt)
        
        # Check if FIN-ACK flood was detected
        with open(self.temp_log_file.name, "r") as f:
            log_content = f.read()
            self.assertIn("Potential FIN-ACK Flood", log_content)

    def test_normal_traffic(self):
        # Simulate normal traffic
        for _ in range(5):
            pkt = IP(src="192.168.1.104", dst="10.0.0.5")/TCP(sport=RandShort(), dport=80, flags="S")
            self.analyzer.analyze_packet(pkt)
        
        # Check that no attack was detected
        with open(self.temp_log_file.name, "r") as f:
            log_content = f.read()
            self.assertNotIn("Potential", log_content)

    def tearDown(self):
        # Clean up the test output file
        if os.path.exists(self.temp_log_file.name):
            os.remove(self.temp_log_file.name)

if __name__ == "__main__":
    unittest.main()
