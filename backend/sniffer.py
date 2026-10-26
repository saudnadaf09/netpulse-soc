from scapy.all import sniff, IP, TCP, UDP, Raw
import time
from collections import defaultdict
import datetime

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.total_bytes = 0
        self.protocols = defaultdict(int)
        self.top_ips = defaultdict(int)
        self.packets_buffer = []
        self.max_buffer_size = 50

    def classify_threat(self, src_port, dst_port, protocol_name):
        """Heuristics-based IDS Threat Detection Engine"""
        suspicious_ports = {
            4444: "Metasploit Reverse Shell (Critical)",
            3389: "RDP Access / Brute-Force Risk",
            22: "SSH Connection Attempt",
            445: "SMB Vulnerability / EternalBlue Risk",
            21: "FTP Plaintext Authentication"
        }
        
        for port in [src_port, dst_port]:
            if port in suspicious_ports:
                return True, suspicious_ports[port]
        return False, "SAFE"

    def packet_callback(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                pkt_size = len(packet)
                ttl = packet[IP].ttl
                
                self.packet_count += 1
                self.total_bytes += pkt_size
                self.top_ips[src_ip] += 1

                proto = "OTHER"
                src_port = 0
                dst_port = 0
                tcp_flags = "N/A"

                if TCP in packet:
                    proto = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    tcp_flags = str(packet[TCP].flags)
                elif UDP in packet:
                    proto = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport

                self.protocols[proto] += 1

                # Extract Payload Data for DPI
                payload_raw = "No Payload Data"
                if Raw in packet:
                    try:
                        payload_raw = packet[Raw].load.hex()[:128] # Truncated Hex string for UI preview
                    except Exception:
                        payload_raw = "Raw Binary Data"

                # Check Threat via Heuristics
                is_threat, threat_desc = self.classify_threat(src_port, dst_port, proto)

                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                country = "India (IN)" if not src_ip.startswith("192.168.") and not src_ip.startswith("10.") else "Local Network"

                pkt_data = {
                    "timestamp": timestamp,
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocol": proto,
                    "size": pkt_size,
                    "country": country,
                    "threat": is_threat,
                    "threat_desc": threat_desc,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "ttl": ttl,
                    "tcp_flags": tcp_flags,
                    "payload": payload_raw
                }

                self.packets_buffer.append(pkt_data)
                if len(self.packets_buffer) > self.max_buffer_size:
                    self.packets_buffer.pop(0)

        except Exception as e:
            print(f"[Sniffer Error]: {e}")

    def start_sniffing(self):
        sniff(prn=self.packet_callback, store=0)

    def get_stats(self):
        return {
            "total_packets": self.packet_count,
            "total_bytes": self.total_bytes,
            "protocols": dict(self.protocols),
            "top_ips": dict(sorted(self.top_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
            "packets": list(self.packets_buffer)
        }

sniffer_instance = NetworkSniffer()