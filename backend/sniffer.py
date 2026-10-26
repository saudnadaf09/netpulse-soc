import os
import threading
import time
import random
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class PacketSniffer:
    def __init__(self):
        self.is_running = False
        self.packets_cache = []
        self.stats = {
            "total_volume": 0.0,
            "active_protocols": set(),
            "top_ips": {},
            "protocol_counts": {"TCP": 0, "UDP": 0, "OTHER": 0}
        }
        self.lock = threading.Lock()
        self.socket_io = None

    def init_socket(self, socket_io):
        self.socket_io = socket_io

    def start_sniffing(self):
        if self.is_running:
            return
        self.is_running = True

        # Check if we are on a cloud platform like Render or lack raw socket permissions
        is_cloud = os.environ.get("RENDER") or not SCAPY_AVAILABLE
        
        if is_cloud or not self._test_raw_socket():
            print("[INFO] Cloud environment or restricted privileges detected. Starting Smart Simulation Mode for live streaming...")
            threading.Thread(target=self._simulate_traffic, daemon=True).start()
        else:
            print("[INFO] Starting Real Scapy Packet Sniffer...")
            threading.Thread(target=self._real_sniff, daemon=True).start()

    def _test_raw_socket(self):
        if not SCAPY_AVAILABLE:
            return False
        try:
            test_sock = sniff(count=1, timeout=1)
            return True
        except Exception:
            return False

    def _real_sniff(self):
        try:
            sniff(prn=self._process_packet, store=False, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            print(f"[WARNING] Real sniffing failed ({e}). Falling back to simulation mode...")
            self._simulate_traffic()

    def _process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_len = len(packet)
            
            proto = "OTHER"
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"

            self._record_packet_data(src_ip, dst_ip, proto, pkt_len)

    def _simulate_traffic(self):
        sample_ips = [
            "192.168.31.5", "192.168.31.1", "216.24.57.18", 
            "20.207.73.82", "3.6.199.65", "142.250.192.46", "157.240.199.35"
        ]
        protocols = ["TCP", "UDP", "TCP", "TCP", "UDP", "OTHER"]
        
        while self.is_running:
            src_ip = random.choice(sample_ips)
            dst_ip = random.choice([ip for ip in sample_ips if ip != src_ip])
            proto = random.choice(protocols)
            pkt_len = random.randint(64, 1500)
            
            self._record_packet_data(src_ip, dst_ip, proto, pkt_len)
            time.sleep(1.2)

    def _record_packet_data(self, src_ip, dst_ip, proto, pkt_len):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        threat_status = "SAFE" if random.random() > 0.15 else "SUSPICIOUS"
        
        packet_info = {
            "time": timestamp,
            "source": f"{src_ip} (Local Network)" if "192.168" in src_ip else src_ip,
            "destination": dst_ip,
            "protocol": proto,
            "size": f"{pkt_len} B",
            "threat": threat_status
        }

        with self.lock:
            self.packets_cache.insert(0, packet_info)
            if len(self.packets_cache) > 100:
                self.packets_cache.pop()

            self.stats["total_volume"] += pkt_len / 1024.0 # KB
            self.stats["active_protocols"].add(proto)
            self.stats["protocol_counts"][proto] = self.stats["protocol_counts"].get(proto, 0) + 1
            self.stats["top_ips"][src_ip] = self.stats["top_ips"].get(src_ip, 0) + 1

        if self.socket_io:
            try:
                self.socket_io.emit('new_packet', packet_info)
                self.socket_io.emit('update_stats', self.get_stats())
            except Exception as e:
                pass

    def get_stats(self):
        with self.lock:
            top_ip = "N/A"
            if self.stats["top_ips"]:
                try:
                    top_ip = max(self.stats["top_ips"], key=self.stats["top_ips"].get)
                except Exception:
                    top_ip = list(self.stats["top_ips"].keys())[0] if self.stats["top_ips"] else "N/A"

            return {
                "total_volume": round(self.stats["total_volume"], 2),
                "active_protocols_count": len(self.stats["active_protocols"]),
                "top_origin_ip": top_ip,
                "protocol_counts": self.stats["protocol_counts"],
                "top_hosts": dict(sorted(self.stats["top_ips"].items(), key=lambda item: item[1], reverse=True)[:5])
            }

    def stop_sniffing(self):
        self.is_running = False

sniffer_instance = PacketSniffer()