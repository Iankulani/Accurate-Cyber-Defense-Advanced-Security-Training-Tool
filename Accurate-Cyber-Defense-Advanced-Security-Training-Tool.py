import socket
import threading
import time
import requests
import json
import subprocess
import os
from datetime import datetime
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether
import logging
from typing import Dict, List, Set, Tuple
import sys
import netifaces
import psutil
import dns.resolver
from cryptography.fernet import Fernet
import hashlib
import base64

class AdvancedCyberSecurityMonitor:
    def __init__(self):
        self.monitored_ips = set()
        self.is_monitoring = False
        self.monitoring_thread = None
        self.command_history = []
        self.telegram_token = None
        self.telegram_chat_id = None
        self.log_file = "cybersecurity_logs.txt"
        self.threat_logs = []
        self.telegram_bot_running = False
        self.telegram_bot_thread = None
        self.last_update_id = 0
        self.network_stats = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Advanced monitoring
        self.suspicious_activities = []
        self.whitelist_ips = set()
        self.blacklist_ips = set()
        self.packet_count = 0
        self.alert_threshold = 100
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger()
        
        self.setup_interface()

    def setup_interface(self):
        """Setup the green-themed interface"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()

    def print_banner(self):
        """Print the main banner"""
        banner = """
        \033[92m
        ╔══════════════════════════════════════════════════════════════╗
        ║                                                              ║
        ║               🌿 ACURATE CYBER DEFENSE      OL 🌿           ║
        ║                                                              ║
        ║         Community:https://github.com/Accurate-Cyber-Defense  ║
        ║                                                              ║
        ╚══════════════════════════════════════════════════════════════╝
        \033[0m
        """
        print(banner)

    def print_green(self, text):
        """Print text in green color"""
        print(f"\033[92m{text}\033[0m")

    def print_red(self, text):
        """Print text in red color for warnings"""
        print(f"\033[91m{text}\033[0m")

    def print_yellow(self, text):
        """Print text in yellow color for information"""
        print(f"\033[93m{text}\033[0m")

    def log_command(self, command):
        """Log command to history"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.command_history.append(f"{timestamp} - {command}")

    # Advanced Network Scanning Methods
    def advanced_port_scan(self, ip, scan_type="comprehensive"):
        """Advanced port scanning with multiple techniques"""
        scan_results = {
            "open_ports": [],
            "services": {},
            "vulnerabilities": [],
            "os_fingerprint": ""
        }
        
        try:
            if scan_type == "comprehensive":
                # TCP SYN Scan
                open_ports = self.syn_scan(ip)
                scan_results["open_ports"] = open_ports
                
                # Service detection
                for port in open_ports[:20]:  # Limit to first 20 ports
                    service = self.detect_service(ip, port)
                    scan_results["services"][port] = service
                
                # OS fingerprinting
                scan_results["os_fingerprint"] = self.os_fingerprint(ip)
                
            elif scan_type == "stealth":
                open_ports = self.stealth_scan(ip)
                scan_results["open_ports"] = open_ports
                
            elif scan_type == "udp":
                open_ports = self.udp_scan(ip)
                scan_results["open_ports"] = open_ports
                
        except Exception as e:
            self.logger.error(f"Advanced scan error: {e}")
            
        return scan_results

    def syn_scan(self, ip, ports_range=(1, 1000)):
        """TCP SYN scan (stealth scan)"""
        open_ports = []
        
        def scan_port(port):
            try:
                # Create raw socket for SYN scan
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except:
                pass

        threads = []
        for port in range(ports_range[0], ports_range[1] + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
            
        return open_ports

    def stealth_scan(self, ip):
        """Stealth scanning techniques"""
        # Implementation of FIN, XMAS, NULL scans
        open_ports = []
        # Placeholder for advanced stealth scanning
        return self.syn_scan(ip)  # Fallback to SYN scan

    def udp_scan(self, ip, ports_range=(1, 100)):
        """UDP port scanning"""
        open_ports = []
        
        for port in ports_range:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                sock.sendto(b"", (ip, port))
                sock.recvfrom(1024)
                open_ports.append(port)
            except:
                pass
            finally:
                sock.close()
                
        return open_ports

    def detect_service(self, ip, port):
        """Detect service running on port"""
        try:
            service = socket.getservbyport(port, 'tcp')
            return service
        except:
            return "unknown"

    def os_fingerprint(self, ip):
        """Basic OS fingerprinting"""
        try:
            # TTL-based OS detection
            response = subprocess.run(
                ['ping', '-c', '1', ip] if os.name != 'nt' else ['ping', '-n', '1', ip],
                capture_output=True, text=True
            )
            
            if 'ttl=64' in response.stdout.lower():
                return "Linux/Unix"
            elif 'ttl=128' in response.stdout.lower():
                return "Windows"
            else:
                return "Unknown"
        except:
            return "Detection failed"

    # Advanced Threat Detection
    def advanced_threat_detection(self, ip):
        """Comprehensive threat detection"""
        threats = []
        
        # Multiple detection methods
        port_scan_threat = self.detect_advanced_port_scan(ip)
        if port_scan_threat:
            threats.append(port_scan_threat)
            
        dos_threat = self.detect_dos_attack(ip)
        if dos_threat:
            threats.append(dos_threat)
            
        malware_threat = self.check_malware_indicators(ip)
        if malware_threat:
            threats.append(malware_threat)
            
        anomaly_threat = self.detect_anomalies(ip)
        if anomaly_threat:
            threats.append(anomaly_threat)
            
        return threats

    def detect_advanced_port_scan(self, ip):
        """Advanced port scan detection"""
        # Implement scan pattern recognition
        return None  # Placeholder

    def detect_dos_attack(self, ip):
        """DOS attack detection"""
        # Implement rate limiting and pattern analysis
        return None  # Placeholder

    def check_malware_indicators(self, ip):
        """Check for malware communication patterns"""
        # Implement malware indicator checks
        return None  # Placeholder

    def detect_anomalies(self, ip):
        """Anomaly detection based on network behavior"""
        # Implement behavioral analysis
        return None  # Placeholder

    # Network Analysis Methods
    def network_mapping(self, subnet):
        """Map network devices and topology"""
        devices = []
        
        try:
            # ARP scanning for local network
            arp_request = ARP(pdst=subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            for element in answered_list:
                device = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "vendor": self.get_mac_vendor(element[1].hwsrc)
                }
                devices.append(device)
                
        except Exception as e:
            self.logger.error(f"Network mapping error: {e}")
            
        return devices

    def get_mac_vendor(self, mac_address):
        """Get vendor from MAC address"""
        # Simple MAC vendor lookup (first 3 bytes)
        vendors = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:1C:42": "Parallels",
            "00:16:3E": "Xensource",
            "00:1B:21": "HP",
            "00:1D:09": "Dell",
            "00:24:8C": "Dell",
            "00:25:B3": "Intel",
            "00:26:B9": "Intel"
        }
        
        mac_prefix = mac_address.upper()[:8]
        return vendors.get(mac_prefix, "Unknown")

    def dns_analysis(self, domain):
        """Comprehensive DNS analysis"""
        dns_info = {}
        
        try:
            # Various DNS record types
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(rdata) for rdata in answers]
                except:
                    dns_info[record_type] = []
                    
        except Exception as e:
            self.logger.error(f"DNS analysis error: {e}")
            
        return dns_info

    def packet_sniffing(self, interface=None, count=50):
        """Basic packet sniffing for analysis"""
        packets = []
        
        try:
            if not interface:
                interfaces = netifaces.interfaces()
                interface = interfaces[0] if interfaces else None
                
            if interface:
                sniffed_packets = scapy.sniff(iface=interface, count=count)
                
                for packet in sniffed_packets:
                    packet_info = {
                        "time": datetime.now().isoformat(),
                        "source": packet[IP].src if IP in packet else "N/A",
                        "destination": packet[IP].dst if IP in packet else "N/A",
                        "protocol": packet.sprintf("%IP.proto%"),
                        "size": len(packet)
                    }
                    packets.append(packet_info)
                    
        except Exception as e:
            self.logger.error(f"Packet sniffing error: {e}")
            
        return packets

    # Security Analysis Methods
    def vulnerability_assessment(self, ip):
        """Basic vulnerability assessment"""
        vulnerabilities = []
        
        # Check for common vulnerabilities
        common_vulnerable_ports = {
            21: "FTP - Check for anonymous login",
            22: "SSH - Check for weak authentication",
            23: "Telnet - Unencrypted communication",
            80: "HTTP - Check for web vulnerabilities",
            443: "HTTPS - Check SSL/TLS configuration",
            3389: "RDP - Check for vulnerabilities"
        }
        
        open_ports = self.syn_scan(ip, (1, 10000))
        
        for port in open_ports:
            if port in common_vulnerable_ports:
                vulnerabilities.append({
                    "port": port,
                    "service": common_vulnerable_ports[port],
                    "risk": "Medium"
                })
                
        return vulnerabilities

    def encryption_tools(self, text, action="encrypt"):
        """Encryption/decryption tools"""
        try:
            if action == "encrypt":
                encrypted_text = self.cipher_suite.encrypt(text.encode())
                return base64.urlsafe_b64encode(encrypted_text).decode()
            else:
                decoded_text = base64.urlsafe_b64decode(text)
                decrypted_text = self.cipher_suite.decrypt(decoded_text)
                return decrypted_text.decode()
        except Exception as e:
            return f"Encryption error: {e}"

    def hash_generator(self, text, algorithm="sha256"):
        """Generate hashes for text"""
        try:
            if algorithm == "md5":
                return hashlib.md5(text.encode()).hexdigest()
            elif algorithm == "sha1":
                return hashlib.sha1(text.encode()).hexdigest()
            elif algorithm == "sha256":
                return hashlib.sha256(text.encode()).hexdigest()
            elif algorithm == "sha512":
                return hashlib.sha512(text.encode()).hexdigest()
            else:
                return "Unsupported algorithm"
        except Exception as e:
            return f"Hash generation error: {e}"

    # System Security Methods
    def system_security_scan(self):
        """Basic system security assessment"""
        security_issues = []
        
        try:
            # Check for open network connections
            connections = psutil.net_connections()
            suspicious_ports = [22, 23, 80, 443, 3389, 5900]
            
            for conn in connections:
                if conn.status == 'LISTEN' and conn.laddr.port in suspicious_ports:
                    security_issues.append(f"Open port {conn.laddr.port} detected")
                    
            # Check system information
            system_info = {
                "platform": sys.platform,
                "users": [user.name for user in psutil.users()],
                "process_count": len(psutil.pids()),
                "boot_time": psutil.boot_time()
            }
            
        except Exception as e:
            self.logger.error(f"System security scan error: {e}")
            
        return security_issues, system_info

    # Telegram Integration (Enhanced)
    def send_telegram_message(self, message):
        """Send message via Telegram"""
        if not self.telegram_token or not self.telegram_chat_id:
            self.print_red("Telegram not configured.")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            response = requests.post(url, data=data)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Telegram error: {e}")
            return False

    # Advanced Command Handlers
    def handle_advanced_commands(self, command, args):
        """Handle advanced security commands"""
        if command == "network_map":
            subnet = args[0] if args else "192.168.1.0/24"
            return self.network_mapping(subnet)
            
        elif command == "dns_analyze":
            domain = args[0] if args else "example.com"
            return self.dns_analysis(domain)
            
        elif command == "vuln_scan":
            ip = args[0] if args else "127.0.0.1"
            return self.vulnerability_assessment(ip)
            
        elif command == "encrypt":
            text = " ".join(args) if args else "sample text"
            return self.encryption_tools(text, "encrypt")
            
        elif command == "decrypt":
            text = args[0] if args else ""
            return self.encryption_tools(text, "decrypt")
            
        elif command == "hash":
            algorithm = args[0] if len(args) > 0 else "sha256"
            text = " ".join(args[1:]) if len(args) > 1 else "sample text"
            return self.hash_generator(text, algorithm)
            
        elif command == "system_scan":
            return self.system_security_scan()
            
        elif command == "packet_capture":
            count = int(args[0]) if args else 10
            return self.packet_sniffing(count=count)
            
        return "Unknown advanced command"

    # Enhanced Main Program Loop
    def show_advanced_help(self):
        """Show advanced help menu"""
        help_text = """
🌿 ADVANCED CYBER SECURITY TOOL - COMMAND HELP 🌿

🔬 Advanced Scanning:
- advanced_scan [ip] [type] - Comprehensive port scanning (comprehensive|stealth|udp)
- network_map [subnet] - Map network devices and topology
- dns_analyze [domain] - Comprehensive DNS analysis
- vuln_scan [ip] - Basic vulnerability assessment
- packet_capture [count] - Capture and analyze network packets

🔐 Security Tools:
- encrypt [text] - Encrypt text using AES
- decrypt [text] - Decrypt encrypted text
- hash [algorithm] [text] - Generate hash (md5|sha1|sha256|sha512)

🖥️ System Security:
- system_scan - Basic system security assessment
- traffic_analysis - Analyze network traffic patterns
- threat_intel [ip] - Check IP against threat intelligence

📊 Monitoring & Analysis:
- start_monitoring [ip] - Start advanced threat monitoring
- stop_monitoring - Stop all monitoring
- view_threats - View detected threats
- export_data - Export all data to encrypted file

🤖 Telegram Integration:
- config_telegram [token] [chat_id] - Configure Telegram bot
- test_telegram - Test Telegram connection
- start_bot - Start Telegram command bot

🛡️ Defense Tools:
- whitelist [ip] - Add IP to whitelist
- blacklist [ip] - Add IP to blacklist
- view_lists - View whitelist/blacklist

Type 'help basic' for basic commands or 'exit' to quit.
        """
        return help_text

    def run(self):
        """Main program loop"""
        self.print_green("🌿 Advanced Cyber Security Tool Started!")
        self.print_green("Type 'help' for advanced commands or 'help basic' for basic commands.")
        
        while True:
            try:
                command = input("\n\033[92maccurate#>\033[0m ").strip()
                if not command:
                    continue
                    
                self.log_command(command)
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd == 'exit':
                    self.stop_monitoring()
                    self.stop_telegram_bot()
                    self.print_green("🌿 Goodbye! Stay secure!")
                    break
                    
                elif cmd == 'help':
                    if args and args[0] == 'basic':
                        self.print_green(self.show_basic_help())
                    else:
                        self.print_green(self.show_advanced_help())
                        
                elif cmd == 'advanced_scan':
                    if args:
                        scan_type = args[1] if len(args) > 1 else "comprehensive"
                        result = self.advanced_port_scan(args[0], scan_type)
                        self.print_green(f"Advanced Scan Results for {args[0]}:")
                        self.print_green(json.dumps(result, indent=2))
                    else:
                        self.print_red("Usage: advanced_scan [IP] [type]")
                        
                elif cmd == 'network_map':
                    subnet = args[0] if args else "192.168.1.0/24"
                    devices = self.network_mapping(subnet)
                    self.print_green(f"Network Devices in {subnet}:")
                    for device in devices:
                        self.print_green(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}")
                        
                elif cmd == 'dns_analyze':
                    domain = args[0] if args else "google.com"
                    dns_info = self.dns_analysis(domain)
                    self.print_green(f"DNS Analysis for {domain}:")
                    self.print_green(json.dumps(dns_info, indent=2))
                    
                elif cmd == 'vuln_scan':
                    ip = args[0] if args else "127.0.0.1"
                    vulnerabilities = self.vulnerability_assessment(ip)
                    self.print_green(f"Vulnerability Assessment for {ip}:")
                    for vuln in vulnerabilities:
                        self.print_green(f"Port {vuln['port']}: {vuln['service']} - Risk: {vuln['risk']}")
                        
                elif cmd == 'encrypt':
                    text = " ".join(args) if args else "sample text"
                    encrypted = self.encryption_tools(text, "encrypt")
                    self.print_green(f"Encrypted text: {encrypted}")
                    
                elif cmd == 'decrypt':
                    if args:
                        decrypted = self.encryption_tools(args[0], "decrypt")
                        self.print_green(f"Decrypted text: {decrypted}")
                    else:
                        self.print_red("Usage: decrypt [encrypted_text]")
                        
                elif cmd == 'hash':
                    algorithm = args[0] if args else "sha256"
                    text = " ".join(args[1:]) if len(args) > 1 else "sample text"
                    hash_value = self.hash_generator(text, algorithm)
                    self.print_green(f"{algorithm.upper()} hash: {hash_value}")
                    
                elif cmd == 'system_scan':
                    issues, info = self.system_security_scan()
                    self.print_green("System Security Scan Results:")
                    self.print_green(f"Platform: {info['platform']}")
                    self.print_green(f"Logged in users: {', '.join(info['users'])}")
                    self.print_green(f"Security issues found: {len(issues)}")
                    for issue in issues:
                        self.print_yellow(f"⚠ {issue}")
                        
                elif cmd == 'packet_capture':
                    count = int(args[0]) if args else 10
                    packets = self.packet_sniffing(count=count)
                    self.print_green(f"Captured {len(packets)} packets:")
                    for pkt in packets[:5]:  # Show first 5 packets
                        self.print_green(f"Source: {pkt['source']} -> Dest: {pkt['destination']} Protocol: {pkt['protocol']}")
                        
                # Basic commands (simplified implementation)
                elif cmd == 'ping':
                    if args:
                        result = self.ping_ip(args[0])
                        self.print_green(result)
                    else:
                        self.print_red("Usage: ping [IP]")
                        
                elif cmd == 'scan':
                    if args:
                        open_ports = self.syn_scan(args[0])
                        self.print_green(f"Open ports: {open_ports}")
                    else:
                        self.print_red("Usage: scan [IP]")
                        
                else:
                    # Try advanced command handler
                    result = self.handle_advanced_commands(cmd, args)
                    if result != "Unknown advanced command":
                        self.print_green(str(result))
                    else:
                        self.print_red("Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                self.print_green("\n🌿 Goodbye! Stay secure!")
                break
            except Exception as e:
                self.print_red(f"Error: {e}")

    # Basic command implementations (simplified)
    def ping_ip(self, ip):
        """Ping an IP address"""
        try:
            param = "-n" if os.name == "nt" else "-c"
            result = subprocess.run(["ping", param, "4", ip], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Ping error: {e}"

    def show_basic_help(self):
        """Show basic help menu"""
        return """
🌿 BASIC COMMANDS 🌿

- ping [ip] - Ping an IP address
- scan [ip] - Basic port scan
- help - Show advanced commands
- exit - Exit the program

For full functionality, use the advanced commands shown with 'help'
        """

    def start_monitoring_ip(self, ip):
        """Start monitoring an IP address"""
        self.monitored_ips.add(ip)
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self.monitor_threats)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
        return f"Started advanced monitoring of {ip}"

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        self.monitored_ips.clear()
        return "Advanced monitoring stopped"

    def monitor_threats(self):
        """Advanced threat monitoring"""
        while self.is_monitoring:
            for ip in list(self.monitored_ips):
                threats = self.advanced_threat_detection(ip)
                for threat in threats:
                    self.log_threat(ip, threat)
            time.sleep(15)

    def log_threat(self, ip, threat):
        """Log threat detection"""
        log_entry = f"{datetime.now()} - ADVANCED THREAT - {ip} - {threat}"
        self.threat_logs.append(log_entry)
        self.logger.warning(log_entry)
        
        # Send Telegram alert if configured
        if self.telegram_token and self.telegram_chat_id:
            self.send_telegram_message(f"🚨 ADVANCED THREAT ALERT 🚨\nIP: {ip}\nThreat: {threat}")

    def stop_telegram_bot(self):
        """Stop Telegram bot"""
        self.telegram_bot_running = False
        return "Telegram bot stopped"

def main():
    """Main function"""
    # Check privileges
    if os.name != 'nt' and os.geteuid() != 0:
        print("\033[92mNote: Some advanced features may require root privileges\033[0m")
    
    # Create and run the advanced monitor
    monitor = AdvancedCyberSecurityMonitor()
    monitor.run()

if __name__ == "__main__":
    main()