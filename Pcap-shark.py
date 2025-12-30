#!/usr/bin/env python3
"""
PCAP Credential Analyzer - Extract cleartext data from insecure protocols
Analyzes PCAP files for credentials, usernames, emails, and sensitive data
"""

import sys
import re
import base64
from collections import defaultdict
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    print("[!] Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class PCAPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.findings = defaultdict(list)
        self.stats = defaultdict(int)
        
        # Regex patterns for sensitive data
        self.patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'password_field': re.compile(r'(?i)(pass(?:word|wd)?|pwd|secret|auth)[=:\s]+([^\s&\r\n]+)', re.IGNORECASE),
            'user_field': re.compile(r'(?i)(user(?:name)?|login|account|uid)[=:\s]+([^\s&\r\n]+)', re.IGNORECASE),
            'auth_basic': re.compile(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.IGNORECASE),
            'cookie': re.compile(r'(?i)Cookie:\s*(.+)', re.IGNORECASE),
            'session': re.compile(r'(?i)(session|sess|token|apikey)[=:\s]+([^\s&\r\n;]+)', re.IGNORECASE),
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{'='*70}
    PCAP Credential Analyzer
    Analyzing: {self.pcap_file}
{'='*70}{Colors.END}
"""
        print(banner)

    def add_finding(self, protocol, severity, description, details):
        self.findings[protocol].append({
            'severity': severity,
            'description': description,
            'details': details
        })
        self.stats[protocol] += 1

    def extract_payload(self, packet):
        """Extract payload from packet"""
        if packet.haslayer(Raw):
            try:
                return packet[Raw].load.decode('utf-8', errors='ignore')
            except:
                return packet[Raw].load.decode('latin-1', errors='ignore')
        return ""

    def analyze_http(self, packet):
        """Analyze HTTP traffic"""
        payload = self.extract_payload(packet)
        
        if not payload:
            return
            
        # HTTP Basic Authentication
        if 'Authorization: Basic' in payload:
            match = self.patterns['auth_basic'].search(payload)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8', errors='ignore')
                    self.add_finding('HTTP', 'HIGH', 'Basic Auth Credentials', {
                        'credentials': decoded,
                        'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
                        'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A'
                    })
                except:
                    pass
        
        # POST data with credentials
        if 'POST' in payload[:50]:
            # Extract username
            user_match = self.patterns['user_field'].search(payload)
            # Extract password
            pass_match = self.patterns['password_field'].search(payload)
            
            if user_match or pass_match:
                self.add_finding('HTTP', 'HIGH', 'POST Credentials', {
                    'username': user_match.group(2) if user_match else 'N/A',
                    'password': pass_match.group(2) if pass_match else 'N/A',
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
                    'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A',
                    'url': self.extract_url(payload)
                })
        
        # Cookies
        cookie_match = self.patterns['cookie'].search(payload)
        if cookie_match:
            self.add_finding('HTTP', 'MEDIUM', 'Cookie', {
                'cookie': cookie_match.group(1)[:100],
                'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
            })
        
        # Session tokens
        session_match = self.patterns['session'].search(payload)
        if session_match:
            self.add_finding('HTTP', 'MEDIUM', 'Session Token', {
                'type': session_match.group(1),
                'token': session_match.group(2)[:50],
                'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
            })
        
        # Email addresses
        emails = self.patterns['email'].findall(payload)
        if emails:
            for email in set(emails):
                self.add_finding('HTTP', 'LOW', 'Email Address', {
                    'email': email,
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                })

    def extract_url(self, payload):
        """Extract URL from HTTP request"""
        lines = payload.split('\r\n')
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                return parts[1]
        return 'N/A'

    def analyze_ftp(self, packet):
        """Analyze FTP traffic"""
        if packet.haslayer(TCP) and packet[TCP].dport == 21 or packet[TCP].sport == 21:
            payload = self.extract_payload(packet)
            
            if 'USER ' in payload:
                username = payload.split('USER ')[1].split('\r\n')[0].strip()
                self.add_finding('FTP', 'HIGH', 'Username', {
                    'username': username,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })
            
            if 'PASS ' in payload:
                password = payload.split('PASS ')[1].split('\r\n')[0].strip()
                self.add_finding('FTP', 'CRITICAL', 'Password', {
                    'password': password,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })

    def analyze_telnet(self, packet):
        """Analyze Telnet traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 23 or packet[TCP].sport == 23):
            payload = self.extract_payload(packet)
            
            if payload and len(payload.strip()) > 0:
                # Look for login prompts and credentials
                if any(keyword in payload.lower() for keyword in ['login:', 'username:', 'password:']):
                    self.add_finding('Telnet', 'HIGH', 'Login Prompt Detected', {
                        'data': payload[:100],
                        'src': packet[IP].src,
                        'dst': packet[IP].dst
                    })
                elif len(payload.strip()) > 3 and payload.isprintable():
                    self.add_finding('Telnet', 'MEDIUM', 'Cleartext Data', {
                        'data': payload[:100],
                        'src': packet[IP].src,
                        'dst': packet[IP].dst
                    })

    def analyze_smtp(self, packet):
        """Analyze SMTP traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 25 or packet[TCP].sport == 25):
            payload = self.extract_payload(packet)
            
            if 'AUTH LOGIN' in payload:
                self.add_finding('SMTP', 'HIGH', 'AUTH LOGIN Detected', {
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })
            
            # Look for base64 encoded credentials after AUTH LOGIN
            if payload and len(payload) < 100:
                try:
                    decoded = base64.b64decode(payload.strip()).decode('utf-8', errors='ignore')
                    if decoded and len(decoded) > 3:
                        self.add_finding('SMTP', 'HIGH', 'Potential Credential', {
                            'decoded': decoded,
                            'src': packet[IP].src,
                            'dst': packet[IP].dst
                        })
                except:
                    pass
            
            # Look for MAIL FROM and RCPT TO
            if 'MAIL FROM:' in payload or 'RCPT TO:' in payload:
                emails = self.patterns['email'].findall(payload)
                for email in emails:
                    self.add_finding('SMTP', 'LOW', 'Email Address', {
                        'email': email,
                        'src': packet[IP].src
                    })

    def analyze_pop3(self, packet):
        """Analyze POP3 traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 110 or packet[TCP].sport == 110):
            payload = self.extract_payload(packet)
            
            if 'USER ' in payload:
                username = payload.split('USER ')[1].split('\r\n')[0].strip()
                self.add_finding('POP3', 'HIGH', 'Username', {
                    'username': username,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })
            
            if 'PASS ' in payload:
                password = payload.split('PASS ')[1].split('\r\n')[0].strip()
                self.add_finding('POP3', 'CRITICAL', 'Password', {
                    'password': password,
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })

    def analyze_imap(self, packet):
        """Analyze IMAP traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 143 or packet[TCP].sport == 143):
            payload = self.extract_payload(packet)
            
            if 'LOGIN' in payload:
                # IMAP LOGIN command format: tag LOGIN username password
                parts = payload.split()
                if len(parts) >= 4 and parts[1] == 'LOGIN':
                    self.add_finding('IMAP', 'CRITICAL', 'Login Credentials', {
                        'username': parts[2],
                        'password': parts[3] if len(parts) > 3 else 'N/A',
                        'src': packet[IP].src,
                        'dst': packet[IP].dst
                    })

    def analyze_snmp(self, packet):
        """Analyze SNMP traffic"""
        if packet.haslayer(UDP) and (packet[UDP].dport == 161 or packet[UDP].sport == 161):
            payload = self.extract_payload(packet)
            
            # SNMP community strings are often in plaintext
            if 'public' in payload.lower() or 'private' in payload.lower():
                self.add_finding('SNMP', 'MEDIUM', 'Community String', {
                    'data': payload[:50],
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
                    'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A'
                })

    def analyze_ldap(self, packet):
        """Analyze LDAP traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 389 or packet[TCP].sport == 389):
            payload = self.extract_payload(packet)
            
            if payload:
                # Look for LDAP bind operations
                if 'simple' in payload.lower() or 'bindrequest' in payload.lower():
                    self.add_finding('LDAP', 'HIGH', 'Bind Request', {
                        'data': payload[:100],
                        'src': packet[IP].src,
                        'dst': packet[IP].dst
                    })

    def analyze_dns(self, packet):
        """Analyze DNS traffic"""
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            
            if dns_layer.qd:
                query = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                self.add_finding('DNS', 'INFO', 'Query', {
                    'query': query,
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                })

    def analyze_tftp(self, packet):
        """Analyze TFTP traffic"""
        if packet.haslayer(UDP) and (packet[UDP].dport == 69 or packet[UDP].sport == 69):
            payload = self.extract_payload(packet)
            
            if payload:
                self.add_finding('TFTP', 'MEDIUM', 'File Transfer', {
                    'data': payload[:50],
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
                    'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A'
                })

    def analyze_vnc(self, packet):
        """Analyze VNC traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 5900 or packet[TCP].sport == 5900 or 
                                     5901 <= packet[TCP].dport <= 5909):
            payload = self.extract_payload(packet)
            
            if 'RFB' in payload[:10]:
                self.add_finding('VNC', 'MEDIUM', 'VNC Handshake', {
                    'version': payload[:12],
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })

    def analyze_smb(self, packet):
        """Analyze SMB traffic"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 445 or packet[TCP].sport == 445 or
                                     packet[TCP].dport == 139 or packet[TCP].sport == 139):
            payload = self.extract_payload(packet)
            
            if payload and ('SMB' in payload[:10] or 'NTLMSSP' in payload):
                self.add_finding('SMB', 'MEDIUM', 'SMB Traffic', {
                    'data': payload[:50],
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })

    def analyze_netbios(self, packet):
        """Analyze NetBIOS traffic"""
        if packet.haslayer(UDP) and (packet[UDP].dport == 137 or packet[UDP].sport == 137):
            payload = self.extract_payload(packet)
            
            if payload:
                self.add_finding('NetBIOS', 'LOW', 'NetBIOS Name Service', {
                    'data': payload[:50],
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                })

    def analyze_ntp(self, packet):
        """Analyze NTP traffic"""
        if packet.haslayer(UDP) and (packet[UDP].dport == 123 or packet[UDP].sport == 123):
            payload = self.extract_payload(packet)
            
            if payload:
                self.add_finding('NTP', 'LOW', 'NTP Traffic', {
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
                    'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A'
                })

    def analyze_syslog(self, packet):
        """Analyze Syslog traffic"""
        if packet.haslayer(UDP) and packet[UDP].dport == 514:
            payload = self.extract_payload(packet)
            
            if payload:
                self.add_finding('Syslog', 'LOW', 'Syslog Message', {
                    'message': payload[:100],
                    'src': packet[IP].src if packet.haslayer(IP) else 'N/A'
                })

    def analyze_packet(self, packet):
        """Analyze a single packet"""
        try:
            # Analyze different protocols
            self.analyze_http(packet)
            self.analyze_ftp(packet)
            self.analyze_telnet(packet)
            self.analyze_smtp(packet)
            self.analyze_pop3(packet)
            self.analyze_imap(packet)
            self.analyze_snmp(packet)
            self.analyze_ldap(packet)
            self.analyze_dns(packet)
            self.analyze_tftp(packet)
            self.analyze_vnc(packet)
            self.analyze_smb(packet)
            self.analyze_netbios(packet)
            self.analyze_ntp(packet)
            self.analyze_syslog(packet)
            
        except Exception as e:
            pass  # Silently skip problematic packets

    def print_findings(self):
        """Print all findings in a formatted way"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== ANALYSIS RESULTS ==={Colors.END}\n")
        
        severity_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.YELLOW,
            'MEDIUM': Colors.CYAN,
            'LOW': Colors.GREEN,
            'INFO': Colors.BLUE
        }
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No sensitive data found in cleartext{Colors.END}")
            return
        
        # Print statistics
        print(f"{Colors.BOLD}Statistics:{Colors.END}")
        for protocol, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {protocol}: {count} findings")
        print()
        
        # Print findings by protocol
        for protocol in sorted(self.findings.keys()):
            findings = self.findings[protocol]
            print(f"{Colors.BOLD}{Colors.CYAN}[{protocol}] - {len(findings)} findings{Colors.END}")
            print("-" * 70)
            
            for idx, finding in enumerate(findings, 1):
                severity = finding['severity']
                color = severity_colors.get(severity, Colors.END)
                
                print(f"{color}  [{severity}] {finding['description']}{Colors.END}")
                
                for key, value in finding['details'].items():
                    if isinstance(value, str) and len(value) > 100:
                        value = value[:100] + "..."
                    print(f"    {key}: {value}")
                
                if idx < len(findings):
                    print()
            
            print()

    def save_report(self, output_file):
        """Save findings to a file"""
        with open(output_file, 'w') as f:
            f.write("PCAP CREDENTIAL ANALYZER REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"PCAP File: {self.pcap_file}\n\n")
            
            f.write("STATISTICS\n")
            f.write("-" * 70 + "\n")
            for protocol, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{protocol}: {count} findings\n")
            f.write("\n")
            
            f.write("DETAILED FINDINGS\n")
            f.write("=" * 70 + "\n\n")
            
            for protocol in sorted(self.findings.keys()):
                findings = self.findings[protocol]
                f.write(f"[{protocol}] - {len(findings)} findings\n")
                f.write("-" * 70 + "\n")
                
                for idx, finding in enumerate(findings, 1):
                    f.write(f"  [{finding['severity']}] {finding['description']}\n")
                    
                    for key, value in finding['details'].items():
                        if isinstance(value, str) and len(value) > 200:
                            value = value[:200] + "..."
                        f.write(f"    {key}: {value}\n")
                    
                    f.write("\n")
                
                f.write("\n")

    def analyze(self):
        """Main analysis function"""
        self.print_banner()
        
        print(f"{Colors.YELLOW}[*] Loading PCAP file...{Colors.END}")
        
        try:
            packets = rdpcap(self.pcap_file)
            total_packets = len(packets)
            print(f"{Colors.GREEN}[+] Loaded {total_packets} packets{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading PCAP: {e}{Colors.END}")
            return
        
        print(f"{Colors.YELLOW}[*] Analyzing packets...{Colors.END}")
        
        for idx, packet in enumerate(packets, 1):
            if idx % 1000 == 0:
                print(f"{Colors.YELLOW}[*] Processed {idx}/{total_packets} packets...{Colors.END}", end='\r')
            self.analyze_packet(packet)
        
        print(f"{Colors.GREEN}[+] Analysis complete!{Colors.END}" + " " * 30)
        
        self.print_findings()

def main():
    if len(sys.argv) < 2:
        print(f"""
{Colors.CYAN}Usage: {sys.argv[0]} <pcap_file> [output_file]{Colors.END}

{Colors.BOLD}Description:{Colors.END}
  Analyzes PCAP files for cleartext credentials and sensitive data
  across multiple insecure protocols.

{Colors.BOLD}Supported Protocols:{Colors.END}
  HTTP, FTP, Telnet, SMTP, POP3, IMAP, SNMP, LDAP, SMB, NetBIOS,
  TFTP, VNC, DNS, Syslog, NTP, and more

{Colors.BOLD}Examples:{Colors.END}
  {sys.argv[0]} capture.pcap
  {sys.argv[0]} capture.pcap report.txt
""")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(pcap_file):
        print(f"{Colors.RED}[!] Error: File '{pcap_file}' not found{Colors.END}")
        sys.exit(1)
    
    analyzer = PCAPAnalyzer(pcap_file)
    analyzer.analyze()
    
    if output_file:
        print(f"\n{Colors.YELLOW}[*] Saving report to {output_file}...{Colors.END}")
        analyzer.save_report(output_file)
        print(f"{Colors.GREEN}[+] Report saved successfully{Colors.END}")

if __name__ == "__main__":
    main()