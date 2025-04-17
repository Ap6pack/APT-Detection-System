"""
Network Event Generator Module

This module provides the NetworkEventGenerator class for generating network security events.
"""

import random
import ipaddress
from typing import Dict, Any
from .base_generator import BaseEventGenerator

class NetworkEventGenerator(BaseEventGenerator):
    """Generator for network security events."""
    
    def generate_event(self) -> Dict[str, Any]:
        """
        Generate a network security event.
        
        Returns:
            Network event data
        """
        # Select a random event type
        event_types = [
            self._generate_connection_event,
            self._generate_port_scan_event,
            self._generate_traffic_spike_event,
            self._generate_dns_query_event,
            self._generate_firewall_event
        ]
        
        generator = random.choice(event_types)
        return generator()
    
    def _generate_connection_event(self) -> Dict[str, Any]:
        """
        Generate a network connection event.
        
        Returns:
            Connection event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Add event-specific data
        event.update({
            "event_type": "network_connection",
            "entity": host.get_id(),
            "entity_type": "host",
            "source_ip": host.get_attribute("ip_address"),
            "destination_ip": self._generate_random_ip(),
            "destination_port": random.choice([80, 443, 22, 25, 53, 3389, 445, 8080, 8443]),
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes_sent": random.randint(100, 10000),
            "bytes_received": random.randint(100, 10000),
            "connection_duration": random.randint(1, 300),  # seconds
            "connection_status": random.choice(["established", "closed", "reset", "timeout"])
        })
        
        # Add MITRE ATT&CK mapping for suspicious connections
        if random.random() < 0.1:  # 10% chance of suspicious connection
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            event["reason"] = random.choice([
                "connection to known malicious IP",
                "unusual destination port",
                "unusual protocol",
                "unusual traffic volume",
                "unusual time of day"
            ])
            
            # Add MITRE ATT&CK mapping
            technique_ids = random.sample([
                'T1071',  # Application Layer Protocol
                'T1095',  # Non-Application Layer Protocol
                'T1571',  # Non-Standard Port
                'T1572',  # Protocol Tunneling
                'T1041'   # Exfiltration Over C2 Channel
            ], k=random.randint(1, 3))
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_port_scan_event(self) -> Dict[str, Any]:
        """
        Generate a port scan event.
        
        Returns:
            Port scan event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Add event-specific data
        event.update({
            "event_type": "port_scan",
            "entity": host.get_id(),
            "entity_type": "host",
            "target_ip": host.get_attribute("ip_address"),
            "source_ip": self._generate_random_ip(),
            "scan_type": random.choice(["SYN", "FIN", "XMAS", "NULL", "ACK"]),
            "ports_scanned": random.randint(1, 1000),
            "duration": random.randint(1, 60),  # seconds
            "severity": random.choice(["Medium", "High"]),
            "suspicious": True,
            "reason": "port scan detected"
        })
        
        # Add MITRE ATT&CK mapping
        technique_ids = ['T1046']  # Network Service Scanning
        self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_traffic_spike_event(self) -> Dict[str, Any]:
        """
        Generate a traffic spike event.
        
        Returns:
            Traffic spike event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Add event-specific data
        event.update({
            "event_type": "traffic_spike",
            "entity": host.get_id(),
            "entity_type": "host",
            "source_ip": host.get_attribute("ip_address"),
            "destination_ip": self._generate_random_ip(),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "bytes_sent": random.randint(10000, 1000000),
            "normal_bytes_sent": random.randint(1000, 5000),
            "duration": random.randint(60, 300),  # seconds
            "severity": random.choice(["Medium", "High"]),
            "suspicious": True,
            "reason": "unusual traffic volume"
        })
        
        # Add MITRE ATT&CK mapping
        technique_ids = random.sample([
            'T1041',  # Exfiltration Over C2 Channel
            'T1048',  # Exfiltration Over Alternative Protocol
            'T1567',  # Exfiltration Over Web Service
            'T1020'   # Automated Exfiltration
        ], k=random.randint(1, 2))
        
        self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_dns_query_event(self) -> Dict[str, Any]:
        """
        Generate a DNS query event.
        
        Returns:
            DNS query event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Generate domain
        domains = [
            "example.com",
            "google.com",
            "microsoft.com",
            "amazon.com",
            "facebook.com",
            "apple.com",
            "github.com",
            "stackoverflow.com",
            "wikipedia.org",
            "reddit.com"
        ]
        
        suspicious_domains = [
            "malware-domain.com",
            "evil-site.net",
            "phishing-attempt.org",
            "suspicious-domain.ru",
            "command-control.cn"
        ]
        
        is_suspicious = random.random() < 0.1  # 10% chance of suspicious domain
        domain = random.choice(suspicious_domains if is_suspicious else domains)
        
        # Add event-specific data
        event.update({
            "event_type": "dns_query",
            "entity": host.get_id(),
            "entity_type": "host",
            "source_ip": host.get_attribute("ip_address"),
            "domain": domain,
            "query_type": random.choice(["A", "AAAA", "MX", "TXT", "CNAME"]),
            "response_code": random.choice(["NOERROR", "NXDOMAIN", "SERVFAIL"]),
            "response_time": random.randint(1, 500)  # milliseconds
        })
        
        if is_suspicious:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            event["reason"] = "query to suspicious domain"
            
            # Add MITRE ATT&CK mapping
            technique_ids = random.sample([
                'T1071.004',  # Application Layer Protocol: DNS
                'T1568',      # Dynamic Resolution
                'T1008',      # Fallback Channels
                'T1105'       # Ingress Tool Transfer
            ], k=random.randint(1, 2))
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_firewall_event(self) -> Dict[str, Any]:
        """
        Generate a firewall event.
        
        Returns:
            Firewall event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Add event-specific data
        event.update({
            "event_type": "firewall",
            "entity": host.get_id(),
            "entity_type": "host",
            "source_ip": self._generate_random_ip(),
            "destination_ip": host.get_attribute("ip_address"),
            "destination_port": random.choice([22, 3389, 445, 1433, 3306, 5432, 8080, 8443]),
            "protocol": random.choice(["TCP", "UDP"]),
            "action": random.choice(["block", "allow", "drop", "reject"]),
            "rule_id": f"FW-{random.randint(1000, 9999)}"
        })
        
        if event["action"] in ["block", "drop", "reject"]:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            event["reason"] = f"blocked connection to port {event['destination_port']}"
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            # Map specific ports to techniques
            port_technique_map = {
                22: ['T1021.004'],    # Remote Services: SSH
                3389: ['T1021.001'],  # Remote Services: RDP
                445: ['T1021.002'],   # Remote Services: SMB
                1433: ['T1190'],      # Exploit Public-Facing Application
                3306: ['T1190'],      # Exploit Public-Facing Application
                5432: ['T1190']       # Exploit Public-Facing Application
            }
            
            if event["destination_port"] in port_technique_map:
                technique_ids.extend(port_technique_map[event["destination_port"]])
            else:
                technique_ids.append('T1190')  # Exploit Public-Facing Application
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_random_ip(self) -> str:
        """
        Generate a random IP address.
        
        Returns:
            Random IP address
        """
        # 10% chance of generating a public IP
        if random.random() < 0.1:
            # Generate a public IP (non-private, non-reserved)
            while True:
                ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                
                # Skip private and reserved ranges
                if not ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_reserved:
                    return ip
        else:
            # Generate a private IP
            subnet = random.choice([
                "192.168.0.0/16",
                "10.0.0.0/8",
                "172.16.0.0/12"
            ])
            
            network = ipaddress.IPv4Network(subnet)
            host_bits = network.max_prefixlen - network.prefixlen
            host_number = random.randint(1, (2 ** host_bits) - 2)
            ip = network.network_address + host_number
            
            return str(ip)
