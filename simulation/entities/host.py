"""
Host Entity Module

This module provides the Host entity class for the simulation system.
"""

import random
import ipaddress
from typing import Dict, Any, List
from datetime import datetime

from .entity import Entity

class Host(Entity):
    """Host entity class representing a computer system."""
    
    def __init__(self, host_id: str):
        """
        Initialize the host entity.
        
        Args:
            host_id: Unique identifier for the host
        """
        super().__init__(host_id, entity_type="host")
        
        # Set default attributes
        self.set_attribute("hostname", host_id)
        self.set_attribute("ip_address", self._generate_ip_address())
        self.set_attribute("os", self._generate_os())
        self.set_attribute("services", self._generate_services())
        
        # Set default state
        self.set_state("status", "online")
        self.set_state("cpu_usage", random.uniform(0.1, 0.3))
        self.set_state("memory_usage", random.uniform(0.2, 0.4))
        self.set_state("disk_usage", random.uniform(0.3, 0.5))
        self.set_state("network_traffic", random.uniform(0.1, 0.2))
    
    def _generate_ip_address(self) -> str:
        """
        Generate a random IP address.
        
        Returns:
            Random IP address
        """
        # Generate a random private IP address
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
    
    def _generate_os(self) -> Dict[str, str]:
        """
        Generate a random operating system.
        
        Returns:
            Operating system information
        """
        os_types = [
            {"name": "Windows", "version": random.choice(["10", "11", "Server 2019", "Server 2022"])},
            {"name": "Linux", "version": random.choice(["Ubuntu 20.04", "CentOS 8", "Debian 11", "RHEL 8"])},
            {"name": "macOS", "version": random.choice(["Monterey", "Ventura", "Sonoma"])}
        ]
        
        return random.choice(os_types)
    
    def _generate_services(self) -> List[Dict[str, Any]]:
        """
        Generate a list of running services.
        
        Returns:
            List of services
        """
        all_services = [
            {"name": "SSH", "port": 22, "status": "running"},
            {"name": "HTTP", "port": 80, "status": "running"},
            {"name": "HTTPS", "port": 443, "status": "running"},
            {"name": "FTP", "port": 21, "status": "stopped"},
            {"name": "SMB", "port": 445, "status": "running"},
            {"name": "DNS", "port": 53, "status": "running"},
            {"name": "SMTP", "port": 25, "status": "stopped"},
            {"name": "RDP", "port": 3389, "status": "stopped"},
            {"name": "Database", "port": 3306, "status": "running"},
            {"name": "NTP", "port": 123, "status": "running"}
        ]
        
        # Select a random number of services
        num_services = random.randint(3, 6)
        return random.sample(all_services, num_services)
    
    def update_state(self) -> None:
        """Update the host state with random variations."""
        # Update CPU usage with small random variation
        current_cpu = self.get_state("cpu_usage", 0.2)
        new_cpu = max(0.05, min(0.95, current_cpu + random.uniform(-0.05, 0.05)))
        self.set_state("cpu_usage", new_cpu)
        
        # Update memory usage with small random variation
        current_memory = self.get_state("memory_usage", 0.3)
        new_memory = max(0.1, min(0.9, current_memory + random.uniform(-0.03, 0.03)))
        self.set_state("memory_usage", new_memory)
        
        # Update disk usage with small random variation
        current_disk = self.get_state("disk_usage", 0.4)
        new_disk = max(0.2, min(0.85, current_disk + random.uniform(-0.01, 0.01)))
        self.set_state("disk_usage", new_disk)
        
        # Update network traffic with small random variation
        current_network = self.get_state("network_traffic", 0.15)
        new_network = max(0.05, min(0.8, current_network + random.uniform(-0.04, 0.04)))
        self.set_state("network_traffic", new_network)
    
    def simulate_high_cpu(self) -> None:
        """Simulate high CPU usage."""
        self.set_state("cpu_usage", random.uniform(0.8, 0.95))
    
    def simulate_high_memory(self) -> None:
        """Simulate high memory usage."""
        self.set_state("memory_usage", random.uniform(0.8, 0.95))
    
    def simulate_high_disk(self) -> None:
        """Simulate high disk usage."""
        self.set_state("disk_usage", random.uniform(0.8, 0.95))
    
    def simulate_high_network(self) -> None:
        """Simulate high network traffic."""
        self.set_state("network_traffic", random.uniform(0.8, 0.95))
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the host to a dictionary.
        
        Returns:
            Host as a dictionary
        """
        base_dict = super().to_dict()
        
        # Add host-specific information
        host_dict = {
            "hostname": self.get_attribute("hostname"),
            "ip_address": self.get_attribute("ip_address"),
            "os": self.get_attribute("os"),
            "services": self.get_attribute("services"),
            "status": self.get_state("status"),
            "cpu_usage": self.get_state("cpu_usage"),
            "memory_usage": self.get_state("memory_usage"),
            "disk_usage": self.get_state("disk_usage"),
            "network_traffic": self.get_state("network_traffic")
        }
        
        base_dict.update(host_dict)
        return base_dict
