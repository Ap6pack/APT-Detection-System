"""
User Event Generator Module

This module provides the UserEventGenerator class for generating user-related security events.
"""

import random
from typing import Dict, Any

from .base_generator import BaseEventGenerator

class UserEventGenerator(BaseEventGenerator):
    """Generator for user-related security events."""
    
    def generate_event(self) -> Dict[str, Any]:
        """
        Generate a user-related security event.
        
        Returns:
            User event data
        """
        # Select a random event type
        event_types = [
            self._generate_login_event,
            self._generate_privilege_change_event,
            self._generate_account_change_event,
            self._generate_password_change_event,
            self._generate_group_membership_event
        ]
        
        generator = random.choice(event_types)
        return generator()
    
    def _generate_login_event(self) -> Dict[str, Any]:
        """
        Generate a user login event.
        
        Returns:
            Login event data
        """
        user = self._get_random_user()
        host = self._get_random_host()
        
        if not user or not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Login types
        login_types = ["Interactive", "Network", "Batch", "Service", "Remote Interactive"]
        login_type = random.choice(login_types)
        
        # Login status
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
            "event_type": "login",
            "entity": user.get_id(),
            "entity_type": "user",
            "host": host.get_id(),
            "host_name": host.get_attribute("hostname"),
            "user_name": user.get_attribute("username"),
            "login_type": login_type,
            "login_status": status,
            "source_ip": random.choice([
                host.get_attribute("ip_address"),
                "192.168.1." + str(random.randint(2, 254)),
                "10.0.0." + str(random.randint(2, 254))
            ])
        })
        
        # Add failure reason if login failed
        if status == "failure":
            event["failure_reason"] = random.choice(failure_reasons)
        
        # Add suspicious information for failed logins or unusual sources
        if status == "failure" or random.random() < 0.1:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            
            if status == "failure":
                event["reason"] = f"login failure: {event.get('failure_reason', 'unknown')}"
                
                # Update user state
                user.simulate_failed_login()
            else:
                event["reason"] = random.choice([
                    "login from unusual source",
                    "login at unusual time",
                    "login for sensitive account",
                    "multiple login attempts"
                ])
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            if status == "failure" and event.get("failure_reason") == "invalid_credentials":
                technique_ids.append('T1110')  # Brute Force
            elif login_type == "Remote Interactive":
                technique_ids.append('T1021.001')  # Remote Services: Remote Desktop Protocol
            else:
                technique_ids.append('T1078')  # Valid Accounts
            
            self._add_mitre_attack_mapping(event, technique_ids)
        else:
            # Update user state for successful login
            user.simulate_login()
        
        return event
    
    def _generate_privilege_change_event(self) -> Dict[str, Any]:
        """
        Generate a privilege change event.
        
        Returns:
            Privilege change event data
        """
        user = self._get_random_user()
        host = self._get_random_host()
        
        if not user or not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Privilege types
        privilege_types = [
            "SeBackupPrivilege",
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeRestorePrivilege",
            "SeShutdownPrivilege",
            "SeSystemtimePrivilege",
            "SeTcbPrivilege",
            "SeSecurityPrivilege"
        ]
        
        privilege = random.choice(privilege_types)
        
        # Actions
        actions = ["granted", "removed"]
        action = random.choice(actions)
        
        # Actor (who made the change)
        actors = [
            {"name": "Administrator", "suspicious": False},
            {"name": "System", "suspicious": False},
            {"name": "SYSTEM", "suspicious": False},
            {"name": "Domain Admin", "suspicious": False}
        ]
        
        suspicious_actors = [
            {"name": user.get_attribute("username"), "suspicious": True},
            {"name": "unknown", "suspicious": True},
            {"name": "guest", "suspicious": True}
        ]
        
        is_suspicious = random.random() < 0.1
        actor = random.choice(suspicious_actors if is_suspicious else actors)
        
        # Add event-specific data
        event.update({
            "event_type": "privilege_change",
            "entity": user.get_id(),
            "entity_type": "user",
            "host": host.get_id(),
            "host_name": host.get_attribute("hostname"),
            "user_name": user.get_attribute("username"),
            "privilege": privilege,
            "action": action,
            "actor": actor["name"],
            "process_name": random.choice(["lsass.exe", "services.exe", "cmd.exe", "powershell.exe", "sudo", "su"]),
            "process_id": random.randint(1000, 65535)
        })
        
        # Add suspicious information if applicable
        if actor["suspicious"] or is_suspicious or privilege in ["SeDebugPrivilege", "SeTcbPrivilege"]:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            
            if action == "granted":
                event["reason"] = f"sensitive privilege {privilege} granted to user"
                
                # Update user state
                user.simulate_privilege_escalation()
            else:
                event["reason"] = f"privilege {privilege} removed from user by suspicious actor"
            
            # Add MITRE ATT&CK mapping
            technique_ids = ['T1078']  # Valid Accounts
            
            if privilege in ["SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege"]:
                technique_ids.append('T1134')  # Access Token Manipulation
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_account_change_event(self) -> Dict[str, Any]:
        """
        Generate an account change event.
        
        Returns:
            Account change event data
        """
        user = self._get_random_user()
        host = self._get_random_host()
        
        if not user or not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Account change types
        change_types = [
            "account_created",
            "account_deleted",
            "account_enabled",
            "account_disabled",
            "account_locked",
            "account_unlocked",
            "account_renamed",
            "account_expired"
        ]
        
        change_type = random.choice(change_types)
        
        # Actor (who made the change)
        actors = [
            {"name": "Administrator", "suspicious": False},
            {"name": "System", "suspicious": False},
            {"name": "SYSTEM", "suspicious": False},
            {"name": "Domain Admin", "suspicious": False}
        ]
        
        suspicious_actors = [
            {"name": user.get_attribute("username"), "suspicious": True},
            {"name": "unknown", "suspicious": True},
            {"name": "guest", "suspicious": True}
        ]
        
        is_suspicious = random.random() < 0.1
        actor = random.choice(suspicious_actors if is_suspicious else actors)
        
        # Add event-specific data
        event.update({
            "event_type": "account_change",
            "entity": user.get_id(),
            "entity_type": "user",
            "host": host.get_id(),
            "host_name": host.get_attribute("hostname"),
            "user_name": user.get_attribute("username"),
            "change_type": change_type,
            "actor": actor["name"],
            "process_name": random.choice(["lsass.exe", "services.exe", "cmd.exe", "powershell.exe", "net.exe", "useradd", "userdel"]),
            "process_id": random.randint(1000, 65535)
        })
        
        # Add additional data based on change type
        if change_type == "account_renamed":
            event["old_name"] = user.get_attribute("username")
            event["new_name"] = f"{user.get_attribute('username')}_new"
        
        # Add suspicious information if applicable
        if actor["suspicious"] or is_suspicious or change_type in ["account_created", "account_deleted"]:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            
            if change_type == "account_created":
                event["reason"] = "account created by suspicious actor"
            elif change_type == "account_deleted":
                event["reason"] = "account deleted by suspicious actor"
            elif change_type == "account_enabled":
                event["reason"] = "disabled account enabled by suspicious actor"
            else:
                event["reason"] = f"account {change_type.replace('_', ' ')} by suspicious actor"
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            if change_type == "account_created":
                technique_ids.append('T1136')  # Create Account
            elif change_type == "account_deleted":
                technique_ids.append('T1531')  # Account Access Removal
            else:
                technique_ids.append('T1098')  # Account Manipulation
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
    
    def _generate_password_change_event(self) -> Dict[str, Any]:
        """
        Generate a password change event.
        
        Returns:
            Password change event data
        """
        user = self._get_random_user()
        host = self._get_random_host()
        
        if not user or not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Password change types
        change_types = [
            "password_change",
            "password_reset",
            "password_expired",
            "password_policy_change"
        ]
        
        change_type = random.choice(change_types)
        
        # Actor (who made the change)
        actors = [
            {"name": user.get_attribute("username"), "suspicious": False},
            {"name": "Administrator", "suspicious": False},
            {"name": "System", "suspicious": False},
            {"name": "SYSTEM", "suspicious": False},
            {"name": "Domain Admin", "suspicious": False}
        ]
        
        suspicious_actors = [
            {"name": "unknown", "suspicious": True},
            {"name": "guest", "suspicious": True},
            {"name": random.choice([u for u in self.entities.keys() if u.startswith("user") and u != user.get_id()]), "suspicious": True}
        ]
        
        is_suspicious = random.random() < 0.1
        actor = random.choice(suspicious_actors if is_suspicious else actors)
        
        # Add event-specific data
        event.update({
            "event_type": "password_change",
            "entity": user.get_id(),
            "entity_type": "user",
            "host": host.get_id(),
            "host_name": host.get_attribute("hostname"),
            "user_name": user.get_attribute("username"),
            "change_type": change_type,
            "actor": actor["name"],
            "process_name": random.choice(["lsass.exe", "services.exe", "cmd.exe", "powershell.exe", "net.exe", "passwd"]),
            "process_id": random.randint(1000, 65535)
        })
        
        # Add additional data based on change type
        if change_type == "password_policy_change":
            event["policy_changes"] = random.choice([
                "minimum_length_increased",
                "complexity_requirements_enabled",
                "maximum_age_decreased",
                "history_enforcement_enabled"
            ])
        
        # Add suspicious information if applicable
        if actor["suspicious"] or is_suspicious or (change_type == "password_reset" and actor["name"] != "Administrator"):
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            
            if change_type == "password_change" and actor["name"] != user.get_attribute("username"):
                event["reason"] = "password changed by someone other than the user"
            elif change_type == "password_reset":
                event["reason"] = "password reset by suspicious actor"
            else:
                event["reason"] = f"suspicious {change_type.replace('_', ' ')}"
            
            # Add MITRE ATT&CK mapping
            technique_ids = ['T1098']  # Account Manipulation
            
            self._add_mitre_attack_mapping(event, technique_ids)
        else:
            # Update user state for normal password change
            user.simulate_password_change()
        
        return event
    
    def _generate_group_membership_event(self) -> Dict[str, Any]:
        """
        Generate a group membership change event.
        
        Returns:
            Group membership event data
        """
        user = self._get_random_user()
        host = self._get_random_host()
        
        if not user or not host:
            return {}
        
        # Create base event
        event = self._create_base_event()
        
        # Groups
        groups = [
            {"name": "Users", "suspicious": False},
            {"name": "Power Users", "suspicious": False},
            {"name": "Remote Desktop Users", "suspicious": False},
            {"name": "Backup Operators", "suspicious": False},
            {"name": "Performance Monitor Users", "suspicious": False}
        ]
        
        suspicious_groups = [
            {"name": "Administrators", "suspicious": True},
            {"name": "Domain Admins", "suspicious": True},
            {"name": "Enterprise Admins", "suspicious": True},
            {"name": "Schema Admins", "suspicious": True},
            {"name": "Account Operators", "suspicious": True}
        ]
        
        is_suspicious = random.random() < 0.1
        group = random.choice(suspicious_groups if is_suspicious else groups)
        
        # Actions
        actions = ["added", "removed"]
        action = random.choice(actions)
        
        # Actor (who made the change)
        actors = [
            {"name": "Administrator", "suspicious": False},
            {"name": "System", "suspicious": False},
            {"name": "SYSTEM", "suspicious": False},
            {"name": "Domain Admin", "suspicious": False}
        ]
        
        suspicious_actors = [
            {"name": user.get_attribute("username"), "suspicious": True},
            {"name": "unknown", "suspicious": True},
            {"name": "guest", "suspicious": True}
        ]
        
        actor = random.choice(suspicious_actors if is_suspicious else actors)
        
        # Add event-specific data
        event.update({
            "event_type": "group_membership",
            "entity": user.get_id(),
            "entity_type": "user",
            "host": host.get_id(),
            "host_name": host.get_attribute("hostname"),
            "user_name": user.get_attribute("username"),
            "group_name": group["name"],
            "action": action,
            "actor": actor["name"],
            "process_name": random.choice(["lsass.exe", "services.exe", "cmd.exe", "powershell.exe", "net.exe", "usermod"]),
            "process_id": random.randint(1000, 65535)
        })
        
        # Add suspicious information if applicable
        if group["suspicious"] or actor["suspicious"] or is_suspicious:
            event["severity"] = random.choice(["Medium", "High"])
            event["suspicious"] = True
            
            if action == "added":
                event["reason"] = f"user added to sensitive group {group['name']}"
                
                # Update user state
                if group["name"] == "Administrators":
                    user.simulate_privilege_escalation()
            else:
                event["reason"] = f"user removed from group {group['name']} by suspicious actor"
            
            # Add MITRE ATT&CK mapping
            technique_ids = []
            
            if action == "added" and group["suspicious"]:
                technique_ids.append('T1078')  # Valid Accounts
                technique_ids.append('T1098')  # Account Manipulation
            else:
                technique_ids.append('T1098')  # Account Manipulation
            
            self._add_mitre_attack_mapping(event, technique_ids)
        
        return event
