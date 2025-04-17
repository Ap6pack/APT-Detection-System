"""
User Entity Module

This module provides the User entity class for the simulation system.
"""

import random
from typing import Dict, Any
from datetime import datetime, timedelta

from .entity import Entity

class User(Entity):
    """User entity class representing a user account."""
    
    def __init__(self, user_id: str):
        """
        Initialize the user entity.
        
        Args:
            user_id: Unique identifier for the user
        """
        super().__init__(user_id, entity_type="user")
        
        # Set default attributes
        self.set_attribute("username", user_id)
        self.set_attribute("full_name", self._generate_full_name())
        self.set_attribute("email", f"{user_id}@example.com")
        self.set_attribute("department", self._generate_department())
        self.set_attribute("role", self._generate_role())
        self.set_attribute("privileges", self._generate_privileges())
        
        # Set default state
        self.set_state("status", "active")
        self.set_state("logged_in", random.choice([True, False]))
        self.set_state("last_login", (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat())
        self.set_state("login_count", random.randint(10, 100))
        self.set_state("failed_login_count", random.randint(0, 5))
    
    def _generate_full_name(self) -> str:
        """
        Generate a random full name.
        
        Returns:
            Random full name
        """
        first_names = [
            "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles",
            "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen"
        ]
        
        last_names = [
            "Smith", "Johnson", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor",
            "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Robinson"
        ]
        
        return f"{random.choice(first_names)} {random.choice(last_names)}"
    
    def _generate_department(self) -> str:
        """
        Generate a random department.
        
        Returns:
            Random department
        """
        departments = [
            "IT", "HR", "Finance", "Marketing", "Sales", "Operations", "R&D", "Legal", "Customer Support", "Executive"
        ]
        
        return random.choice(departments)
    
    def _generate_role(self) -> str:
        """
        Generate a random role.
        
        Returns:
            Random role
        """
        roles = {
            "IT": ["System Administrator", "Network Engineer", "Security Analyst", "Developer", "IT Manager"],
            "HR": ["HR Specialist", "Recruiter", "HR Manager", "Payroll Specialist", "Training Coordinator"],
            "Finance": ["Accountant", "Financial Analyst", "Controller", "Finance Manager", "Auditor"],
            "Marketing": ["Marketing Specialist", "Content Writer", "SEO Specialist", "Marketing Manager", "Brand Manager"],
            "Sales": ["Sales Representative", "Account Manager", "Sales Manager", "Business Development", "Sales Analyst"],
            "Operations": ["Operations Manager", "Project Manager", "Business Analyst", "Quality Assurance", "Process Improvement"],
            "R&D": ["Research Scientist", "Product Developer", "R&D Manager", "Lab Technician", "Innovation Specialist"],
            "Legal": ["Legal Counsel", "Paralegal", "Compliance Officer", "Contract Specialist", "Legal Assistant"],
            "Customer Support": ["Support Specialist", "Customer Service Rep", "Support Manager", "Technical Support", "Customer Success"],
            "Executive": ["CEO", "CFO", "CTO", "COO", "CIO"]
        }
        
        department = self.get_attribute("department", "IT")
        department_roles = roles.get(department, roles["IT"])
        
        return random.choice(department_roles)
    
    def _generate_privileges(self) -> Dict[str, bool]:
        """
        Generate random user privileges.
        
        Returns:
            Dictionary of privileges
        """
        # Base privileges
        privileges = {
            "login": True,
            "file_access": True,
            "email": True,
            "internet": True
        }
        
        # Department-specific privileges
        department = self.get_attribute("department", "IT")
        role = self.get_attribute("role", "")
        
        if department == "IT":
            privileges["admin_access"] = "Administrator" in role or "Manager" in role
            privileges["system_config"] = "Administrator" in role or "Engineer" in role
            privileges["network_config"] = "Network" in role or "Administrator" in role
            privileges["security_tools"] = "Security" in role or "Administrator" in role
        
        elif department == "Finance":
            privileges["financial_systems"] = True
            privileges["payment_processing"] = "Accountant" in role or "Controller" in role or "Manager" in role
            privileges["payroll"] = "Payroll" in role or "Manager" in role
        
        elif department == "HR":
            privileges["hr_systems"] = True
            privileges["employee_records"] = True
            privileges["payroll_view"] = "Payroll" in role or "Manager" in role
        
        elif department == "Executive":
            privileges["all_systems"] = True
            privileges["financial_reports"] = True
            privileges["strategic_documents"] = True
        
        return privileges
    
    def update_state(self) -> None:
        """Update the user state with random variations."""
        # Randomly change login status
        if random.random() < 0.1:  # 10% chance to change login status
            current_login = self.get_state("logged_in", False)
            self.set_state("logged_in", not current_login)
            
            if not current_login:  # If logging in
                self.set_state("last_login", datetime.now().isoformat())
                login_count = self.get_state("login_count", 0)
                self.set_state("login_count", login_count + 1)
    
    def simulate_login(self) -> None:
        """Simulate a user login."""
        self.set_state("logged_in", True)
        self.set_state("last_login", datetime.now().isoformat())
        login_count = self.get_state("login_count", 0)
        self.set_state("login_count", login_count + 1)
        
        self.add_history_event("login", {
            "timestamp": datetime.now().isoformat(),
            "success": True,
            "source_ip": f"192.168.1.{random.randint(2, 254)}"
        })
    
    def simulate_logout(self) -> None:
        """Simulate a user logout."""
        self.set_state("logged_in", False)
        
        self.add_history_event("logout", {
            "timestamp": datetime.now().isoformat()
        })
    
    def simulate_failed_login(self) -> None:
        """Simulate a failed login attempt."""
        failed_count = self.get_state("failed_login_count", 0)
        self.set_state("failed_login_count", failed_count + 1)
        
        self.add_history_event("failed_login", {
            "timestamp": datetime.now().isoformat(),
            "reason": random.choice(["incorrect_password", "account_locked", "expired_password"]),
            "source_ip": f"192.168.1.{random.randint(2, 254)}"
        })
    
    def simulate_password_change(self) -> None:
        """Simulate a password change."""
        self.add_history_event("password_change", {
            "timestamp": datetime.now().isoformat(),
            "source_ip": f"192.168.1.{random.randint(2, 254)}"
        })
    
    def simulate_privilege_escalation(self) -> None:
        """Simulate a privilege escalation."""
        # Add admin access if not already present
        privileges = self.get_attribute("privileges", {})
        if not privileges.get("admin_access", False):
            privileges["admin_access"] = True
            self.set_attribute("privileges", privileges)
            
            self.add_history_event("privilege_change", {
                "timestamp": datetime.now().isoformat(),
                "privilege": "admin_access",
                "action": "added"
            })
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the user to a dictionary.
        
        Returns:
            User as a dictionary
        """
        base_dict = super().to_dict()
        
        # Add user-specific information
        user_dict = {
            "username": self.get_attribute("username"),
            "full_name": self.get_attribute("full_name"),
            "email": self.get_attribute("email"),
            "department": self.get_attribute("department"),
            "role": self.get_attribute("role"),
            "privileges": self.get_attribute("privileges"),
            "status": self.get_state("status"),
            "logged_in": self.get_state("logged_in"),
            "last_login": self.get_state("last_login"),
            "login_count": self.get_state("login_count"),
            "failed_login_count": self.get_state("failed_login_count")
        }
        
        base_dict.update(user_dict)
        return base_dict
