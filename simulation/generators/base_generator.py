"""
Base Event Generator Module

This module provides the base class for all event generators in the simulation system.
"""

import random
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..config import SimulationConfig

class BaseEventGenerator:
    """Base class for all event generators in the simulation system."""
    
    def __init__(self, config: SimulationConfig, entities: Dict[str, Any]):
        """
        Initialize the event generator.
        
        Args:
            config: Simulation configuration
            entities: Dictionary of entities
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.entities = entities
    
    def generate_event(self) -> Dict[str, Any]:
        """
        Generate a security event.
        
        Returns:
            Event data
        """
        # This is a placeholder method that should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement generate_event()")
    
    def _get_random_entity(self, entity_type: Optional[str] = None) -> Any:
        """
        Get a random entity.
        
        Args:
            entity_type: Type of entity to get (if None, any type)
            
        Returns:
            Random entity
        """
        if not self.entities:
            return None
        
        if entity_type:
            # Filter entities by type
            filtered_entities = {
                entity_id: entity for entity_id, entity in self.entities.items()
                if entity.get_type() == entity_type
            }
            
            if not filtered_entities:
                return None
            
            # Select a random entity
            entity_id = random.choice(list(filtered_entities.keys()))
            return filtered_entities[entity_id]
        else:
            # Select a random entity
            entity_id = random.choice(list(self.entities.keys()))
            return self.entities[entity_id]
    
    def _get_random_host(self) -> Any:
        """
        Get a random host entity.
        
        Returns:
            Random host entity
        """
        return self._get_random_entity(entity_type="host")
    
    def _get_random_user(self) -> Any:
        """
        Get a random user entity.
        
        Returns:
            Random user entity
        """
        return self._get_random_entity(entity_type="user")
    
    def _get_timestamp(self) -> str:
        """
        Get the current timestamp.
        
        Returns:
            Current timestamp as ISO format string
        """
        return datetime.now().isoformat()
    
    def _get_severity(self) -> str:
        """
        Get a random severity level.
        
        Returns:
            Random severity level
        """
        severities = ["Low", "Medium", "High", "Critical"]
        weights = [0.5, 0.3, 0.15, 0.05]  # More low severity events than high
        
        return random.choices(severities, weights=weights, k=1)[0]
    
    def _get_source_type(self) -> str:
        """
        Get the source type for the event.
        
        Returns:
            Source type
        """
        return "simulation"
    
    def _create_base_event(self) -> Dict[str, Any]:
        """
        Create a base event with common fields.
        
        Returns:
            Base event
        """
        return {
            "timestamp": self._get_timestamp(),
            "source": {
                "type": self._get_source_type(),
                "name": "Security Event Simulator"
            },
            "severity": self._get_severity(),
            "is_simulated": True
        }
    
    def _add_mitre_attack_mapping(self, event: Dict[str, Any], technique_ids: List[str]) -> Dict[str, Any]:
        """
        Add MITRE ATT&CK mapping to an event.
        
        Args:
            event: Event to add mapping to
            technique_ids: List of MITRE ATT&CK technique IDs
            
        Returns:
            Event with MITRE ATT&CK mapping
        """
        # MITRE ATT&CK tactics
        tactics = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution',
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control',
            'TA0040': 'Impact',
            'TA0042': 'Resource Development',
            'TA0043': 'Reconnaissance'
        }
        
        # MITRE ATT&CK techniques with their tactics
        techniques = {
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactic_ids': ['TA0002']},
            'T1078': {'name': 'Valid Accounts', 'tactic_ids': ['TA0001', 'TA0003', 'TA0004', 'TA0005']},
            'T1053': {'name': 'Scheduled Task/Job', 'tactic_ids': ['TA0002', 'TA0003', 'TA0004']},
            'T1082': {'name': 'System Information Discovery', 'tactic_ids': ['TA0007']},
            'T1083': {'name': 'File and Directory Discovery', 'tactic_ids': ['TA0007']},
            'T1046': {'name': 'Network Service Scanning', 'tactic_ids': ['TA0007']},
            'T1057': {'name': 'Process Discovery', 'tactic_ids': ['TA0007']},
            'T1021': {'name': 'Remote Services', 'tactic_ids': ['TA0008']},
            'T1560': {'name': 'Archive Collected Data', 'tactic_ids': ['TA0009']},
            'T1005': {'name': 'Data from Local System', 'tactic_ids': ['TA0009']},
            'T1071': {'name': 'Application Layer Protocol', 'tactic_ids': ['TA0011']},
            'T1105': {'name': 'Ingress Tool Transfer', 'tactic_ids': ['TA0011']},
            'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic_ids': ['TA0010']},
            'T1486': {'name': 'Data Encrypted for Impact', 'tactic_ids': ['TA0040']},
            'T1566': {'name': 'Phishing', 'tactic_ids': ['TA0001']},
            'T1190': {'name': 'Exploit Public-Facing Application', 'tactic_ids': ['TA0001']},
            'T1133': {'name': 'External Remote Services', 'tactic_ids': ['TA0001']},
            'T1110': {'name': 'Brute Force', 'tactic_ids': ['TA0006']},
            'T1496': {'name': 'Resource Hijacking', 'tactic_ids': ['TA0040']},
            'T1055': {'name': 'Process Injection', 'tactic_ids': ['TA0004', 'TA0005']},
            'T1559': {'name': 'Inter-Process Communication', 'tactic_ids': ['TA0002']},
            'T1095': {'name': 'Non-Application Layer Protocol', 'tactic_ids': ['TA0011']},
            'T1114': {'name': 'Email Collection', 'tactic_ids': ['TA0009']}
        }
        
        # Create techniques list
        technique_list = []
        for technique_id in technique_ids:
            if technique_id in techniques:
                technique = techniques[technique_id]
                technique_list.append({
                    'id': technique_id,
                    'name': technique['name'],
                    'tactics': [{'id': tactic_id, 'name': tactics.get(tactic_id, 'Unknown')} for tactic_id in technique['tactic_ids']]
                })
        
        # Create tactics list
        tactic_dict = {}
        for technique_id in technique_ids:
            if technique_id in techniques:
                for tactic_id in techniques[technique_id]['tactic_ids']:
                    if tactic_id not in tactic_dict:
                        tactic_dict[tactic_id] = {
                            'id': tactic_id,
                            'name': tactics.get(tactic_id, 'Unknown'),
                            'techniques': []
                        }
                    
                    tactic_dict[tactic_id]['techniques'].append({
                        'id': technique_id,
                        'name': techniques[technique_id]['name']
                    })
        
        tactic_list = list(tactic_dict.values())
        
        # Add MITRE ATT&CK mapping to event
        event['mitre_attack'] = {
            'techniques': technique_list,
            'tactics': tactic_list
        }
        
        return event
