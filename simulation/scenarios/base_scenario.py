"""
Base Scenario Module

This module provides the base class for all attack scenarios in the simulation system.
"""

import random
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from ..config import SimulationConfig

class BaseScenario:
    """Base class for all attack scenarios in the simulation system."""
    
    def __init__(self, config: SimulationConfig, entities: Dict[str, Any]):
        """
        Initialize the attack scenario.
        
        Args:
            config: Simulation configuration
            entities: Dictionary of entities
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.entities = entities
        
        # Initialize scenario state
        self.started = False
        self.completed = False
        self.start_time = None
        self.end_time = None
        self.current_stage = 0
        self.stages = []
        self.target_entities = {}
        self.scenario_id = f"scenario-{random.randint(1000, 9999)}"
        self.scenario_type = "base"
        self.scenario_name = "Base Scenario"
        self.scenario_description = "Base scenario class"
    
    def start(self) -> None:
        """Start the scenario."""
        if self.started:
            return
        
        self.started = True
        self.start_time = datetime.now()
        self.current_stage = 0
        self.completed = False
        
        # Select target entities
        self._select_target_entities()
        
        # Initialize stages
        self._initialize_stages()
        
        self.logger.info(f"Started scenario: {self.scenario_name} ({self.scenario_id})")
    
    def update(self) -> List[Dict[str, Any]]:
        """
        Update the scenario state and generate events.
        
        Returns:
            List of generated events
        """
        if not self.started or self.completed:
            return []
        
        # Check if scenario has timed out
        if self.start_time and (datetime.now() - self.start_time) > timedelta(minutes=30):
            self.completed = True
            self.end_time = datetime.now()
            self.logger.info(f"Scenario timed out: {self.scenario_name} ({self.scenario_id})")
            return []
        
        # Check if all stages are completed
        if self.current_stage >= len(self.stages):
            self.completed = True
            self.end_time = datetime.now()
            self.logger.info(f"Scenario completed: {self.scenario_name} ({self.scenario_id})")
            return []
        
        # Execute current stage
        events = self._execute_current_stage()
        
        # Move to next stage if current stage is completed
        if self._is_current_stage_completed():
            self.current_stage += 1
            self.logger.debug(f"Moving to stage {self.current_stage} in scenario: {self.scenario_name} ({self.scenario_id})")
        
        return events
    
    def is_completed(self) -> bool:
        """
        Check if the scenario is completed.
        
        Returns:
            True if the scenario is completed, False otherwise
        """
        return self.completed
    
    def _select_target_entities(self) -> None:
        """Select target entities for the scenario."""
        # This is a placeholder method that should be overridden by subclasses
        pass
    
    def _initialize_stages(self) -> None:
        """Initialize scenario stages."""
        # This is a placeholder method that should be overridden by subclasses
        self.stages = []
    
    def _execute_current_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the current scenario stage.
        
        Returns:
            List of generated events
        """
        # This is a placeholder method that should be overridden by subclasses
        return []
    
    def _is_current_stage_completed(self) -> bool:
        """
        Check if the current stage is completed.
        
        Returns:
            True if the current stage is completed, False otherwise
        """
        # This is a placeholder method that should be overridden by subclasses
        return True
    
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
    
    def _create_base_event(self, severity: str = None) -> Dict[str, Any]:
        """
        Create a base event with common fields.
        
        Args:
            severity: Event severity (if None, a random severity will be used)
            
        Returns:
            Base event
        """
        if severity is None:
            severity = random.choice(["Medium", "High"])
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": {
                "type": "simulation",
                "name": "Security Event Simulator"
            },
            "severity": severity,
            "is_simulated": True,
            "scenario_id": self.scenario_id,
            "scenario_type": self.scenario_type,
            "scenario_name": self.scenario_name,
            "scenario_stage": self.current_stage
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
            base_technique_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
            
            if base_technique_id in techniques:
                technique = techniques[base_technique_id]
                technique_list.append({
                    'id': technique_id,
                    'name': technique['name'],
                    'tactics': [{'id': tactic_id, 'name': tactics.get(tactic_id, 'Unknown')} for tactic_id in technique['tactic_ids']]
                })
        
        # Create tactics list
        tactic_dict = {}
        for technique_id in technique_ids:
            base_technique_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
            
            if base_technique_id in techniques:
                for tactic_id in techniques[base_technique_id]['tactic_ids']:
                    if tactic_id not in tactic_dict:
                        tactic_dict[tactic_id] = {
                            'id': tactic_id,
                            'name': tactics.get(tactic_id, 'Unknown'),
                            'techniques': []
                        }
                    
                    tactic_dict[tactic_id]['techniques'].append({
                        'id': technique_id,
                        'name': techniques[base_technique_id]['name']
                    })
        
        tactic_list = list(tactic_dict.values())
        
        # Add MITRE ATT&CK mapping to event
        event['mitre_attack'] = {
            'techniques': technique_list,
            'tactics': tactic_list
        }
        
        return event
