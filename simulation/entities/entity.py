"""
Base Entity Module

This module provides the base class for all entities in the simulation system.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime

class Entity:
    """Base class for all entities in the simulation system."""
    
    def __init__(self, entity_id: str, entity_type: str = "generic"):
        """
        Initialize the entity.
        
        Args:
            entity_id: Unique identifier for the entity
            entity_type: Type of entity
        """
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.attributes = {}
        self.state = {}
        self.history = []
        self.created_at = datetime.now()
        self.last_updated = self.created_at
    
    def get_id(self) -> str:
        """
        Get the entity ID.
        
        Returns:
            Entity ID
        """
        return self.entity_id
    
    def get_type(self) -> str:
        """
        Get the entity type.
        
        Returns:
            Entity type
        """
        return self.entity_type
    
    def set_attribute(self, key: str, value: Any) -> None:
        """
        Set an entity attribute.
        
        Args:
            key: Attribute key
            value: Attribute value
        """
        self.attributes[key] = value
        self.last_updated = datetime.now()
    
    def get_attribute(self, key: str, default: Any = None) -> Any:
        """
        Get an entity attribute.
        
        Args:
            key: Attribute key
            default: Default value if attribute not found
            
        Returns:
            Attribute value
        """
        return self.attributes.get(key, default)
    
    def set_state(self, key: str, value: Any) -> None:
        """
        Set an entity state value.
        
        Args:
            key: State key
            value: State value
        """
        self.state[key] = value
        self.last_updated = datetime.now()
    
    def get_state(self, key: str, default: Any = None) -> Any:
        """
        Get an entity state value.
        
        Args:
            key: State key
            default: Default value if state not found
            
        Returns:
            State value
        """
        return self.state.get(key, default)
    
    def add_history_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """
        Add an event to the entity's history.
        
        Args:
            event_type: Type of event
            details: Event details
        """
        event = {
            'timestamp': datetime.now(),
            'type': event_type,
            'details': details
        }
        self.history.append(event)
        self.last_updated = event['timestamp']
    
    def get_history(self, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get the entity's history.
        
        Args:
            event_type: Filter by event type (if None, return all events)
            
        Returns:
            List of history events
        """
        if event_type:
            return [event for event in self.history if event['type'] == event_type]
        return self.history
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the entity to a dictionary.
        
        Returns:
            Entity as a dictionary
        """
        return {
            'entity_id': self.entity_id,
            'entity_type': self.entity_type,
            'attributes': self.attributes,
            'state': self.state,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat()
        }
