"""
Base Output Module

This module provides the base class for all output adapters in the simulation system.
"""

import logging
from typing import Dict, Any

from ..config import SimulationConfig

class BaseOutput:
    """Base class for all output adapters in the simulation system."""
    
    def __init__(self, config: SimulationConfig):
        """
        Initialize the output adapter.
        
        Args:
            config: Simulation configuration
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """
        Send an event to the output destination.
        
        Args:
            event: Event data
            
        Returns:
            True if the event was sent successfully, False otherwise
        """
        # This is a placeholder method that should be overridden by subclasses
        raise NotImplementedError("Subclasses must implement send_event()")
    
    def _format_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format an event for output.
        
        Args:
            event: Event data
            
        Returns:
            Formatted event data
        """
        # Add any common formatting here
        return event
