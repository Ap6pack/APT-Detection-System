"""
Scenarios Package

This package provides attack scenario classes for the simulation system.
"""

from .base_scenario import BaseScenario
from .basic_scenarios import DataExfiltrationScenario, BruteForceScenario

__all__ = [
    'BaseScenario',
    'DataExfiltrationScenario',
    'BruteForceScenario'
]
