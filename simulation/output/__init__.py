"""
Output Package

This package provides output adapters for the simulation system.
"""

from .base_output import BaseOutput
from .redis_output import RedisOutput
from .kafka_output import KafkaOutput

__all__ = [
    'BaseOutput',
    'RedisOutput',
    'KafkaOutput'
]
