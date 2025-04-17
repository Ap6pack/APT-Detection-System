"""
Security Event Simulator Module

This module provides the main simulator class for generating security events
and attack scenarios.
"""

import time
import logging
import threading
import random
from typing import Dict, List, Any, Optional
from datetime import datetime
from .config import SimulationConfig

class SecurityEventSimulator:
    """
    Main simulator class for generating security events and attack scenarios.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the security event simulator.
        
        Args:
            config_path: Path to the configuration file (if None, use default config.yaml)
        """
        self.logger = logging.getLogger(__name__)
        self.config = SimulationConfig(config_path)
        
        # Check if simulation is enabled
        if not self.config.is_enabled():
            self.logger.warning("Simulation is disabled in configuration")
            return
        
        self.logger.info(f"Initializing security event simulator with realism level: {self.config.get_realism_level()}")
        
        # Initialize components
        self.generators = {}
        self.entities = {}
        self.scenarios = {}
        self.outputs = {}
        
        # Initialize state
        self.running = False
        self.thread = None
        self.active_scenarios = []
        
        # Load components based on realism level
        self._load_components()
    
    def _load_components(self) -> None:
        """Load simulation components based on configuration."""
        self._load_entities()
        self._load_generators()
        self._load_scenarios()
        self._load_outputs()
    
    def _load_entities(self) -> None:
        """Load entity definitions."""
        # This is a placeholder for the basic implementation
        # In a more advanced implementation, this would dynamically load entity classes
        from .entities.host import Host
        from .entities.user import User
        
        # Create hosts
        host_config = self.config.get_entities_config().get('hosts', {})
        host_count = host_config.get('count', 10)
        host_prefix = host_config.get('prefix', 'host')
        
        for i in range(1, host_count + 1):
            host_id = f"{host_prefix}{i}"
            self.entities[host_id] = Host(host_id)
            self.logger.debug(f"Created host entity: {host_id}")
        
        # Create users
        user_config = self.config.get_entities_config().get('users', {})
        user_count = user_config.get('count', 20)
        user_prefix = user_config.get('prefix', 'user')
        
        for i in range(1, user_count + 1):
            user_id = f"{user_prefix}{i}"
            self.entities[user_id] = User(user_id)
            self.logger.debug(f"Created user entity: {user_id}")
        
        self.logger.info(f"Loaded {len(self.entities)} entities")
    
    def _load_generators(self) -> None:
        """Load event generators."""
        # This is a placeholder for the basic implementation
        # In a more advanced implementation, this would dynamically load generator classes
        from .generators.network_events import NetworkEventGenerator
        from .generators.endpoint_events import EndpointEventGenerator
        from .generators.user_events import UserEventGenerator
        
        # Create generators
        self.generators['network'] = NetworkEventGenerator(self.config, self.entities)
        self.generators['endpoint'] = EndpointEventGenerator(self.config, self.entities)
        self.generators['user'] = UserEventGenerator(self.config, self.entities)
        
        self.logger.info(f"Loaded {len(self.generators)} event generators")
    
    def _load_scenarios(self) -> None:
        """Load attack scenarios."""
        # This is a placeholder for the basic implementation
        # In a more advanced implementation, this would dynamically load scenario classes
        if self.config.get_scenarios_config().get('enabled', True):
            from .scenarios.basic_scenarios import DataExfiltrationScenario, BruteForceScenario
            
            # Create scenarios
            self.scenarios['data_exfiltration'] = DataExfiltrationScenario(self.config, self.entities)
            self.scenarios['brute_force'] = BruteForceScenario(self.config, self.entities)
            
            self.logger.info(f"Loaded {len(self.scenarios)} attack scenarios")
        else:
            self.logger.info("Attack scenarios are disabled in configuration")
    
    def _load_outputs(self) -> None:
        """Load output adapters."""
        # This is a placeholder for the basic implementation
        # In a more advanced implementation, this would dynamically load output classes
        output_config = self.config.get_output_config()
        output_type = output_config.get('type', 'redis')
        
        if output_type == 'redis' or output_type == 'both':
            from .output.redis_output import RedisOutput
            self.outputs['redis'] = RedisOutput(self.config)
            self.logger.info("Loaded Redis output adapter")
        
        if output_type == 'kafka' or output_type == 'both':
            from .output.kafka_output import KafkaOutput
            self.outputs['kafka'] = KafkaOutput(self.config)
            self.logger.info("Loaded Kafka output adapter")
        
        self.logger.info(f"Loaded {len(self.outputs)} output adapters")
    
    def start(self) -> None:
        """Start the simulation."""
        if self.running:
            self.logger.warning("Simulation is already running")
            return
        
        if not self.config.is_enabled():
            self.logger.warning("Simulation is disabled in configuration")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_simulation)
        self.thread.daemon = True
        self.thread.start()
        
        self.logger.info("Started security event simulation")
    
    def stop(self) -> None:
        """Stop the simulation."""
        if not self.running:
            self.logger.warning("Simulation is not running")
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5.0)
        
        self.logger.info("Stopped security event simulation")
    
    def _run_simulation(self) -> None:
        """Run the simulation loop."""
        events_config = self.config.get_events_config()
        rate = events_config.get('rate', 5)  # Events per minute
        interval = 60.0 / rate  # Seconds between events
        
        distribution = events_config.get('distribution', {
            'network': 0.4,
            'endpoint': 0.4,
            'user': 0.2
        })
        
        generator_weights = []
        for generator_type, weight in distribution.items():
            if generator_type in self.generators:
                generator_weights.append((generator_type, weight))
        
        # Normalize weights
        total_weight = sum(weight for _, weight in generator_weights)
        generator_weights = [(gen_type, weight / total_weight) for gen_type, weight in generator_weights]
        
        scenarios_config = self.config.get_scenarios_config()
        max_concurrent = scenarios_config.get('concurrent', 2)
        
        last_scenario_check = datetime.now()
        scenario_check_interval = 60.0  # Check for new scenarios every minute
        
        try:
            while self.running:
                # Generate regular events
                generator_type = self._weighted_choice(generator_weights)
                generator = self.generators.get(generator_type)
                
                if generator:
                    event = generator.generate_event()
                    if event:
                        self._send_event(event)
                
                # Check if we should start a new scenario
                now = datetime.now()
                if (now - last_scenario_check).total_seconds() >= scenario_check_interval:
                    self._check_scenarios(max_concurrent)
                    last_scenario_check = now
                
                # Update active scenarios
                self._update_scenarios()
                
                # Sleep until next event
                time.sleep(interval)
        except Exception as e:
            self.logger.error(f"Error in simulation loop: {str(e)}")
            self.running = False
    
    def _weighted_choice(self, choices: List[tuple]) -> Any:
        """
        Make a weighted random choice.
        
        Args:
            choices: List of (item, weight) tuples
            
        Returns:
            Randomly selected item based on weights
        """
        total = sum(weight for _, weight in choices)
        r = random.uniform(0, total)
        upto = 0
        
        for item, weight in choices:
            upto += weight
            if upto >= r:
                return item
        
        # Fallback to first item
        return choices[0][0] if choices else None
    
    def _check_scenarios(self, max_concurrent: int) -> None:
        """
        Check if we should start a new scenario.
        
        Args:
            max_concurrent: Maximum number of concurrent scenarios
        """
        if not self.scenarios or not self.config.get_scenarios_config().get('enabled', True):
            return
        
        # Remove completed scenarios
        self.active_scenarios = [s for s in self.active_scenarios if not s.is_completed()]
        
        # Check if we can start a new scenario
        if len(self.active_scenarios) >= max_concurrent:
            return
        
        # Determine if we should start a new scenario based on frequency
        frequency = self.config.get_scenarios_config().get('frequency', 'medium')
        probability = {
            'low': 0.1,
            'medium': 0.3,
            'high': 0.5
        }.get(frequency, 0.3)
        
        if random.random() < probability:
            # Select a random scenario
            scenario_type = random.choice(list(self.scenarios.keys()))
            scenario = self.scenarios.get(scenario_type)
            
            if scenario:
                # Start the scenario
                scenario.start()
                self.active_scenarios.append(scenario)
                self.logger.info(f"Started scenario: {scenario_type}")
    
    def _update_scenarios(self) -> None:
        """Update active scenarios and generate events."""
        for scenario in self.active_scenarios:
            if not scenario.is_completed():
                events = scenario.update()
                for event in events:
                    self._send_event(event)
    
    def _send_event(self, event: Dict[str, Any]) -> None:
        """
        Send an event to all output adapters.
        
        Args:
            event: Event data
        """
        for output_name, output in self.outputs.items():
            try:
                output.send_event(event)
            except Exception as e:
                self.logger.error(f"Error sending event to {output_name}: {str(e)}")
    
    def generate_event(self, generator_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a single event on demand.
        
        Args:
            generator_type: Type of generator to use (if None, choose randomly)
            
        Returns:
            Generated event
        """
        if not generator_type:
            generator_type = random.choice(list(self.generators.keys()))
        
        generator = self.generators.get(generator_type)
        if generator:
            return generator.generate_event()
        
        return {}
    
    def start_scenario(self, scenario_type: str) -> bool:
        """
        Start a specific scenario on demand.
        
        Args:
            scenario_type: Type of scenario to start
            
        Returns:
            True if scenario was started, False otherwise
        """
        scenario = self.scenarios.get(scenario_type)
        if scenario:
            scenario.start()
            self.active_scenarios.append(scenario)
            self.logger.info(f"Started scenario: {scenario_type}")
            return True
        
        return False
