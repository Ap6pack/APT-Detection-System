# Security Event Simulation System

This module provides a comprehensive security event simulation system for generating realistic security events for testing and development purposes.

## Overview

The Security Event Simulation System is designed to generate realistic security events that mimic real-world security incidents, including normal and suspicious activities. It can be used to:

- Test security monitoring and detection systems
- Develop and validate security analytics
- Train machine learning models for security event detection
- Demonstrate security incident response workflows
- Benchmark system performance under various security event loads

## Features

- **Entity Simulation**: Simulates various entities such as hosts, users, and networks
- **Event Generation**: Generates realistic security events across multiple categories
- **Attack Scenario Simulation**: Simulates complex attack scenarios with multiple stages
- **MITRE ATT&CK Integration**: Maps events to MITRE ATT&CK techniques and tactics
- **Configurable Realism Levels**: Supports different levels of realism for event generation
- **Multiple Output Options**: Can output events to Redis, Kafka, or both
- **Time-based Patterns**: Can simulate business hours and other time-based patterns
- **Adaptive Behavior**: Can adapt event generation based on system responses

## Architecture

The simulation system consists of the following components:

- **Entities**: Represent the objects in the simulated environment (hosts, users, networks)
- **Generators**: Generate security events for different categories
- **Scenarios**: Implement complex attack scenarios with multiple stages
- **Outputs**: Send generated events to various destinations (Redis, Kafka)
- **Simulator**: Coordinates the overall simulation process

## Configuration

The simulation system is configured through the main `config.yaml` file. The relevant section is:

```yaml
# Simulation configuration
simulation:
  enabled: true                # Set to false to disable simulation
  realism_level: "basic"       # Can be "basic", "intermediate", or "advanced"
  output:
    type: "redis"              # Can be "redis", "kafka", or "both"
    redis_key: "apt:alerts"
    kafka_topic: "apt_topic"
  entities:
    hosts:
      count: 10
      prefix: "host"
    users:
      count: 20
      prefix: "user"
    networks:
      count: 3
      subnets: ["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"]
  events:
    rate: 5                    # Events per minute
    distribution:
      network: 0.4
      endpoint: 0.4
      user: 0.2
  scenarios:
    enabled: true
    frequency: "medium"        # How often to trigger scenarios (low, medium, high)
    concurrent: 2              # Maximum number of concurrent scenarios
  time_patterns:
    enabled: false             # Set to true for intermediate realism
    business_hours:
      start: 9                 # 9 AM
      end: 17                  # 5 PM
      days: [0, 1, 2, 3, 4]    # Monday to Friday (0 = Monday)
  adaptive_behavior:
    enabled: false             # Set to true for advanced realism
```

## Usage

### Running with the APT Detection System

The simulation system is integrated with the APT Detection System and can be run using the main.py script:

```bash
# Run only the simulation
python main.py --simulation

# Run the simulation with the dashboard
python main.py --simulation --dashboard

# Run all components including the simulation
python main.py --all
```

### Running Standalone

The simulation system can also be run standalone using the simulation_runner.py script:

```bash
# Run with default configuration
python simulation_runner.py

# Run with a specific configuration file
python simulation_runner.py --config custom_config.yaml

# Run with a specific event rate
python simulation_runner.py --rate 10

# Run with a specific realism level
python simulation_runner.py --realism advanced

# Run with a specific output destination
python simulation_runner.py --output kafka

# Run a specific scenario
python simulation_runner.py --scenario data_exfiltration

# Run for a specific duration
python simulation_runner.py --duration 30
```

## Event Types

The simulation system generates the following types of events:

### Network Events
- Network connections
- Port scans
- Traffic spikes
- DNS queries
- Firewall events

### Endpoint Events
- Process creation/termination
- File creation/modification/deletion
- Registry changes (Windows)
- Authentication events
- Service installation/modification

### User Events
- Login/logout events
- Privilege changes
- Account changes
- Password changes
- Group membership changes

## Attack Scenarios

The simulation system includes the following attack scenarios:

### Data Exfiltration
Simulates a data exfiltration attack with the following stages:
1. Initial Access (phishing, exploitation)
2. Discovery (system information, network, files)
3. Collection (sensitive data, archiving)
4. Exfiltration (data transfer to external server)

### Brute Force
Simulates a brute force attack with the following stages:
1. Reconnaissance (network scanning, user enumeration)
2. Brute Force (repeated login attempts)
3. Initial Access (if successful)
4. Lateral Movement (if successful)

## Extending the System

### Adding New Event Types

To add a new event type, create a new method in the appropriate generator class:

```python
def _generate_new_event_type(self) -> Dict[str, Any]:
    """
    Generate a new event type.
    
    Returns:
        New event data
    """
    # Create base event
    event = self._create_base_event()
    
    # Add event-specific data
    event.update({
        "event_type": "new_event_type",
        # Add other fields as needed
    })
    
    # Add MITRE ATT&CK mapping if applicable
    self._add_mitre_attack_mapping(event, ['T1234'])
    
    return event
```

### Adding New Scenarios

To add a new scenario, create a new class that inherits from BaseScenario:

```python
class NewScenario(BaseScenario):
    """New attack scenario."""
    
    def __init__(self, config, entities):
        """Initialize the new scenario."""
        super().__init__(config, entities)
        
        self.scenario_type = "new_scenario"
        self.scenario_name = "New Scenario"
        self.scenario_description = "Description of the new scenario"
        
        # Scenario-specific state
        self.stage_progress = {}
    
    def _select_target_entities(self) -> None:
        """Select target entities for the scenario."""
        # Implementation here
    
    def _initialize_stages(self) -> None:
        """Initialize scenario stages."""
        self.stages = [
            "stage1",
            "stage2",
            "stage3"
        ]
        
        # Initialize stage progress
        for stage in self.stages:
            self.stage_progress[stage] = 0
    
    def _execute_current_stage(self) -> List[Dict[str, Any]]:
        """
        Execute the current scenario stage.
        
        Returns:
            List of generated events
        """
        # Implementation here
    
    def _is_current_stage_completed(self) -> bool:
        """
        Check if the current stage is completed.
        
        Returns:
            True if the current stage is completed, False otherwise
        """
        # Implementation here
```

### Adding New Output Adapters

To add a new output adapter, create a new class that inherits from BaseOutput:

```python
class NewOutput(BaseOutput):
    """New output adapter for the simulation system."""
    
    def __init__(self, config: SimulationConfig):
        """
        Initialize the new output adapter.
        
        Args:
            config: Simulation configuration
        """
        super().__init__(config)
        
        # Initialize adapter-specific resources
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """
        Send an event to the new destination.
        
        Args:
            event: Event data
            
        Returns:
            True if the event was sent successfully, False otherwise
        """
        # Implementation here
    
    def _format_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format an event for the new output.
        
        Args:
            event: Event data
            
        Returns:
            Formatted event data
        """
        # Apply base formatting
        formatted_event = super()._format_event(event)
        
        # Add adapter-specific formatting
        
        return formatted_event
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
