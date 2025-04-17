#!/usr/bin/env python3
"""
Simulation Runner

This script runs the security event simulation system.
"""

import argparse
import logging
import sys
import time
import signal
from simulation import SecurityEventSimulator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('simulation.log')
    ]
)
logger = logging.getLogger(__name__)

# Global variables
simulator = None
running = True

def signal_handler(sig, frame):
    """Handle signals to gracefully stop the simulation."""
    global running
    logger.info("Stopping simulation...")
    running = False

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Security Event Simulation System')
    
    parser.add_argument('--config', type=str, help='Path to configuration file')
    parser.add_argument('--rate', type=int, help='Events per minute')
    parser.add_argument('--realism', type=str, choices=['basic', 'intermediate', 'advanced'], 
                        help='Realism level')
    parser.add_argument('--output', type=str, choices=['redis', 'kafka', 'both'], 
                        help='Output destination')
    parser.add_argument('--scenario', type=str, help='Run a specific scenario')
    parser.add_argument('--duration', type=int, help='Duration in minutes (0 for indefinite)')
    
    return parser.parse_args()

def update_config(simulator, args):
    """Update simulator configuration based on command line arguments."""
    if args.rate:
        simulator.config.config['simulation']['events']['rate'] = args.rate
        logger.info(f"Set event rate to {args.rate} events per minute")
    
    if args.realism:
        simulator.config.config['simulation']['realism_level'] = args.realism
        logger.info(f"Set realism level to {args.realism}")
    
    if args.output:
        simulator.config.config['simulation']['output']['type'] = args.output
        logger.info(f"Set output destination to {args.output}")

def main():
    """Main function."""
    global simulator, running
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize simulator
        logger.info("Initializing security event simulator...")
        simulator = SecurityEventSimulator(args.config)
        
        # Update configuration based on command line arguments
        update_config(simulator, args)
        
        # Start the simulator
        logger.info("Starting security event simulator...")
        simulator.start()
        
        # Run a specific scenario if requested
        if args.scenario:
            logger.info(f"Running scenario: {args.scenario}")
            if not simulator.start_scenario(args.scenario):
                logger.error(f"Scenario not found: {args.scenario}")
        
        # Run for the specified duration
        if args.duration and args.duration > 0:
            logger.info(f"Running for {args.duration} minutes")
            end_time = time.time() + (args.duration * 60)
            
            while running and time.time() < end_time:
                time.sleep(1)
        else:
            logger.info("Running indefinitely (press Ctrl+C to stop)")
            
            while running:
                time.sleep(1)
        
        # Stop the simulator
        logger.info("Stopping security event simulator...")
        simulator.stop()
        
        logger.info("Simulation completed")
        return 0
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        if simulator:
            simulator.stop()
        return 0
    except Exception as e:
        logger.error(f"Error running simulation: {str(e)}", exc_info=True)
        if simulator:
            simulator.stop()
        return 1

if __name__ == "__main__":
    sys.exit(main())
