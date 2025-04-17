#!/bin/bash

# APT Detection System - Production Runner
# This script starts the APT Detection System in production mode

# Set environment variables
export PYTHONPATH=$(pwd)

# Check if Python 3 is available
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python not found. Please install Python 3."
    exit 1
fi

# Check if required files exist
if [ ! -f "main.py" ]; then
    echo "Error: main.py not found. Please run this script from the project root directory."
    exit 1
fi

if [ ! -f "config.yaml" ]; then
    echo "Error: config.yaml not found. Please ensure the configuration file exists."
    exit 1
fi

# Check if models exist
if [ ! -d "models/baselines" ]; then
    echo "Warning: Baseline models not found. They will be created on first run."
fi

if [ ! -f "models/lightgbm_model.pkl" ] || [ ! -f "models/bilstm_model.h5" ]; then
    echo "Warning: ML models not found. Make sure to train models before running in production."
fi

# Start the APT Detection System in production mode
echo "Starting APT Detection System in production mode..."
$PYTHON_CMD main.py --production

# This script will not return until the application is terminated
