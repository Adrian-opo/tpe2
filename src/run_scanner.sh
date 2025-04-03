#!/bin/bash

# This script helps set up and run the port scanner GUI

echo "Setting up Network Port Scanner..."

# Install required packages
pip install -r ../requirements.txt

# Check if tkinter is installed
python3 -c "import tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Tkinter is not installed. Would you like to install it? (y/n)"
    read answer
    if [ "$answer" == "y" ] || [ "$answer" == "Y" ]; then
        echo "Installing tkinter..."
        sudo apt-get update
        sudo apt-get install -y python3-tk
    else
        echo "Tkinter is required for the GUI. Exiting."
        exit 1
    fi
fi

# Run the scanner
echo "Starting Network Port Scanner GUI..."
python3 scanner_gui.py
