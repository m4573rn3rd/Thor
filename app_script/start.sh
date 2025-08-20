#!/bin/bash
###############################################################
# Script: to start the Thor program
# File : start.sh
###############################################################

echo "Starting the Thor program..."

# Navigate to the project directory
cd ~/code/Thor

# Activate the virtual environment if it's not already active
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Virtual environment not detected. Activating..."
    source venv/bin/activate
else
    echo "Virtual environment is already active."
fi

# --- NEW: Ensure log file has correct permissions ---
LOG_FILE="app.log"
echo "Preparing log file: $LOG_FILE"
# Create the log file if it doesn't exist
touch "$LOG_FILE"
# Set the owner to the current user (even if script is run with sudo)
# Sudo preserves the SUDO_USER variable, which is the original user's name.
chown ${SUDO_USER:-$(whoami)}:${SUDO_USER:-$(whoami)} "$LOG_FILE"
# --- END NEW SECTION ---

# Launch the application with sudo, preserving the environment (-E flag)
echo "Launching the application with sudo..."
sudo -E "$VIRTUAL_ENV/bin/python3" app.py