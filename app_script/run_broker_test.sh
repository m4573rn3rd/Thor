#!/bin/bash
###############################################################
# Script: to run the Python test script for the Message Broker
# File : run_broker_test.sh
###############################################################

echo "--- Starting Message Broker Test Runner ---"

# Define project paths
PROJECT_DIR="$HOME/code/Thor"
VENV_PATH="$PROJECT_DIR/venv/bin/activate"
TEST_SCRIPT="test_broker.py"

# 1. Navigate to the project directory
echo "Navigating to project directory..."
if [ ! -d "$PROJECT_DIR" ]; then
    echo "ERROR: Project directory not found at $PROJECT_DIR"
    exit 1
fi
cd "$PROJECT_DIR"

# 2. Activate the Python virtual environment
echo "Activating virtual environment..."
if [ ! -f "$VENV_PATH" ]; then
    echo "ERROR: Virtual environment not found. Please run install_linux.sh first."
    exit 1
fi
source "$VENV_PATH"

# 3. Run the Python test script and capture its output
echo "Executing Python test script: $TEST_SCRIPT..."
if [ ! -f "$TEST_SCRIPT" ]; then
    echo "ERROR: Test script '$TEST_SCRIPT' not found."
    exit 1
fi

TEST_OUTPUT=$(python3 "$TEST_SCRIPT" 2>&1)
EXIT_CODE=$?

# Display the full, real-time output from the Python script
echo
echo "----------------- Test Script Output ------------------"
echo "$TEST_OUTPUT"
echo "-------------------------------------------------------"
echo

# 4. Analyze the output to determine the final result
echo "Analyzing test results..."
if [ $EXIT_CODE -ne 0 ]; then
    echo "TEST SUMMARY: FAILED (Python script exited with error code: $EXIT_CODE)"
elif echo "$TEST_OUTPUT" | grep -q "TEST PASSED"; then
    echo "TEST SUMMARY: PASSED"
elif echo "$TEST_OUTPUT" | grep -q "TEST FAILED"; then
    echo "TEST SUMMARY: FAILED (Test reported a failure)"
else
    echo "TEST SUMMARY: UNKNOWN (Could not determine pass/fail status from output)"
fi

echo
echo "--- Test Runner Finished ---"