#!/bin/bash
###############################################################
# Script: to test sending SNMP traps
# File : test_trap.sh
###############################################################

# --- Configuration ---
DESTINATION="127.0.0.1:162"
COMMUNITY="public"
TRAP_OID="1.3.6.1.6.3.1.1.5.1"

# --- Payload (Variable Bindings) ---
# Each piece (OID, Type, Value) is now a separate element in the array.
PAYLOAD=(
    1.3.6.1.4.1.8072.2.3.0.1 s "Test alert from script"
    1.3.6.1.4.1.8072.2.3.2.1 i 42
)

echo "Sending SNMP trap to $DESTINATION..."

# --- The snmptrap command ---
snmptrap -v 2c -c "$COMMUNITY" "$DESTINATION" '' "$TRAP_OID" "${PAYLOAD[@]}"

echo "Trap sent."