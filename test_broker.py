#!/usr/bin/env python3
###############################################################
# Script: to test the Message Broker functionality
# File : test_broker.py
###############################################################

import threading
import time
import logging

# Import the broker instance from your main application file
from app import message_broker

# --- Configure Logging for the Test ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
)

def producer_task(queue_name, messages):
    """A task that publishes a list of messages to a specified queue."""
    logging.info(f"Starting producer for '{queue_name}'.")
    for msg in messages:
        message_broker.publish(queue_name, msg)
        logging.info(f"Published to '{queue_name}': {msg}")
        time.sleep(0.3)  # Simulate some work
    logging.info(f"Producer for '{queue_name}' has finished.")

def consumer_task(queue_name, stop_event):
    """A task that consumes messages from a queue until a stop event is set."""
    logging.info(f"Starting consumer for '{queue_name}'.")
    while not stop_event.is_set():
        # Use a timeout so the loop can check the stop_event periodically
        message = message_broker.get_message(queue_name, timeout=0.5)
        if message:
            logging.info(f"Consumed from '{queue_name}': {message}")
    logging.info(f"Consumer for '{queue_name}' is shutting down.")

# --- Main Test Execution ---
if __name__ == '__main__':
    logging.info("--- Starting Message Broker Test ---")

    stop_event = threading.Event()

    # 1. Define Test Data for two different queues
    snmp_test_messages = [
        {'source_ip': '10.1.1.1', 'data': 'Link Down'},
        {'source_ip': '10.2.2.2', 'data': 'High CPU'},
        {'source_ip': '10.3.3.3', 'data': 'Auth Failure'}
    ]
    
    event_test_messages = [
        {'event': 'user_login', 'user': 'admin'},
        {'event': 'service_restart', 'service': 'webserver'}
    ]

    # 2. Setup Consumer and Producer Threads
    threads = [
        # Consumers
        threading.Thread(target=consumer_task, args=('snmp_traps', stop_event), name="SNMP-Consumer"),
        threading.Thread(target=consumer_task, args=('system_events', stop_event), name="Events-Consumer"),
        # Producers
        threading.Thread(target=producer_task, args=('snmp_traps', snmp_test_messages), name="SNMP-Producer"),
        threading.Thread(target=producer_task, args=('system_events', event_test_messages), name="Events-Producer")
    ]

    # 3. Run the Test
    for thread in threads:
        thread.start()

    # Wait only for the producer threads to finish
    for thread in threads:
        if 'Producer' in thread.name:
            thread.join()
    
    logging.info("--- All producers have finished. ---")

    # Give consumers a moment to process any remaining messages
    time.sleep(1)

    # 4. Verify the Results
    logging.info("--- Verifying Broker Statistics ---")
    stats = message_broker.get_stats()
    all_ok = True
    for s in stats:
        logging.info(f"Queue '{s['name']}': Size={s['size']}, Published={s['published']}, Consumed={s['consumed']}")
        if s['published'] != s['consumed'] or s['size'] != 0:
            logging.error(f"TEST FAILED: Mismatch found in queue '{s['name']}'!")
            all_ok = False
            
    if all_ok:
        logging.info("TEST PASSED: All statistics match.")

    # 5. Shutdown
    logging.info("--- Shutting down consumer threads... ---")
    stop_event.set()
    for thread in threads:
        if 'Consumer' in thread.name:
            thread.join()

    logging.info("--- Test Script Finished ---")