#!/usr/bin/env python3
###############################################################
# Script: to act as a message broker for SNMP traps and DNS records and other messages
# File : message_broker.py
###############################################################

import queue
import threading
import time
import logging

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
)

class MessageBroker:
    """
    A simple, thread-safe, in-memory message broker.
    It manages multiple named queues and tracks statistics.
    """
    def __init__(self):
        """Initializes the message broker and statistics trackers."""
        self._queues = {}
        self._lock = threading.Lock()
        self.published_stats = {}
        self.consumed_stats = {}
        logging.info("Message Broker initialized.")

    def subscribe(self, queue_name):
        """
        Ensures a queue exists. Call this from a consumer before it starts listening.
        """
        with self._lock:
            if queue_name not in self._queues:
                self._queues[queue_name] = queue.Queue()
                self.published_stats[queue_name] = 0
                self.consumed_stats[queue_name] = 0
                logging.info(f"Queue '{queue_name}' created.")

    def publish(self, queue_name, message):
        """
        Publishes a message to a specific queue.
        """
        if queue_name not in self._queues:
            self.subscribe(queue_name)
        
        self._queues[queue_name].put(message)
        self.published_stats[queue_name] += 1

    def get_message(self, queue_name, block=True, timeout=None):
        """
        Retrieves a message from a specific queue.
        """
        if queue_name not in self._queues:
            logging.warning(f"Attempted to get message from non-existent queue '{queue_name}'.")
            return None
        
        try:
            message = self._queues[queue_name].get(block=block, timeout=timeout)
            if message:
                self.consumed_stats[queue_name] += 1
            return message
        except queue.Empty:
            return None

    def get_stats(self):
        """Returns a list of dictionaries with stats for each queue."""
        stats = []
        with self._lock:
            for name, q in self._queues.items():
                stats.append({
                    'name': name,
                    'size': q.qsize(),
                    'published': self.published_stats.get(name, 0),
                    'consumed': self.consumed_stats.get(name, 0),
                })
        return stats

# --- Singleton Instance ---
message_broker = MessageBroker()


# --- Example Usage (demonstrates how it works) ---
if __name__ == '__main__':
    
    # Use an Event for graceful shutdown
    stop_event = threading.Event()

    def snmp_trap_producer():
        """A producer that simulates receiving SNMP traps."""
        for i in range(5):
            trap_message = {'source_ip': f'192.168.1.{i}', 'data': 'CPU high'}
            logging.info(f"Publishing trap message {i+1}")
            message_broker.publish('snmp_traps', trap_message)
            time.sleep(0.5)

    def db_writer_consumer():
        """A consumer that simulates writing messages to a database."""
        logging.info("Waiting for messages on 'snmp_traps' queue...")
        while not stop_event.is_set():
            # Use a timeout to periodically check the stop_event
            message = message_broker.get_message('snmp_traps', timeout=1)
            if message:
                logging.info(f"Got message: {message}. Simulating DB write...")
        logging.info("Consumer shutting down.")

    # --- Main Demonstration Logic ---
    logging.info("--- Message Broker Demonstration ---")
    
    message_broker.subscribe('snmp_traps')

    # Create and start threads
    consumer_thread = threading.Thread(target=db_writer_consumer, name="ConsumerThread")
    producer_thread = threading.Thread(target=snmp_trap_producer, name="ProducerThread")
    
    consumer_thread.start()
    producer_thread.start()

    # Wait for the producer to finish its work
    producer_thread.join()
    
    logging.info("Producer has finished.")
    
    # Log the final stats
    time.sleep(1) # Give consumer a moment to process final items
    final_stats = message_broker.get_stats()
    logging.info(f"Final Broker Stats: {final_stats}")

    # Signal the consumer to stop and wait for it
    logging.info("Signaling consumer to stop.")
    stop_event.set()
    consumer_thread.join()

    logging.info("Demonstration finished.")