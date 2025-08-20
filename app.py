#!/usr/bin/env python3
###############################################################
# Script: to run the main application with SNMP trap receiver and DNS server
# File : app.py
###############################################################

import os
import threading
import datetime
import asyncio
import socket
import logging
import queue
from flask import Flask, render_template, cli, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE

# Import pysnmp modules
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp

# --- Flask App and Database Configuration ---
app = Flask(__name__)
cli.show_server_banner = lambda *args: None

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://testuser:1234567890@localhost/snmp_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- SQLAlchemy Database Models ---
class SNMPTrap(db.Model):
    __tablename__ = 'traps'
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(100), nullable=False)
    varbinds = db.Column(JSONB)
    received_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class DnsRecord(db.Model):
    __tablename__ = 'dns_records'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)

class ThorLog(db.Model):
    __tablename__ = 'thor_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
    thread_name = db.Column(db.String(100))
    level = db.Column(db.String(20))
    message = db.Column(db.Text)

# --- Custom Logging Handler to Write to Database ---
class DatabaseLogHandler(logging.Handler):
    def emit(self, record):
        with app.app_context():
            try:
                log_entry = ThorLog(
                    thread_name=record.threadName,
                    level=record.levelname,
                    message=self.format(record)
                )
                db.session.add(log_entry)
                db.session.commit()
            except Exception:
                # If logging to the DB fails (e.g., during init), do nothing.
                # This prevents the app from crashing.
                db.session.rollback()

# --- Logging Configuration ---
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.handlers.clear()
formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
root_logger.addHandler(stream_handler)
db_handler = DatabaseLogHandler()
db_handler.setFormatter(formatter)
root_logger.addHandler(db_handler)

# --- Message Broker with Statistics Tracking ---
class MessageBroker:
    def __init__(self):
        self._queues = {}
        self._lock = threading.Lock()
        self.published_stats = {}
        self.consumed_stats = {}
        # MODIFICATION: DO NOT LOG HERE.
        # logging.info("Message Broker initialized.")
    def subscribe(self, queue_name):
        with self._lock:
            if queue_name not in self._queues:
                self._queues[queue_name] = queue.Queue()
                self.published_stats.setdefault(queue_name, 0)
                self.consumed_stats.setdefault(queue_name, 0)
                logging.info(f"Queue '{queue_name}' created.")
    def publish(self, queue_name, message):
        if queue_name not in self._queues:
            self.subscribe(queue_name)
        self._queues[queue_name].put(message)
        self.published_stats[queue_name] += 1
    def get_message(self, queue_name, block=True, timeout=None):
        if queue_name not in self._queues:
            return None
        try:
            message = self._queues[queue_name].get(block=block, timeout=timeout)
            if message:
                self.consumed_stats[queue_name] += 1
            return message
        except queue.Empty:
            return None
    def get_stats(self):
        stats = []
        with self._lock:
            for name, q in self._queues.items():
                stats.append({'name': name, 'size': q.qsize(), 'published': self.published_stats.get(name, 0), 'consumed': self.consumed_stats.get(name, 0)})
        return stats

message_broker = MessageBroker()

# --- Background Threads ---
def run_trap_receiver():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    snmpEngine = engine.SnmpEngine()
    config.add_transport(snmpEngine, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(('0.0.0.0', 162)))
    config.add_v1_system(snmpEngine, 'my-community', 'public')
    def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
        transportDomain, transportAddress = snmpEngine.message_dispatcher.get_transport_info(stateReference)
        source_ip = transportAddress[0]
        varbinds_list = [{'oid': oid.prettyPrint(), 'value': val.prettyPrint()} for oid, val in varBinds]
        trap_message = {'source_ip': source_ip, 'varbinds': varbinds_list}
        message_broker.publish('snmp_traps', trap_message)
        logging.info("Trap from %s published to 'snmp_traps' queue.", source_ip)
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)
    logging.info("SNMP Server is running on UDP port 162...")
    snmpEngine.transport_dispatcher.run_dispatcher()

def db_writer_worker():
    logging.info("Database writer worker started, waiting for messages...")
    message_broker.subscribe('snmp_traps')
    while True:
        trap_message = message_broker.get_message('snmp_traps')
        if trap_message:
            try:
                with app.app_context():
                    new_trap = SNMPTrap(source_ip=trap_message['source_ip'], varbinds=trap_message['varbinds'])
                    db.session.add(new_trap)
                    db.session.commit()
                    logging.info("Trap from %s written to database.", trap_message['source_ip'])
            except Exception as e:
                logging.error("DB writer failed to process message: %s. Error: %s", trap_message, e, exc_info=True)

def run_dns_server():
    listen_ip = '0.0.0.0'
    port = 53
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_socket.bind((listen_ip, port))
    except PermissionError:
        logging.critical("Permission denied to bind to port 53. Run with sudo.")
        return
    except OSError as e:
        logging.critical("Could not bind to %s:%s. Error: %s", listen_ip, port, e)
        return
    logging.info("DNS Server is running on UDP port %s...", port)
    while True:
        data, addr = udp_socket.recvfrom(1024)
        try:
            request = DNSRecord.parse(data)
            qname = request.q.qname
            response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            with app.app_context():
                record = DnsRecord.query.filter(DnsRecord.domain.ilike(str(qname).rstrip('.'))).first()
            if record and request.q.qtype == QTYPE.A:
                ip = record.ip_address
                response.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
                logging.info("DNS Query: %s -> %s", qname, ip)
            else:
                response.header.rcode = 3
                logging.warning("DNS Query: %s -> Not Found (NXDOMAIN)", qname)
            udp_socket.sendto(response.pack(), addr)
        except Exception as e:
            logging.error("Error handling DNS request: %s", e, exc_info=True)

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('thor.html')
    
@app.route('/traps')
def traps():
    traps = SNMPTrap.query.order_by(SNMPTrap.received_at.desc()).limit(200).all()
    return render_template('traps.html', traps=traps)

@app.route('/dns')
def dns_records():
    records = DnsRecord.query.order_by(DnsRecord.domain).all()
    return render_template('dns.html', records=records)

@app.route('/broker')
def broker_status():
    stats = message_broker.get_stats()
    return render_template('message_broker.html', stats=stats)

@app.route('/logs')
def view_logs():
    logs = ThorLog.query.order_by(ThorLog.timestamp.desc()).limit(200).all()
    return render_template('thor_logs.html', logs=logs)

@app.route('/dns/add', methods=['POST'])
def add_dns_record():
    domain = request.form.get('domain')
    ip_address = request.form.get('ip_address')
    if domain and ip_address:
        existing = DnsRecord.query.filter_by(domain=domain).first()
        if not existing:
            new_record = DnsRecord(domain=domain, ip_address=ip_address)
            db.session.add(new_record)
            db.session.commit()
            logging.info("Added DNS record: %s -> %s", domain, ip_address)
    return redirect(url_for('dns_records'))

@app.route('/dns/delete/<int:record_id>', methods=['POST'])
def delete_dns_record(record_id):
    record = DnsRecord.query.get_or_404(record_id)
    logging.info("Deleted DNS record: %s -> %s", record.domain, record.ip_address)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for('dns_records'))

# --- CLI command to initialize the database ---
@app.cli.command("init-db")
def init_db_command():
    """Creates all database tables."""
    db.create_all()
    # Use print here because the log table may not exist yet.
    print("Initialized the database. All tables are ready.")

# --- Main Execution ---
if __name__ == '__main__':
    # MODIFICATION: LOG THE BROKER INIT MESSAGE HERE
    logging.info("Message Broker initialized.")
    logging.info("Starting application threads...")
    receiver_thread = threading.Thread(target=run_trap_receiver, name="SNMPThread", daemon=True)
    receiver_thread.start()
    dns_thread = threading.Thread(target=run_dns_server, name="DNSThread", daemon=True)
    dns_thread.start()
    db_worker_thread = threading.Thread(target=db_writer_worker, name="DBWriterThread", daemon=True)
    db_worker_thread.start()
    logging.info("Starting Flask web server on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000)