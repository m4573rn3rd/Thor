#!/usr/bin/env python3
###############################################################
# Script: to run the main application with SNMP trap receiver and DNS server
# File : app.py
###############################################################

import threading
import datetime
import socket
import logging
import queue
import asyncio
import time
import json
from flask import Flask, render_template, cli, request, redirect, url_for, Response
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

# --- MODIFIED: Message Broker to support SSE broadcasting ---
class MessageBroker:
    def __init__(self):
        self._queues = {}
        self._lock = threading.Lock()
        self.published_stats = {}
        self.consumed_stats = {}
        self.listeners = [] # For SSE clients

    def subscribe(self, queue_name):
        with self._lock:
            if queue_name not in self._queues:
                self._queues[queue_name] = queue.Queue()
                self.published_stats.setdefault(queue_name, 0)
                self.consumed_stats.setdefault(queue_name, 0)
                logging.info(f"Queue '{queue_name}' created.")

    def publish(self, queue_name, message, event_type=None):
        """Publishes a message to a main queue and broadcasts to SSE listeners."""
        # Publish to the internal queue for workers if it's a main queue
        if queue_name in self._queues:
            self._queues[queue_name].put(message)
            self.published_stats[queue_name] += 1
        
        # Broadcast the event to any listening web clients
        if event_type:
            sse_data = f"event: {event_type}\ndata: {json.dumps(message)}\n\n"
            for q in self.listeners:
                q.put(sse_data)

    def get_message(self, queue_name, block=True, timeout=None):
        if queue_name not in self._queues: return None
        try:
            message = self._queues[queue_name].get(block=block, timeout=timeout)
            if message: self.consumed_stats[queue_name] += 1
            return message
        except queue.Empty: return None
        
    def add_listener(self, listener_queue):
        self.listeners.append(listener_queue)

    def remove_listener(self, listener_queue):
        if listener_queue in self.listeners:
            self.listeners.remove(listener_queue)

    def get_stats(self):
        stats = []
        with self._lock:
            # We add listener queues to the stats display for debugging
            queue_names = list(self._queues.keys()) + [f"listener_{i}" for i, _ in enumerate(self.listeners)]
            for name in queue_names:
                if name.startswith('listener'):
                    q = self.listeners[int(name.split('_')[1])]
                    stats.append({'name': name, 'size': q.qsize(), 'published': 'N/A', 'consumed': 'N/A'})
                else:
                    q = self._queues[name]
                    stats.append({'name': name, 'size': q.qsize(), 'published': self.published_stats.get(name, 0), 'consumed': self.consumed_stats.get(name, 0)})
        return stats

message_broker = MessageBroker()

# --- Custom Logging Handler ---
class DatabaseLogHandler(logging.Handler):
    def emit(self, record):
        with app.app_context():
            try:
                log_entry = ThorLog(thread_name=record.threadName, level=record.levelname, message=self.format(record))
                db.session.add(log_entry)
                db.session.commit()
                # Broadcast the new log entry as an SSE event
                event_data = {
                    'timestamp': log_entry.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'level': log_entry.level,
                    'thread_name': log_entry.thread_name,
                    'message': log_entry.message
                }
                # Publish only as an event, not to another main queue
                message_broker.publish(None, event_data, event_type='new_log')
            except Exception:
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

# --- Service Manager Class ---
class ServiceManager:
    def __init__(self):
        self.services = {}
        self._lock = threading.Lock()
    def register(self, name, target, thread_name):
        with self._lock:
            self.services[name] = {
                'target': target,
                'thread_name': thread_name,
                'thread': None,
                'stop_event': None,
                'loop': None
            }
            logging.info(f"Service '{name}' registered.")
    def start(self, name):
        with self._lock:
            service = self.services.get(name)
            if service and (service['thread'] is None or not service['thread'].is_alive()):
                logging.info(f"Starting service: {name}")
                service['stop_event'] = threading.Event()
                service['thread'] = threading.Thread(
                    target=service['target'],
                    name=service['thread_name'],
                    args=(service['stop_event'],),
                    daemon=True
                )
                service['thread'].start()
                return True
        logging.warning(f"Service '{name}' is already running or not registered.")
        return False
    def stop(self, name):
        with self._lock:
            service = self.services.get(name)
            if service and service['thread'] and service['thread'].is_alive():
                logging.info(f"Stopping service: {name}")
                if name == 'SNMP Trap Receiver' and service.get('loop'):
                    service['loop'].call_soon_threadsafe(service['loop'].stop)
                if service['stop_event']:
                    service['stop_event'].set()
                return True
        logging.warning(f"Service '{name}' is not running or not registered.")
        return False
    def start_all(self):
        for name in self.services:
            self.start(name)
    def get_status(self):
        status = []
        with self._lock:
            for name, service in self.services.items():
                status.append({
                    'name': name,
                    'is_alive': service['thread'] is not None and service['thread'].is_alive()
                })
        return status

service_manager = ServiceManager()

# --- NEW: SSE Event Stream Generator ---
def sse_event_stream():
    q = queue.Queue()
    message_broker.add_listener(q)
    try:
        while True:
            message = q.get()
            yield message
    finally:
        message_broker.remove_listener(q)

# --- Background Threads ---
def run_trap_receiver(stop_event):
    logging.info("SNMP Server starting (asyncio)...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    service_manager.services['SNMP Trap Receiver']['loop'] = loop

    snmpEngine = engine.SnmpEngine()
    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(('0.0.0.0', 162))
    )
    config.add_v1_system(snmpEngine, 'my-community', 'public')

    def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
        transportDomain, transportAddress = snmpEngine.message_dispatcher.get_transport_info(stateReference)
        source_ip = transportAddress[0]
        varbinds_list = [{'oid': oid.prettyPrint(), 'value': val.prettyPrint()} for oid, val in varBinds]
        trap_message = {'source_ip': source_ip, 'varbinds': varbinds_list}
        message_broker.publish('snmp_traps', trap_message)
        logging.info("Trap from %s published.", source_ip)
    
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    try:
        snmpEngine.transport_dispatcher.run_dispatcher()
    finally:
        snmpEngine.transport_dispatcher.close_dispatcher()
        logging.info("SNMP Server has stopped.")

def db_writer_worker(stop_event):
    logging.info("Database writer worker starting...")
    message_broker.subscribe('snmp_traps')
    while not stop_event.is_set():
        trap_message = message_broker.get_message('snmp_traps', timeout=1)
        if trap_message:
            try:
                with app.app_context():
                    new_trap = SNMPTrap(source_ip=trap_message['source_ip'], varbinds=trap_message['varbinds'])
                    db.session.add(new_trap)
                    db.session.commit()
                    logging.info("Trap from %s written to database.", trap_message['source_ip'])
                    event_data = {
                        'id': new_trap.id,
                        'received_at': new_trap.received_at.strftime('%Y-%m-%d %H:%M:%S'),
                        'source_ip': new_trap.source_ip,
                        'varbinds': new_trap.varbinds
                    }
                    message_broker.publish(None, event_data, event_type='new_trap')
            except Exception as e:
                logging.error("DB writer failed: %s", e, exc_info=True)
    logging.info("Database writer worker has stopped.")

def run_dns_server(stop_event):
    logging.info("DNS Server starting...")
    listen_ip = '0.0.0.0'
    port = 53
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(1.0)
    try:
        udp_socket.bind((listen_ip, port))
    except Exception as e:
        logging.critical(f"DNS Server failed to bind: {e}")
        return
    while not stop_event.is_set():
        try:
            data, addr = udp_socket.recvfrom(1024)
            request = DNSRecord.parse(data)
            qname = request.q.qname
            response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            with app.app_context():
                record = DnsRecord.query.filter(DnsRecord.domain.ilike(str(qname).rstrip('.'))).first()
            if record and request.q.qtype == QTYPE.A:
                response.add_answer(RR(qname, QTYPE.A, rdata=A(record.ip_address), ttl=60))
                logging.info("DNS Query: %s -> %s", qname, record.ip_address)
            else:
                response.header.rcode = 3
                logging.warning("DNS Query: %s -> Not Found", qname)
            udp_socket.sendto(response.pack(), addr)
        except socket.timeout:
            continue
        except Exception as e:
            logging.error("Error in DNS server loop: %s", e)
    udp_socket.close()
    logging.info("DNS Server has stopped.")

# --- Flask Routes ---
@app.route('/')
def index(): 
    return render_template('thor.html', active_page='index')
    
@app.route('/traps')
def traps():
    traps = SNMPTrap.query.order_by(SNMPTrap.received_at.desc()).limit(200).all()
    return render_template('traps.html', traps=traps, active_page='traps')

@app.route('/dns')
def dns_records():
    records = DnsRecord.query.order_by(DnsRecord.domain).all()
    return render_template('dns.html', records=records, active_page='dns')

@app.route('/broker')
def broker_status():
    stats = message_broker.get_stats()
    return render_template('message_broker.html', stats=stats, active_page='broker')

@app.route('/logs')
def view_logs():
    logs = ThorLog.query.order_by(ThorLog.timestamp.desc()).limit(200).all()
    return render_template('thor_logs.html', logs=logs, active_page='logs')

@app.route('/services')
def view_services():
    return render_template('service_manager.html', services=service_manager.get_status(), active_page='services')

@app.route('/getTime')
def get_time():
    browser_time = request.args.get("time", "Not Provided")
    server_time = time.strftime('%A, %B %d %Y %H:%M:%S')
    logging.info(f"Browser time ping: {browser_time}")
    logging.info(f"Server time at ping: {server_time}")
    return '', 204

@app.route('/service/start/<service_name>', methods=['POST'])
def start_service(service_name):
    service_manager.start(service_name)
    return redirect(url_for('view_services'))
@app.route('/service/stop/<service_name>', methods=['POST'])
def stop_service(service_name):
    service_manager.stop(service_name)
    return redirect(url_for('view_services'))

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

# --- NEW: Flask Route for the SSE Stream ---
@app.route('/stream')
def stream():
    return Response(sse_event_stream(), mimetype="text/event-stream")

# --- CLI command to initialize the database ---
@app.cli.command("init-db")
def init_db_command():
    print("Creating all database tables...")
    db.create_all()
    print("Tables created successfully.")

# --- Main Execution using ServiceManager ---
if __name__ == '__main__':
    logging.info("Message Broker initialized.")
    service_manager.register('SNMP Trap Receiver', run_trap_receiver, 'SNMPThread')
    service_manager.register('DNS Server', run_dns_server, 'DNSThread')
    service_manager.register('Database Writer', db_writer_worker, 'DBWriterThread')
    service_manager.start_all()
    logging.info("Starting Flask web server on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000)