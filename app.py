import os
import threading
import datetime
import asyncio  # <--- Import asyncio
from flask import Flask, render_template, cli
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import DateTime

# Import pysnmp modules
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp

# --- Flask App and Database Configuration ---
app = Flask(__name__)
cli.show_server_banner = lambda *args: None

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://testuser:1234567890@localhost/snmp_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- SQLAlchemy Database Model ---
class SNMPTrap(db.Model):
    __tablename__ = 'traps'
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(100), nullable=False)
    varbinds = db.Column(JSONB)
    received_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# --- SNMP Trap Receiver Logic ---
def run_trap_receiver():
    """This function runs the SNMP trap receiver in a separate thread."""
    # Create and set a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    snmpEngine = engine.SnmpEngine()
    
    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(('0.0.0.0', 162))
    )
    config.add_v1_system(snmpEngine, 'my-community', 'public')

    def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
        """Callback function to process received traps."""
        print("--- New Trap Received ---")
        transportDomain, transportAddress = snmpEngine.message_dispatcher.get_transport_info(stateReference)
        source_ip = transportAddress[0]
        print(f"Source IP: {source_ip}")

        varbinds_list = []
        for oid, val in varBinds:
            oid_str = oid.prettyPrint()
            val_str = val.prettyPrint()
            varbinds_list.append({'oid': oid_str, 'value': val_str})
            print(f"{oid_str} = {val_str}")

        with app.app_context():
            new_trap = SNMPTrap(source_ip=source_ip, varbinds=varbinds_list)
            db.session.add(new_trap)
            db.session.commit()
            print("Trap successfully stored in the database.")

    ntfrcv.NotificationReceiver(snmpEngine, cbFun)
    print("SNMP trap receiver is running in a background thread...")
    snmpEngine.transport_dispatcher.run_dispatcher()

# --- Flask Routes ---
@app.route('/')
def index():
    """Main route to display received traps."""
    traps = SNMPTrap.query.order_by(SNMPTrap.received_at.desc()).all()
    return render_template('traps.html', traps=traps)

# --- CLI command to initialize the database ---
@app.cli.command("init-db")
def init_db_command():
    """Creates the database tables."""
    db.create_all()
    print("Initialized the database.")

# --- Main Execution ---
if __name__ == '__main__':
    receiver_thread = threading.Thread(target=run_trap_receiver, daemon=True)
    receiver_thread.start()

    print("Starting Flask web server...")
    app.run(host='0.0.0.0', port=5000)