import asyncio
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from app import SNMPTrap
import json

# --- Database Connection Setup ---
DATABASE_URI = 'postgresql://testuser:1234567890@localhost/snmp_db'
db_engine = sqlalchemy.create_engine(DATABASE_URI)
Session = sessionmaker(bind=db_engine)

# --- Callback Function for Processing Traps ---
def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    print("--- New Trap Received ---")
    # This is the corrected line
    transportDomain, transportAddress = snmpEngine.message_dispatcher.get_transport_info(stateReference) # <--- FINAL FIX
    source_ip = transportAddress[0]
    print(f"Source IP: {source_ip}")

    varbinds_list = []
    for oid, val in varBinds:
        oid_str = oid.prettyPrint()
        val_str = val.prettyPrint()
        varbinds_list.append({'oid': oid_str, 'value': val_str})
        print(f"{oid_str} = {val_str}")

    session = Session()
    try:
        new_trap = SNMPTrap(source_ip=source_ip, varbinds=varbinds_list)
        session.add(new_trap)
        session.commit()
        print("Trap successfully stored in the database.")
    except Exception as e:
        print(f"Error storing trap: {e}")
        session.rollback()
    finally:
        session.close()

# --- Main Execution ---
def main():
    snmpEngine = engine.SnmpEngine()
    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(('0.0.0.0', 162))
    )
    config.add_v1_system(snmpEngine, 'my-community', 'public')
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)
    print("SNMP trap receiver is running...")
    snmpEngine.transport_dispatcher.run_dispatcher()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Receiver stopped.")