#!/usr/bin/env python3
###############################################################
# Script: to receive and process DNS records
# File : dns_reciver.py
###############################################################

import socket
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE

# --- Database Connection Setup ---
# This URI should match the one in your main application
DATABASE_URI = 'postgresql://testuser:1234567890@localhost/snmp_db'
db_engine = sqlalchemy.create_engine(DATABASE_URI)
Session = sessionmaker(bind=db_engine)
Base = declarative_base()

# --- SQLAlchemy Database Model ---
# This class maps to the 'dns_records' table in your database.
# It's needed for SQLAlchemy to understand the table structure.
class DnsRecord(Base):
    __tablename__ = 'dns_records'
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False)
    ip_address = Column(String(45), nullable=False)

    def __repr__(self):
        return f'<DnsRecord {self.domain} -> {self.ip_address}>'

# --- Main DNS Server Logic ---
def run_dns_server():
    """
    This function runs a simple DNS server that queries a PostgreSQL database.
    """
    listen_ip = '0.0.0.0'
    port = 53
    
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((listen_ip, port))
        
    print(f"DNS Server is running on {listen_ip}:{port}...")

    while True:
        # Wait for a DNS query
        data, addr = udp_socket.recvfrom(1024)
        try:
            # Parse the raw data into a DNSRecord object
            request = DNSRecord.parse(data)
            qname = request.q.qname
            qtype = request.q.qtype

            # Create a DNS response header from the request's header
            response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            
            # --- Database Lookup ---
            session = Session()
            # Query the database for a matching domain name (case-insensitive)
            record = session.query(DnsRecord).filter(DnsRecord.domain.ilike(str(qname).rstrip('.'))).first()
            session.close()

            # If a record is found and the query is for an 'A' record (IPv4)
            if record and qtype == QTYPE.A:
                ip = record.ip_address
                response.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
                print(f"Query handled: {qname} -> {ip}")
            else:
                # If no record is found, set the response code to NXDOMAIN (Non-Existent Domain)
                response.header.rcode = 3 
                print(f"Query failed: {qname} -> Not Found (NXDOMAIN)")

            # Send the response back to the client
            udp_socket.sendto(response.pack(), addr)

        except Exception as e:
            print(f"Error handling DNS request: {e}")

# --- Main Execution ---
if __name__ == '__main__':
    try:
        run_dns_server()
    except PermissionError:
        print("\n[ERROR] Permission denied to bind to port 53.")
        print("Please run this script with root privileges: 'sudo python3 dns_reciver.py'")
    except KeyboardInterrupt:
        print("\nDNS server stopped.")