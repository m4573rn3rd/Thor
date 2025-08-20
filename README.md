# Thor Application Suite

Thor is a multi-service Python application featuring an SNMP trap receiver, a DNS server, and a web-based monitoring dashboard. It's designed to be a lightweight, all-in-one network utility.

---
## Features

* **SNMP Trap Receiver**: Listens on UDP port 162 for SNMPv1 traps and stores them in a PostgreSQL database.
* **Authoritative DNS Server**: Responds to DNS 'A' record queries for domains managed through the web interface.
* **Internal Message Broker**: A thread-safe, in-memory queue decouples network services from database writers for improved resiliency.
* **Database Logging**: All application logs are written to a dedicated database table for easy viewing and querying.
* **Web Dashboard**: A Flask-based web interface to monitor all services, view data, and manage configuration.

---
## Installation

These instructions assume a Debian-based Linux environment (like Ubuntu).

1.  **Clone the Repository**
    ```bash
    git clone <your-repo-url>
    cd Thor
    ```

2.  **Make Scripts Executable**
    Make sure all the shell scripts in the `app_script/` directory are executable.
    ```bash
    chmod +x app_script/*.sh
    ```

3.  **Run the Installer**
    The installation script handles all system dependencies, PostgreSQL setup, and Python environment configuration. It must be run with `sudo`.
    ```bash
    sudo ./app_script/install_linux.sh
    ```

---
## Usage

#### Running Manually
To run the application directly for development or testing, use the `start.sh` script.

```bash
./app_script/start.sh

# Thor SNMP trap
Python SNMP trap

# Ports used 
162


#
mkdir ~/code
cd ~/code
# Create a new directory for your project
mkdir Thor
cd Thor

# It's a good practice to use a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the required libraries
pip install pysnmp flask flask-sqlalchemy psycopg2-binary
pip freeze > requirements.txt

# Switch to the postgres user and open the psql prompt
sudo -u postgres psql

# Endpoints

## Message Broker
http://127.0.0.1:5000/broker

## Dns
http://127.0.0.1:5000/dns

## Traps
http://127.0.0.1:5000/traps

## Logs
http://127.0.0.1:5000/logs

# -- Create a new user (role) with a password
# CREATE USER myuser WITH PASSWORD 'mypassword';

# -- Create a new database and set the owner to your new user
# CREATE DATABASE snmp_db OWNER myuser;


# -- This gives 'myuser' the same level of power as the default 'postgres' user
# ALTER USER myuser WITH SUPERUSER;

#  Exit 
#  \q


# Create Database tables 
# sudo -u postgres psql -d snmp_db
# 
# CREATE TABLE traps (
#     id SERIAL PRIMARY KEY,
#     source_ip VARCHAR(100) NOT NULL,
#     varbinds JSONB,
#     received_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc')
# );

#
# CREATE TABLE dns_records (
#     id SERIAL PRIMARY KEY,
#     domain VARCHAR(255) UNIQUE NOT NULL,
#     ip_address VARCHAR(45) NOT NULL
# );

