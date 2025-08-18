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