#!/bin/bash
###############################################################
# Script : to install and set up the Thor program on Linux
# File : install_linux.sh
###############################################################

# --- 1. Sudo Check ---
# This script needs to be run with sudo to install system packages.
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run with sudo: sudo ./install_linux.sh" 
   exit 1
fi

# --- 2. Define Users and Paths ---
# Identify the user who ran sudo, default to 'pi' or current user if not set
TARGET_USER=${SUDO_USER:-$(whoami)}
TARGET_HOME=$(eval echo ~$TARGET_USER)
PROJECT_DIR="$TARGET_HOME/code/Thor"
DB_NAME="snmp_db"
DB_USER="testuser"
DB_PASS="1234567890"

echo "--- Thor Installer ---"
echo "Running setup for user: $TARGET_USER"
echo "Project Directory: $PROJECT_DIR"

# --- 3. Create Directory and Set Ownership ---
echo "Ensuring project directory exists..."
mkdir -p "$PROJECT_DIR"
# This is a key fix: ensure the target user owns the directory
chown -R "$TARGET_USER:$TARGET_USER" "$(dirname "$PROJECT_DIR")"

# --- 4. System Package Installation (as root) ---
echo "Updating package list..."
apt update -y

echo "Checking for required system packages..."
if ! dpkg -s snmp &> /dev/null; then
    apt install -y snmp
else
    echo "SNMP is already installed."
fi
if ! dpkg -s postgresql &> /dev/null; then
    apt install -y postgresql postgresql-contrib
else
    echo "PostgreSQL is already installed."
fi

# --- 5. Database Setup (as root/postgres) ---
systemctl start postgresql
systemctl enable postgresql
if ! systemctl is-active --quiet postgresql; then
    echo "Error: PostgreSQL service is not running."
    exit 1
fi
echo "PostgreSQL service is running."

echo "Configuring PostgreSQL database..."
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1; then
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
fi
if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;"
fi
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

# --- 6. Prerequisite Check ---
# The rest of the script needs your app.py file to be present.
if [ ! -f "$PROJECT_DIR/app.py" ]; then
    echo "ERROR: app.py not found in $PROJECT_DIR."
    echo "Please place your application files in the directory before running this installer."
    exit 1
fi

# --- 7. Python Environment Setup (as the TARGET_USER) ---
# This is another key fix: all python commands are run as the user, not root.
echo "Setting up Python environment as user $TARGET_USER..."
sudo -u "$TARGET_USER" bash << EOF
cd "$PROJECT_DIR"

# Clean up old environment
rm -rf __pycache__ venv

# Create and activate venv, then install packages
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip &> /dev/null
pip install pysnmp flask flask-sqlalchemy psycopg2-binary dnslib  

# Initialize the database tables
echo "Creating database tables..."
flask init-db
EOF
# --- End of user-specific commands ---

echo
echo "Thor installation complete for user $TARGET_USER!"