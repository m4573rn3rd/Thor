# Thor SNMP trap
echo "Python SNMP trap install"

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

echo "Python virtual env ready"