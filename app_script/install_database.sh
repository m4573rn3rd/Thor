cd ~/code
cd Thor

echo "checking for updates"
# Update your package list
sudo apt update -y  && sudo apt install update -y 

# Install snmp for test
sudo apt install snmp

# Install PostgreSQL and its contrib package
sudo apt install postgresql postgresql-contrib



# Check the service to make sure it is running.
sudo systemctl status postgresql