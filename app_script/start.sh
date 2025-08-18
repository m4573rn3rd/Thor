echo "starting the rec"
cd ~/code/Thor
sudo apt update -y && sudo apt install snmp -y
sudo $VIRTUAL_ENV/bin/python3 trap_receiver.py