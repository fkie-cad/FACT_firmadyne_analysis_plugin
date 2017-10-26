#!/bin/bash

echo "-> Removing addional sources"
sudo rm -R ./exploits

sudo -u postgres /usr/bin/dropdb firmware
sudo -u postgres /usr/bin/createdb -O firmadyne firmware
sudo -u postgres /usr/bin/psql -d firmware < ./database/schema
sudo rm snmp.private.txt snmp.public.txt
sudo rm log.txt

echo "-> Done."

exit 0
