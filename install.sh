#!/usr/bin/env bash

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo "------------------------------------"
echo "       installing firmadyne         "
echo "------------------------------------"

echo "->  Install FIRMADYNE dependencies"
sudo -E apt-get install -y policykit-1
sudo -E apt-get install -y kpartx python-psycopg2 python3-psycopg2 snmp uml-utilities util-linux vlan postgresql nmap ruby ruby-dev rubygems
sudo -E apt-get install -y qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
sudo -EH pip3 install pexpect

echo "->  get Firmadyne"

FIRMADYNE_PATH=$(pwd)/bin/firmadyne
sudo rm -rf $FIRMADYNE_PATH

mkdir -p ./bin
cd ./bin
git clone --recursive https://github.com/firmadyne/firmadyne.git

# update submodules
(cd firmadyne && git pull && git submodule foreach 'git checkout master' && git submodule foreach 'git pull')

python3 ../internal/set_config.py -input $FIRMADYNE_PATH/firmadyne.config -firmadyne_path $FIRMADYNE_PATH

echo "->  Download pre-compiled binaries"

(cd firmadyne && /bin/bash download.sh)

echo "->  Initialize FIRMADYNE database"
sudo -EH python3 ../internal/init_database.py

(cd ../test/data && wget -nc 'http://www.downloads.netgear.com/files/GDC/WNAP320/WNAP320%20Firmware%20Version%202.0.3.zip' 'http://static.tp-link.com/Archer%20C1200(EU)_V1_160918.zip')

echo "-> Install Metasploit"
sudo -E apt-get -y install autoconf bison build-essential libapr1 libaprutil1 libcurl4-openssl-dev libgmp3-dev libpcap-dev libpq-dev libreadline6-dev libsqlite3-dev libssl-dev libsvn1 libtool libxml2 libxml2-dev libxslt-dev libyaml-dev locate ncurses-dev openssl postgresql postgresql-contrib xsel zlib1g zlib1g-dev
git clone https://github.com/rapid7/metasploit-framework.git
cd metasploit-framework
git pull
sudo -EH gem install bundler
sudo -EH bundle install
sudo -EH ln -s $(pwd)/msfconsole /usr/bin/
cd ..

echo "-> Install Fping"
sudo -E apt-get -y install fping


chmod a+x ../internal/additional_delete.sh
cp ../internal/additional_delete.sh firmadyne/scripts/

echo "-> add necessary sudo rights"
# Insert additional changes to the sudoers file by applying the syntax used below
CURUSER=$(whoami 2>&1)
printf "$CURUSER\tALL=NOPASSWD: /usr/bin/nmap \n\
$CURUSER\tALL=NOPASSWD: /usr/local/bin/nmap \n\
$CURUSER\tALL=NOPASSWD: $FIRMADYNE_PATH/scripts/delete.sh \n\
$CURUSER\tALL=NOPASSWD: $FIRMADYNE_PATH/scripts/additional_delete.sh \n\
$CURUSER\tALL=NOPASSWD: $FIRMADYNE_PATH/scripts/makeImage.sh \n\
$CURUSER\tALL=NOPASSWD: $FIRMADYNE_PATH/scratch/1/run.sh \n" > /tmp/firmadyne_overrides
sudo chown root:root /tmp/firmadyne_overrides
sudo mv /tmp/firmadyne_overrides /etc/sudoers.d/firmadyne_overrides

exit 0
