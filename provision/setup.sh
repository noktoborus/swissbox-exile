#!/bin/bash -e
if [ $(whoami) != "vagrant" ];
then
  su - vagrant $0 $@
  exit
fi

cd

echo "Installing keys"
mkdir -p ~/.ssh
sudo cp ~/conf.d/id_rsa.pub ~/.ssh/id_rsa.pub
sudo cp ~/conf.d/id_rsa ~/.ssh/id_rsa
sudo cp ~/conf.d/config ~/.ssh/config


echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y git protobuf-c-compiler libev-dev libpq-dev pkg-config libpthread-stubs0-dev postgresql-9.4

sudo su postgres -c 'psql -c "CREATE USER vagrant;"'
sudo su postgres -c 'psql -c "CREATE DATABASE fepserver OWNER vagrant;"'


git clone git@5.200.44.34:swissbox-server
cd swissbox-server/server
make
