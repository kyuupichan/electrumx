#!/bin/sh
###################
# install electrumx
###################

# Remove "raspi-copies-and-fills" as it breaks the upgrade process
sudo apt-get purge raspi-copies-and-fills

# upgrade raspbian to 'stretch' distribution
sudo echo 'deb http://mirrordirector.raspbian.org/raspbian/ testing main contrib non-free rpi' > /etc/apt/sources.list.d/stretch.list
sudo apt-get update
sudo apt-get dist-upgrade
sudo apt-get autoremove

# install electrumx dependencies
sudo apt-get install python3-pip
sudo apt-get install build-essential libc6-dev
sudo apt-get install libncurses5-dev libncursesw5-dev
sudo apt install libreadline6-dev/stable libreadline6/stable
sudo apt-get install libleveldb-dev
sudo apt-get install git
sudo pip3 install plyvel

# install electrumx
git clone https://github.com/kyuupichan/electrumx.git
cd electrumx
sudo python3 setup.py install
