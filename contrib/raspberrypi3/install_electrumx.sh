###################
# install electrumx
###################

# upgrade raspbian to 'stretch' distribution for python 3.5 support
sudo echo 'deb http://mirrordirector.raspbian.org/raspbian/ testing main contrib non-free rpi' > /etc/apt/sources.list.d/stretch.list
sudo apt-get update
sudo apt-get dist-upgrade
sudo apt-get autoremove

# install electrumx dependencies
sudo apt-get install python3-pip
sudo apt-get install build-essential libc6-dev
sudo apt-get install libncurses5-dev libncursesw5-dev libreadline6-dev
sudo apt-get install libleveldb-dev
sudo apt-get install git
sudo pip3 install plyvel
sudo pip3 install irc

# install electrumx
git clone https://github.com/kyuupichan/electrumx.git
cd electrumx
sudo python3 setup.py install

