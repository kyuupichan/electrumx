# Instructions for running on an Ubuntu 16.04 server:

# Install necessary packages

	sudo apt-get -y install build-essential python-dev python-setuptools python-pip python-smbus
	sudo apt-get -y install libncursesw5-dev libgdbm-dev libc6-dev
	sudo apt-get -y install zlib1g-dev libsqlite3-dev tk-dev
	sudo apt-get -y install libssl-dev openssl
	sudo apt-get -y install libffi-dev
	sudo ufw allow 50001/tcp # Needed to allow incoming connections
	sudo ufw allow 50002/tcp # Needed to allow incoming connections

# Install Python 3.7

	mkdir /tmp/Python37
	cd /tmp/Python37
	wget https://www.python.org/ftp/python/3.7.0/Python-3.7.0.tar.xz
	tar xvf Python-3.7.0.tar.xz
	cd /tmp/Python37/Python-3.7.0
	./configure
	sudo make altinstall

# Setup your local virtualenv for Python

	sudo pip install virtualenv
	cd ~
	virtualenv -p /usr/local/bin/python3.7 ve 
	echo "source ve/bin/activate" >> ~/.bashrc
	. ~/.bashrc
	python --version # Should show 3.7
	pip install plyvel pylru aiorpcx aiohttp
	pip install git+https://github.com/traysi/x16r_hash

# Install ElectrumX

	git clone https://github.com/traysi/electrumx.git
	cd electrumx/
	python setup.py install
	mkdir -p ~/.electrumx/rvn
	openssl genrsa -des3 -passout pass:x -out ~/server.pass.key 2048
	openssl rsa -passin pass:x -in ~/server.pass.key -out ~/.electrumx/server.key
	rm ~/server.pass.key
	# Don’t set a password in the next step !
	openssl req -new -key ~/.electrumx/server.key -out ~/.electrumx/server.csr
	openssl x509 -req -days 1825 -in ~/.electrumx/server.csr -signkey ~/.electrumx/server.key -out ~/.electrumx/server.crt

# Edit ~/electrumx/start_ravencoin to update the variables to reflect your local environment.

	~/electrumx/start_ravencoin &
	tail -f ~/.electrumx/electrumx.log # to watch the logs.

It'll take a while to connect and build its local database, so be patient. After the syncing is finished, you can connect and test it with:

(echo '{ "id": 0, "method": "server.version", "params": [ "2.7.11", "1.3" ] }'; sleep 3) | ncat --ssl localhost 50002

You should see a response like:

{"jsonrpc": "2.0", "result": ["ElectrumX 1.8.5", "1.3"], "id": 0}

