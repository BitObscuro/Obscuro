
# Obscuro

## Description

The implementation of Obscuro, as proposed in [Obscuro: A Bitcoin Mixer using Trusted Execution Environments](https://www.comp.nus.edu.sg/~muoitran/papers/obscuro.pdf).  

Obscuro is used to mix 1000 users (in [a non-standard transaction](https://live.blockcypher.com/btc-testnet/tx/f5230965145ef06eb65595e41ecb701af6c128802a174f34a7b65ac7d44dc9b8/)) and 430 users (in [a standard transaction](https://live.blockcypher.com/btc-testnet/tx/59e1f4ffe3e6b735f279f340a088597af45f545e6bab4542c82a24d0014b59b9/)).

## Before we begin

* We highly recommend using VirtualBox for this demonstration.

* This guide is for you to build the project from scratch and have better understanding about the dependencies. 
Alternatively, you can use an OVA file with everything is ready for ussage, see our [Release](https://github.com/BitObscuro/Obscuro/releases/tag/v0.1.2). 

* Obscuro can run in both Hardware mode (when the platform has SGX enabled) and Simulation mode (any machine can run). 
This demo will be running in Simulation mode. If you want to run with Hardware mode, see Notes below. 

* Obscuro can run in Bitcoin Regtest/Testnet/Mainnet environment.
This demo will be running in Regtest mode due to the liquidity constraint. 

* Obscuro is tested with [Ubuntu* Desktop-16.04-LTS 64bits](http://releases.ubuntu.com/16.04.5/ubuntu-16.04.5-desktop-amd64.iso) and [Ubuntu* 16.04.3 LTS Server 64bits](http://old-releases.ubuntu.com/releases/16.04.3/ubuntu-16.04.3-server-amd64.iso) with their default kernels. We do not guarantee its compatibility with any other version of OS and kernel, unfortunately. 

* Similarly, Obscuro works well with [Intel SGX SDK for Linux version 1.8](https://github.com/intel/linux-sgx/tree/sgx_1.8). 
We do not guarantee its compatibility with more recent versions. 

## Installation

**Important note: We assume all the downloads in this section are stored in the $HOME folder.**

### Intel SGX Driver
* Download SGX 1.5 Linux Driver (master) : https://github.com/intel/linux-sgx-driver
	````
	git clone https://github.com/intel/linux-sgx-driver.git
	````
* Check and install matching header (optional):
	 ````
	cd ~/linux-sgx-driver
	dpkg-query -s linux-headers-$(uname -r)
	sudo apt-get install linux-headers-$(uname -r)
	````
* Build the Intel(R) SGX Driver
	````
	make
	sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
	sudo cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
	sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"    
	sudo /sbin/depmod
	sudo /sbin/modprobe isgx
	````
	
### Intel SGX SDK
* Download Intel(R) Software Guard Extensions for Linux* OS:
	* [Version 1.8](https://github.com/intel/linux-sgx/tree/sgx_1.8)
	````
	git clone https://github.com/intel/linux-sgx.git
	cd ~/linux-sgx
	git checkout tags/sgx_1.8
	````
* Use the following command(s) to install the required tools to build Intel(R) SGX SDK:
	```
	sudo apt-get install build-essential ocaml automake autoconf libtool wget python
	```
* Use the following command to install additional required tools to build Intel(R) SGX PSW:
	````
	 sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev
	````
	* PSW is needed for running Obscuro in Hardware mode, see [Intel Website](https://github.com/intel/linux-sgx/tree/sgx_1.8) for details.
*  Download prebuilt binaries:
	```	
	./download_prebuilt.sh
	```
* Build the Intel(R) SGX SDK
	```
	make
	```
* Build the Intel(R) SGX SDK Installer
	 ```
	make sdk_install_pkg
	```
*  Install Intel(R) SGX SDK
	````
	sudo apt-get install build-essential python
	cd linux/installer/bin
	sudo ./sgx_linux_x64_sdk_${version}.bin 
	````
	* Note: when promted by the installer, hit _No_, and enter the installation location at: _/opt/intel/_
* Test Intel(R) SGX SDK Package with the Sample Codes at your workplace, such as:
	```
	cp -r /opt/intel/sgxsdk/SampleCode ~
	cd ~/SampleCode/LocalAttestation
	make SGX_MODE=SIM
	source /opt/intel/sgxsdk/environment
	./app
	```
	* The sample code should not return any error and end up with "Hit a key..."

### Bitcoin Client
* Download [Bitcoin Core version 0.13.1](https://bitcoincore.org/bin/bitcoin-core-0.13.1/bitcoin-0.13.1-x86_64-linux-gnu.tar.gz) and extract it.
* Copy the binaries:
	```
	sudo install -m 0755 -o root -g root -t /usr/local/bin bitcoin-0.13.1/bin/*
	```
### Build Obscuro 
* Download Obscuro: https://github.com/BitObscuro/Obscuro
	```
	git clone https://github.com/BitObscuro/Obscuro.git
	```
* Build Obscuro:
	```
	cd ~/Obscuro/src
	sudo cp sgx_status.h /opt/intel/sgxsdk/include/sgx_status.h
	make
	```
	* To clean dependencies of previous make: ```make clean```
	* To clean crypto keys: ```make clear```
* Build User client:
	* Download and install the secpk256k1 library: https://github.com/bitcoin-core/secp256k1
		```
		git clone https://github.com/bitcoin-core/secp256k1.git
		cd ~/secp256k1
		./autogen.sh
		./configure
		make
		./tests #optional
		sudo make install
		```
	* Make sure the library is installed in _/usr/local/lib_
	* Build User application:
		```
		cd ~/Obscuro/src/User
		make
		```

## Demonstration
### Demonstration Methodology
We run Obscuro to scan the recent blocks for deposit transaction. When Obscuro receives 10 deposit transactions, it will start mixing and output a mixed transaction. 

The User client includes several scripts that basically send 10 deposit transactions with encrypted returning addresses embedded in them to Obscuro. 

### Starting Obscuro scanning
* Start Bitcoin Regtest server:
	```
	bitcoind -regtest -daemon	# start regtest daemon
	```
* Generate and verify that we have 50 bitcoins available to spend:
	```
	bitcoin-cli -regtest generate 101	#bootstrap blockchain
	bitcoin-cli -regtest getbalance
	```
* Bootstrap Obscuro's scanning:
	```
	cd ~/Obscuro/src
	source /opt/intel/sgxsdk/environment 	# optional
	./app scan
	```
	* Obscuro will keep scanning until _Ctrl+C_ is hit
### Sending deposit transactions
*  Open another terminal tab:
	```
	cd ~/Obscuro/src/User
	./genTx.sh		# Generate and send 10 deposit transactions
	bitcoin-cli -regtest generate 1		# Mine a block that include the deposit transaction
	```
### Checking results
* In the Obscuro scanning tab, you should be able to receive a mixed transaction in hex format. 
* Verify the mixing operation:
```bitcoin-cli -regtest decoderawtransaction <hex_mixed_transaction>```

## What's next?

### Running Obscuro in Hardware mode
* Ensure that you have the following required hardware:
    * 6th Generation Intel(R) Core(TM) Processor or newer
    * Configure the system with the  **SGX hardware enabled**  option.
    * The list of supporting hardware is available here: https://github.com/ayeks/SGX-hardware
* Modify SGX_MODE ?= HW in Makefile and rename vrfcert.sign.so.hw to vrfcert.sign.so (the old vrfcert.sign.so should be renamed to vrfcert.sign.so.sim).

### Guides
* List of Bitcoin RPC APIs, parameters, and many other information are available here: https://bitcoin.org/en/developer-reference
* Intel SGX developer zone: https://software.intel.com/en-us/sgx-sdk


## Contacts
* **Muoi Tran** - *Project maintainer* - [Email](mailto:muoitran@comp.nus.edu.sg)

## License

This project is licensed under the [MIT License](http://www.opensource.org/licenses/mit-license.php).

## Acknowledgments

* Special thanks to [Panoply team](https://shwetasshinde24.github.io/Panoply/) for letting us use their code base and for several useful comments during the deployment.

