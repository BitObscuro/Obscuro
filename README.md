# Obscuro

## Description

The implementation of Obscuro, as proposed in [Obscuro: A Secure and Anonymous Bitcoin Mixer using SGX](TBD).  

In this demonstration, we set up Obscuro in the Intel SGX Simulation mode so
that any machine meets the prerequisites can run it. Due to the liquidity
problem, this proof-of-concept implementation is run in Bitcoin Regtest mode.


## Prerequisites
Following is the software configuration required for Intel SGX SDK and Obscuro.
* [Ubuntu* Desktop-14.04-LTS 64bits](http://old-releases.ubuntu.com/releases/trusty/ubuntu-14.04.1-desktop-amd64.iso)
* Note that this demonstration has been tested to work on [Linux Kernel v3.13.0-106-generic](http://packages.ubuntu.com/trusty/kernel/linux-image-3.13.0-106-generic)


## Install
### Install Intel SGX SDK
Download Intel(R) Software Guard Extensions for Linux* OS
* [Version 1.6](https://github.com/01org/linux-sgx/tree/sgx_1.6)

Build and install Intel(R) SGX SDK
- Use the following command to install the required tools to build Intel(R) SGX SDK:  
```
sudo apt-get install build-essential ocaml automake autoconf libtool
```
- Use the script `download_prebuilt.sh` inside source code package to download prebuilt binaries to prebuilt folder
```
./download_prebuilt.sh
```
- Build Intel SGX SDK 
```
make
```
- To build Intel(R) SGX SDK installer, enter the following command
```
make sdk_install_pkg
```
You can find the generated Intel SGX SDK installer `sgx_linux_x64_sdk_${version}.bin` located under `linux/installer/bin/`, where `${version}` refers to the version number.
- To install Intel(R) SGX SDK, enter the following commands and install SGX SDK to /opt/intel
```
cd linux/installer/bin
./sgx_linux_x64_sdk_${version}.bin 
```
- Compile and run each sample codes in the simulation mode to make sure the package works well.  
```
  $ cd SampleCode/LocalAttestation
  $ make SGX_MODE=SIM
  $ ./app
```
### Install Bitcoin Client
* [Bitcoin Core version 0.13.1](https://github.com/bitcoin/bitcoin/archive/v0.13.1.tar.gz).

### Some notes 
- To run Obscuro in  Hardware mode on an SGX-enable machine: Modify SGX_MODE ?= HW in Makefile and rename vrfcert.sign.so.hw to vrfcert.sign.so (the old vrfcert.sign.so should be renamed to vrfcert.sign.so.sim).
- If get compile time error about “sgx-status.h”, copy the file from src/ to /opt/intel/sgxsdk/include/sgx_status.h
- If get error when run ./app after rebooting: "./app: error while loading shared libraries: libsgx_urts_sim.so: cannot open shared object file: No such file or directory", uninstall SGX SDK from /opt/intel and reinstall it

## Running the demo

- Start Bitcoin Regtest server

```
bitcoind -regtest -daemon

bitcoin-cli -regtest generate 101
```
- Verify that we now have 50 bitcoins available to spend
```
bitcoin-cli -regtest getbalance
50.00000000
```

- Build Obscuro

```
cd src
make
```
- To clean dependencies of previous make
```
make clean
```
- To clear ElGamal and ECDSA private keys of Obscuro
```
make clear

```
- Bootstrap (load blocks up to current best block, generate new keys) and scan for deposit transaction in the next blocks.
Setup the size of the mixing transaction in \MyEnclave\MyEnclave.cpp, set nSize to some number.
```
./app scan
```

- To craft the deposit transaction of the user side

```
cd User
make
```
- Run genTx.sh to generate the transactions for mixing. Set the number of the transaction in genTx.sh.
User application takes a hexed string of previous transaction (funding for deposit transaction), key to spend the previous transaction,
and the key for the returing address.
```
./genTx.sh
```



## Contacts
* **Muoi Tran** - *Project maintainer* - [Email](mailto:muoitran@comp.nus.edu.sg)

## License

This project is licensed under the [MIT License](http://www.opensource.org/licenses/mit-license.php).

## Acknowledgments

* Special thanks to [Panoply team](https://shwetasshinde24.github.io/Panoply/) who let us use their code base and give us several comments during the deployment.

