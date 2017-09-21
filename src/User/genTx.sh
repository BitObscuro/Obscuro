#!/bin/bash

loop=10
mode=-regtest
denomination=0.01
denoandfee=0.0101


for (( i=1; i <= $loop; ++i ))
do
    address=$(bitcoin-cli $mode getnewaddress)

	privKey=$(bitcoin-cli $mode dumpprivkey $address)

	prevTx=$(bitcoin-cli $mode sendtoaddress $address $denoandfee)

	hexPrevTx=$(bitcoin-cli $mode getrawtransaction $prevTx)

	address2=$(bitcoin-cli $mode getnewaddress)

	privKey2=$(bitcoin-cli $mode dumpprivkey $address2)

	# ./user $hexPrevTx $privKey $privKey2
	craftTx=$(./user $hexPrevTx $privKey $privKey2)

	echo $craftTx

	t=$(bitcoin-cli $mode signrawtransaction $craftTx | grep hex)
	if [[ $t == *"error"* ]]; then
  		echo "Break when sign failed!"
  		break
	fi
	x=($(echo "$t" | sed 's/"//g'))
	signTx=$(echo ${x[1]//,})
	hexTx=$(bitcoin-cli $mode sendrawtransaction $signTx)
	echo $hexTx

	if [[ -z "$hexTx" ]]; then
  		echo "Break when send failed!"
  		break
	fi

	# bitcoin-cli $mode getbalance
	# echo "Sent $denomination coin to $mixerAdr in transaction: $hexTx"
	if ! ((i % 25)); then
		y=$(bitcoin-cli $mode generate 1)
	fi
	# sleep 5s
done