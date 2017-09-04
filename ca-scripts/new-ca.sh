#!/bin/sh -e

name="$1"
target="$2"
olddir="$(pwd)"

if [ -z "$name" ]; then
	echo "usage: new-ch.sh [name] [location][.]"
	exit 0
fi

if [ -z "$target" ]; then
	target="."
fi

target="${target}/${name}"
mkdir $target
chmod 700 $target
cp openssl.conf add-client.sh $target/

cd $target
mkdir certs private newcerts
echo 1000 > serial
touch index.txt index.txt.attr

openssl ecparam -name secp521r1 -out secp521r1.pem
openssl ecparam -in secp521r1.pem -genkey -out ca-key.pem
openssl req -new -x509 -days 36500 -key ca-key.pem -out ca-cert.pem -config openssl.conf -subj "/CN=$name"
cd "$oldir"

echo "********************************"
echo "cd $target"
echo "./add-client [name]"
echo "********************************"
