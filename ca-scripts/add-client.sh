#!/bin/sh -e

client="$1"
copy_only="$2"

if [ -z "$client" ]; then
	echo "add-client.sh <name>"
	exit 1
fi

c_req=/tmp/${client}-req.pem
c_key=private/${client}-key.pem
c_cert=certs/${client}-cert.pem
iddir=/tmp/${client}-id

create_id()
{
	[ -f $c_key ] && {
		echo "user already exists"
		exit 1
	}
	
	openssl ecparam -in secp521r1.pem -genkey -out ${c_key}
	openssl req -new -nodes -out $c_req -key $c_key -subj "/CN=$client"
	openssl ca -batch -config openssl.conf -out $c_cert -infiles $c_req
	rm $c_req
}

copy_id_dir()
{
	mkdir $iddir
	cp $c_cert ${iddir}/cert.pem
	cp $c_key ${iddir}/key.pem
	cp ca-cert.pem ${iddir}/
}

[ -z "$copy_only" ] && create_id
copy_id_dir
