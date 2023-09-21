#!/bin/bash
# Run this on the CA machine

KEYS_MISSING_MSG="Plese copy over keys/1 AND keys/1.pub to the current directory"
if [[ ! -f "1" || ! -f "1.pub" ]]; then
    echo "$KEYS_MISSING_MSG"
fi

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

mkdir packages
cd packages

wget http://snapshot.debian.org/archive/debian/20120229T213309Z/pool/main/d/dash/dash_0.5.7-2_amd64.deb

dpkg -i *.deb

apt-mark hold dash

cd ..
rm -rf packages

rm -f /etc/ssh/ssh_host_*

cp 1 /etc/ssh/ssh_host_rsa_key
cp 1.pub /etc/ssh/ssh_host_rsa_key.pub

chown root:root /etc/ssh/ssh_host_rsa_key
chown root:root /etc/ssh/ssh_host_rsa_key.pub

chmod 600 /etc/ssh/ssh_host_rsa_key
chmod 644 /etc/ssh/ssh_host_rsa_key.pub

chmod u+s `which less`
