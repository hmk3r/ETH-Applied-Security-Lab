#!/bin/bash
# Run this on the backup machine
KEYS_MISSING_MSG="Plese copy over keys/0 AND keys/0.pub to the current directory"
if [[ ! -f "0" || ! -f "0.pub" ]]; then
    echo "$KEYS_MISSING_MSG"
fi

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

echo -e "\e[5;1;31mNOTE\e[0m"
echo -e "If a prompt appears about a configuration file conflict, select 'Install the package maintainer's version'\e[49m":
sleep 5

mkdir packages
cd packages

wget http://security.debian.org/debian-security/pool/updates/main/o/openssl1.0/libssl1.0.2_1.0.2u-1~deb9u2_amd64.deb

dpkg -i libssl1.0.2_1.0.2u-1~deb9u2_amd64.deb
rm libssl1.0.2_1.0.2u-1~deb9u2_amd64.deb

wget http://snapshot.debian.org/archive/debian/20171006T152325Z/pool/main/o/openssh/openssh-client_7.6p1-1_amd64.deb
wget http://snapshot.debian.org/archive/debian/20171006T152325Z/pool/main/o/openssh/openssh-server_7.6p1-1_amd64.deb
wget http://snapshot.debian.org/archive/debian/20171006T152325Z/pool/main/o/openssh/openssh-sftp-server_7.6p1-1_amd64.deb
wget http://snapshot.debian.org/archive/debian/20171006T152325Z/pool/main/o/openssh/ssh_7.6p1-1_all.deb
wget http://snapshot.debian.org/archive/debian/20120229T213309Z/pool/main/d/dash/dash_0.5.7-2_amd64.deb

dpkg -i *.deb

apt-mark hold libssl1.0.2
apt-mark hold openssh-server
apt-mark hold openssh-client
apt-mark hold openssh-sftp-server
apt-mark hold ssh
apt-mark hold dash

cd ..
rm -rf packages

rm -f /etc/ssh/ssh_host_*

cp 0 /etc/ssh/ssh_host_rsa_key
cp 0.pub /etc/ssh/ssh_host_rsa_key.pub

chown root:root /etc/ssh/ssh_host_rsa_key
chown root:root /etc/ssh/ssh_host_rsa_key.pub

chmod 600 /etc/ssh/ssh_host_rsa_key
chmod 644 /etc/ssh/ssh_host_rsa_key.pub

chmod u+s `which less`
