#!/bin/bash
# Run this on all other machines except the web server machine

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

# You can just type this command in the machine, but make sure it tuns as root

mkdir packages
cd packages

wget http://snapshot.debian.org/archive/debian/20120229T213309Z/pool/main/d/dash/dash_0.5.7-2_amd64.deb

dpkg -i *.deb

apt-mark hold dash

cd ..
rm -rf packages

chmod u+s `which less`
