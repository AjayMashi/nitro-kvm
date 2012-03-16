#!/bin/sh
dpkg -i linux-headers-2.6.37-02063706-generic_2.6.37-02063706.201103281005_amd64.deb
dpkg -i linux-headers-2.6.37-02063706_2.6.37-02063706.201103281005_all.deb
dpkg -i linux-image-2.6.37-02063706-generic_2.6.37-02063706.201103281005_amd64.deb

cd /usr/src/nitro/nitro
./configure --prefix=/opt/nitro --enable-kvm --disable-xen --enable-debug
make
make install

cd /usr/src/nitro/nitro-kmod
./configure
make
rmmod kvm
rmmod kvm_intel
rmmod kvm_amd
rmmod kvm
make install
depmod -a

