#!/bin/bash
modprobe kvm
modprobe kvm-intel
/opt/nitro/bin/qemu-system-x86_64 -snapshot -chardev vc,id=foo -monitor stdio -m 1024 -usbdevice tablet -vnc :0 /opt/windows-xpsp3-hd.img
