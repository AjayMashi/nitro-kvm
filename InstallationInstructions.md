# Overview #
Nitro is an extension to KVM, hence the compilation and installation is identical to that of KVM.  You will have to compile the userland portion (nitro) and the kernel modules (nitro-kmod).  The binarys and modules have the same names as their KVM counterparts.  That is, usage is also identical to that of KVM.

Please be aware that Nitro **only** works for the Intel virtualization extensions.  That is, only the Intel kernel module has the Nitro extensions.


Nitro has been tested with Debian 6.0.3 (though a kernel upgrade is required) and (K)Ubuntu 11.04 and is based on qemu-kvm-0.13.0 and kvm-kmod-2.6.37.