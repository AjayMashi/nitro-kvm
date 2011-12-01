/*
 * kvm_vmi.h
 *
 *  Created on: Oct 22, 2009
 *      Author: pfoh
 */

#ifndef HTFU_COMMON_H_
#define HTFU_COMMON_H_

#include <linux/ioctl.h>
//#include <linux/kvm.h>

#define KVM_HARDEN	_IOW(KVMIO, 0xFA, uint32_t)
#define KVM_UNHARDEN	_IO(KVMIO, 0xFB)
#define KVM_WARN_INT	_IO(KVMIO, 0xFC)
#define KVM_UNWARN_INT	_IO(KVMIO, 0xFD)
#define KVM_BLOCK_SC	_IOW(KVMIO, 0xFE, uint32_t)
#define KVM_UNBLOCK_SC	_IOW(KVMIO, 0xFF, uint32_t)



#endif /* HTFU_COMMON_H_ */
