/*
 * kvm_vmi.h
 *
 *  Created on: Oct 22, 2009
 *      Author: pfoh
 */

#ifndef HTFU-COMMON_H_
#define HTFU-COMMON_H_

#include <linux/ioctl.h>
//#include <linux/kvm.h>

#define KVM_BLOCK_INT	_IOW(KVMIO, 0xFA, uint32_t)
#define KVM_UNBLOCK_INT	_IOW(KVMIO, 0xFB, uint32_t)
#define KVM_WARN_INT	_IOW(KVMIO, 0xFC, uint32_t)
#define KVM_UNWARN_INT	_IOW(KVMIO, 0xFD, uint32_t)
#define KVM_BLOCK_SC	_IOW(KVMIO, 0xFE, uint32_t)
#define KVM_UNBLOCK_SC	_IOW(KVMIO, 0xFF, uint32_t)



#endif /* HTFU-COMMON_H_ */
