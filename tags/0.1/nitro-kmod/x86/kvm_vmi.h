/*
 * kvm_vmi.h
 *
 *  Created on: Oct 22, 2009
 *      Author: pfoh
 */

#ifndef VMI_H_
#define VMI_H_

#include <linux/ioctl.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>

struct kvm_vmi_data {
	unsigned long idt_index;
	char syscall_reg[4];
};

struct kvm_scmon_rule {
	unsigned int cond_reg;
	unsigned long cond_val;
	unsigned int action_reg;
	long action_reg_offset;
	unsigned int action;
};

struct kvm_scmon_str {
	char* string;
	unsigned int length;
};

#define KVM_START_SCTRACE  	_IOW(KVMIO, 0xF0, struct kvm_vmi_data)
#define KVM_STOP_SCTRACE   	_IO(KVMIO, 0xF1)
#define KVM_START_SCMON  	_IOW(KVMIO, 0xF2, struct kvm_vmi_data)
#define KVM_STOP_SCMON   	_IO(KVMIO, 0xF3)
#define KVM_LIST_SCMON_RULES	_IOW(KVMIO, 0xF4, struct kvm_scmon_str)
#define KVM_FLUSH_SCMON_RULES	_IO(KVMIO, 0xF5)
#define KVM_ADD_SCMON_RULE		_IOW(KVMIO, 0xF6, struct kvm_scmon_rule)
#define KVM_REMOVE_SCMON_RULE	_IOW(KVMIO, 0xF7, long)





#endif /* VMI_H_ */
