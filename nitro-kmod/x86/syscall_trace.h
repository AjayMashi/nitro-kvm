/*
 * syscall_trace.h
 *
 *  Created on: Nov 6, 2009
 *      Author: pfoh
 */

#ifndef SYSCALL_TRACE_H_
#define SYSCALL_TRACE_H_

struct sctrace_data{
	int running;
	char id[16];
	u64 sysenter_cs_val;
	u64 efer_val;
	u8 idt_int_offset;
	u8 idt_replaced_offset;
	int pae;
	int syscall_reg;
	int no_int;
};

enum nitro_mode {
	NITRO_MODE_TRACE,
	NITRO_MODE_MONITORING
};

int sctrace_mod_init(void);
int sctrace_mod_exit(void);

int sctrace_kvm_init(struct kvm *kvm);

int start_syscall_trace(struct kvm *kvm,int64_t idt_index,char *syscall_reg,enum nitro_mode nitro_mode);
int stop_syscall_trace(struct kvm *kvm);

int handle_gp(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run);
int handle_ud(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run);
int syscall_hook(char prefix, struct x86_emulate_ctxt *ctxt);

#endif /* SYSCALL_TRACE_H_ */
