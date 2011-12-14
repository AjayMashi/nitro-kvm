/*
 * syscall_trace.h
 *
 *  Created on: Nov 6, 2009
 *      Author: pfoh
 */

#ifndef SYSCALL_TRACE_H_
#define SYSCALL_TRACE_H_

#define DEBUG_INT 1

#ifdef DEBUG_INT
#define DEBUG_PRINT(...)	printk(__VA_ARGS__);
#else
#define DEBUG_PRINT(...)	while (false) {}
#endif

struct shadow_idt{
	__u64 base;
	__u16 limit;
	u8 *table;
};

struct nitro_data {
	int running;
	char id[16];
	u64 sysenter_cs_val;
	u64 efer_val;
	u8 idt_int_offset;
	u8 idt_replaced_offset;
	int pae;
	int syscall_reg;
	int no_int;
	u16 orig_cs;
	struct shadow_idt shadow_idt;
};

struct gate_descriptor{
	u16 offset_low;
	u16 seg_selector;
	u16 flags;
	u16 offset_high;
};

enum nitro_mode {
	NITRO_MODE_TRACE,
	NITRO_MODE_MONITORING
};

int nitro_mod_init(void);
int nitro_mod_exit(void);

int nitro_kvm_init(struct kvm *kvm);
int nitro_kvm_exit(struct kvm *kvm);

int start_nitro(struct kvm *kvm,int64_t idt_index,char *syscall_reg,enum nitro_mode nitro_mode);
int stop_nitro(struct kvm *kvm);

int handle_gp(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run);
int handle_ud(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run);
int syscall_hook(char prefix, struct x86_emulate_ctxt *ctxt);

int load_segment_descriptor(struct x86_emulate_ctxt *ctxt,
				   struct x86_emulate_ops *ops,
				   u16 selector, int seg);

int handle_asynchronous_interrupt(struct kvm_vcpu *vcpu);

#endif /* SYSCALL_TRACE_H_ */
