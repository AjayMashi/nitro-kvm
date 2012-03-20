/*
 * nitro.h
 *
 *  Created on: Nov 6, 2009
 *      Author: pfoh
 */


#ifndef SYSCALL_TRACE_H_
#define SYSCALL_TRACE_H_

#define DEBUG_INTERRUPTS 1

#ifdef DEBUG_INTERRUPTS
#define DEBUG_PRINT(...)	printk(__VA_ARGS__);
#else
#define DEBUG_PRINT(...)	while (false) {}
#endif

//#define SHADOW_IDT
#undef SHADOW_IDT

struct shadow_idt{
	__u64 base;
	__u16 limit;
	u8 *table;
};

/*
 * struct sctrace_singlestep
 * This struct indicates whether nitro is in singlestep mode and if kvm
 * should return to qemu after each syscall. Qemu will pause the machine
 *
 * implementation note: To keep interference with kvm to a minimum, this
 * struct is used instead of return codes.
 *
 * implementation note: qemu will invoce vm_stop() on the machine,
 * use the qemu monitor console 'cont' to resume execution
 */
struct sctrace_singlestep {
	int singlestep; // <! bool to indicate if we want to return to qemu after every trapped syscall
	int need_exit_to_qemu; // <! not all VMEXITs are due to a trapped syscall, only return to qemu after nitro produced output
	//int exit_reason; // <! currently unused
};

struct nitro_data{
	int running;
	char id[16];
	u64 sysenter_cs_val;
	u64 efer_val;
	u8 idt_int_offset;
	u8 idt_replaced_offset;
	int pae;
	int syscall_reg;
	int no_int;
	struct sctrace_singlestep singlestep;
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

#define VCPU_SCMON_REGS_ANY (42) // used for scmon, represnets the "any" register

int nitro_mod_init(void);
int nitro_mod_exit(void);

int nitro_kvm_init(struct kvm *kvm);
int nitro_kvm_exit(struct kvm *kvm);

int start_nitro(struct kvm *kvm,int64_t idt_index,char *syscall_reg,enum nitro_mode nitro_mode);
int stop_nitro(struct kvm *kvm);

int handle_gp(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run);
int handle_ud(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run);
int syscall_hook(char prefix, struct x86_emulate_ctxt *ctxt);

/* return true if singlestep mode is active and set exit_reason to qemu accordingly */
int nitro_check_singlestep(struct kvm_vcpu *vcpu);

int start_syscall_singlestep(struct kvm *kvm);
int stop_syscall_singlestep(struct kvm *kvm);

void get_process_hardware_id(struct kvm_vcpu *vcpu, unsigned long *cr3, u32 *verifier, unsigned long *pde);

int handle_asynchronous_interrupt(struct kvm_vcpu *vcpu);
int emulate_int_prot(struct x86_emulate_ctxt *ctxt,
		struct x86_emulate_ops *ops, int irq);

#endif /* SYSCALL_TRACE_H_ */
