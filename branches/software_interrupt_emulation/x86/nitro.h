/*
 * nitro.h
 *
 *  Created on: Nov 6, 2009
 *      Author: pfoh
 */


#ifndef NITRO_H_
#define NITRO_H_


/**************************** Global options for nitro ****************************/

#define VCPU_SCMON_REGS_ANY (42) 		// Used for scmon, represents the "any"
										// register
#define DUM_SEG_SELECT 		0xFFFF		// Value to be used to simulate the absence
										// of IDT entries
#define SHADOW_IDT			1			// Whether to use the shadow idt technique
//#define DEBUG_INTERRUPTS 	1			// Switch for debugging interrupt emulation
//#define USE_NETLINK			1			// Switch between netlink and dmesg (printk)
#define NETLINK_NITRO 		42			// Value used as id for netlink connection
#define NETLINK_MC_GROUP	13			// Multicast group for receiving user space
										// processes
#define OUTPUT_MAX_CHARS	4096		// Buffer size for each output message

/** Nothing below this line should be changed, configure only the macros above! ***/
/**********************************************************************************/

#ifdef SHADOW_IDT
struct shadow_idt {
	__u64 base;
	__u16 limit;
	u8 *table;
};
#endif

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
	struct sctrace_singlestep singlestep;
	struct shadow_idt shadow_idt;
};

struct gate_descriptor {
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

/* return true if singlestep mode is active and set exit_reason to qemu accordingly */
int nitro_check_singlestep(struct kvm_vcpu *vcpu);

int start_syscall_singlestep(struct kvm *kvm);
int stop_syscall_singlestep(struct kvm *kvm);

void get_process_hardware_id(struct kvm_vcpu *vcpu, unsigned long *cr3, u32 *verifier, unsigned long *pde);

int handle_asynchronous_interrupt(struct kvm_vcpu *vcpu);
int emulate_int_prot(struct x86_emulate_ctxt *ctxt, struct x86_emulate_ops *ops, int irq);

#endif /* NITRO_H_ */
