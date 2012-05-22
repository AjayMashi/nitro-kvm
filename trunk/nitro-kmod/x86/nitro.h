/*
 * nitro.h
 *
 *  Created on: Nov 6, 2009
 *      Author: pfoh
 */


#ifndef SYSCALL_TRACE_H_
#define SYSCALL_TRACE_H_



/************************************** Global options for nitro ****************************************/

#define VCPU_SCMON_REGS_ANY 	(42) 			/* Used for scmon, represents the "any" 	*/
							/* register */
#define DUM_SEG_SELECT 		0xFFFF			/* Value to be used to simulate the absence 	*/
							/* of IDT entries */
#undef SHADOW_IDT					/* Whether to use the shadow idt technique 	*/
//#define DEBUG_INTERRUPTS 	1			/* Switch for debugging interrupt emulation 	*/
#define USE_NETLINK		1			/* Switch between netlink and dmesg (printk) 	*/
#define NETLINK_NITRO 		26			/* Value used as netlink protocol type. 	*/
							/* Be sure to pick a value < MAX_LINKS as	*/
							/* defined in linux/netlink.h (default is 32) 	*/
#define NETLINK_MC_GROUP	13			/* Multicast group for receiving user space 	*/
							/* processes (needs to be < 32)			*/
#define OUTPUT_MAX_CHARS	1024 - 20		/* Buffer size for each output message 		*/
#define NETLINK_EXIT		"NITRO_NETLINK_EXIT"
#define NITRO_HEXDUMP_BPL	16			/* bytecount per line in hexdumps 		*/

/************* Nothing below this line should be changed, configure only the macros above! **************/
/********************************************************************************************************/

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

enum cpu_mode {
	UNDEF,
	PROT,
	PAE,
	LONG
};

struct nitro_data{
	int running;
	char id[16];
	u64 sysenter_cs_val;
	u64 efer_val;
	u8 idt_int_offset;
	u8 idt_replaced_offset;
	//int pae;
	enum cpu_mode mode;
	int idt_entry_size;
	int syscall_reg;
	int no_int;
	struct sctrace_singlestep singlestep;
#ifdef SHADOW_IDT
	struct shadow_idt shadow_idt;
#endif
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
