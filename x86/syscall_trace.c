/*
 * syscall_trace.c
 *
 *  Created on: Nov 6, 2009
 *      Author: pfoh
 */



#include <linux/kvm_host.h>
#include "kvm_cache_regs.h"
#include "x86.h"
#include "mmu.h"
#include "kvm_vmi.h"
#include "nitro_output.h"
#include "syscall_trace.h"
#include "syscall_monitor.h"
#include "tss.h"
#include "lapic.h"

#define DUM_SEG_SELECT 0xFFFF

extern int kvm_write_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);
extern int kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);
extern int is_sysenter_sysreturn(struct kvm_vcpu *vcpu);
extern int is_int(struct kvm_vcpu *vcpu);
extern int emulate_int(struct x86_emulate_ctxt *ctxt, struct x86_emulate_ops *ops, int irq);

static int original_selector = 0;

int nitro_mod_init(void){
	return 0;

}

int nitro_mod_exit(void){
	return 0;
	//nitro_output_exit();
}

int nitro_kvm_init(struct kvm *kvm){
	kvm->nitro_data.running = 0;
	kvm->nitro_data.id[0] = '\0';
	kvm->nitro_data.sysenter_cs_val = 0;
	kvm->nitro_data.efer_val = 0;
	kvm->nitro_data.idt_int_offset = 0;
	kvm->nitro_data.idt_replaced_offset = 0;
	kvm->nitro_data.pae = 0;
	kvm->nitro_data.no_int = 0;
	kvm->nitro_data.syscall_reg = VCPU_REGS_RAX;
	kvm->nitro_data.shadow_idt.base = 0;
	kvm->nitro_data.shadow_idt.limit = 0;
	kvm->nitro_data.shadow_idt.table = 0;
	return 0;
}

int nitro_kvm_exit(struct kvm *kvm){
	if(kvm->nitro_data.shadow_idt.table != 0){
		kfree(kvm->nitro_data.shadow_idt.table);
	}
	return 0;
}

int start_nitro(struct kvm *kvm,int64_t idt_index,char* syscall_reg,enum nitro_mode nitro_mode){
	int i, output_init;
	u16 j;
	struct kvm_sregs sregs;
	u8 *idt;
	u64 idt_base,efer;
	u32 error;
	unsigned long cr4,cr0;
	struct kvm_vcpu *vcpu;

	printk("idt_index = %ld, syscall_reg = %s\n", (long int) idt_index, syscall_reg);

	if(kvm->nitro_data.running){
		printk("kvm:start_syscall_trace: WARNING: nitro is already running, start will be aborted.\n");
		return 1;
	}

	vcpu=kvm_get_vcpu(kvm,0);

	// check if idt_index is an intelligent value
	printk("check if idt index is an intelligent value\n");
	vcpu_load(vcpu);
	kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
	vcpu_put(vcpu);

	if(idt_index == 0){
		kvm->nitro_data.no_int = 1;
	}
	else if(idt_index<32 || idt_index>(sregs.idt.limit+1)/8){
		printk("kvm:start_syscall_trace: ERROR: invalid idt_index passed, start will be aborted.\n");
		return 2;
	}
	else{
		kvm->nitro_data.idt_int_offset = (u8) idt_index;
	}

	//check if Paging/PAE/IA32-E mode
	printk("check if Paging/PAE/IA32-E mode available\n");
	printk("get some registers\n");
	//cr0 = kvm->vcpus[0]->arch.cr0;
	//cr4 = kvm->vcpus[0]->arch.cr4;
	cr0 = sregs.cr0;
	cr4 = sregs.cr4;
	printk("kvm_get_msr_common\n");
	//kvm_get_msr_common(kvm->vcpus[0], MSR_EFER, &efer);
	efer = sregs.efer;

	if(!(cr0 & 0x80000000)){
		printk("kvm:start_syscall_trace: WARNING: paging not set in guest, aborting system call tracing.\n");
		return 3;
	}

	if(cr4 & 0x00000020){
		if(efer & EFER_LME){
			kvm->nitro_data.pae = 2;
			printk("kvm:start_syscall_trace: starting syscall trace with IA32-E on.\n");
		}
		else{
			kvm->nitro_data.pae = 1;
			printk("kvm:start_syscall_trace: starting syscall trace with PAE on.\n");
		}
	}
	else{
		kvm->nitro_data.pae = 0;
		printk("kvm:start_syscall_trace: starting syscall trace with PAE/IA32-E off.\n");
	}

	// set syscall_reg
	printk("set syscall_reg\n");
	if (strcmp(syscall_reg, "rbx") == 0) {
		kvm->nitro_data.syscall_reg = VCPU_REGS_RBX;
	}
	else if (strcmp(syscall_reg, "rcx") == 0) {
		kvm->nitro_data.syscall_reg = VCPU_REGS_RCX;
	}
	else if (strcmp(syscall_reg, "rdx") == 0) {
		kvm->nitro_data.syscall_reg = VCPU_REGS_RDX;
	}
	else {
		kvm->nitro_data.syscall_reg = VCPU_REGS_RAX;
	}
	printk("kvm:start_syscall_trace: starting syscall trace with syscall_reg = %d, name='%s'\n", kvm->nitro_data.syscall_reg, syscall_reg);

	if (nitro_mode == NITRO_MODE_TRACE) {
		kvm->nitro_data.running = 1;
	}
	else if (nitro_mode == NITRO_MODE_MONITORING) {
		kvm->nitro_data.running = 2;
	}

	//code to set #GP trap
	//i=0;
	//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->set_gp_trap(vcpu);
		printk("kvm:start_syscall_trace: cpu%d: GP trap set\n",i);
		vcpu_put(vcpu);

		//i++;
	}


	//code to cause sysenter to cause #GP
	//i=0;
	//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->get_msr(vcpu, MSR_IA32_SYSENTER_CS, &(kvm->nitro_data.sysenter_cs_val));
		kvm_x86_ops->set_msr(vcpu, MSR_IA32_SYSENTER_CS, 0);
		vcpu_put(vcpu);

		//i++;
	}

	//code to cause syscall to cause #UD (64 bit ubuntu)
	//i=0;
	//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_get_msr_common(vcpu, MSR_EFER, &(kvm->nitro_data.efer_val));
		kvm_set_msr_common(vcpu, MSR_EFER, kvm->nitro_data.efer_val & ~EFER_SCE);
		vcpu_put(vcpu);

		//i++;
	}


	//old code to cause int x to cause #GP/#NP
	//i=0;
/*
	idt_base = 0;

	if(!kvm->nitro_data.no_int){

		//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		kvm_for_each_vcpu(i, vcpu, kvm){
			kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);

			if(sregs.idt.base != idt_base){
				idt_base = sregs.idt.base;

				idt = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
				memset(idt,0,sregs.idt.limit + 1);
				//kvm_read_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit + 1));
				kvm_read_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);


				kvm->nitro_data.idt_replaced_offset = 0x81;

				//for(j=32;j<(sregs.idt.limit + 1)/8;j++){
				for(j=((sregs.idt.limit + 1)/8) - 1; j>=32;j--){
					//printk("kvm:start_syscall_trace: checking IDT gate 0x%hX, p=0x%X, seg. sel.=%hu\n",j,(idt[(j*8)+5] & 0x80),*((u16*) (idt +  (INT_OFFSET*8) + 2)));
					if((idt[(j*8)+5] & 0x80) == 0){
						kvm->nitro_data.idt_replaced_offset = (u8)j;
						break;
					}
				}

				printk("kvm:start_syscall_trace: using empty gate 0x%hX\n",kvm->nitro_data.idt_replaced_offset);

				memcpy(idt + (kvm->nitro_data.idt_replaced_offset*8), idt + (kvm->nitro_data.idt_int_offset*8), 8);

				kvm->nitro_data.orig_cs = *((u16*) (idt +  (kvm->nitro_data.idt_int_offset*8) + 2));
				*((u16*) (idt +  (kvm->nitro_data.idt_int_offset*8) + 2)) = DUM_SEG_SELECT;  //set selector
				//idt[(INT_OFFSET*8) + 5] &= 0x7F;  //unset present bit

				//kvm_write_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit));
				kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);

				kfree(idt);
			}

			i++;
		}

	}

*/
	//extern int emulator_read_emulated(unsigned long addr, void *val, unsigned int bytes, unsigned int *error_code, struct kvm_vcpu *vcpu)

	if(!kvm->nitro_data.no_int){
		kvm_for_each_vcpu(i, vcpu, kvm){
			kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
			if(kvm->nitro_data.shadow_idt.base == 0){
				kvm->nitro_data.shadow_idt.base = sregs.idt.base;
				kvm->nitro_data.shadow_idt.limit = sregs.idt.limit;
				kvm->nitro_data.shadow_idt.table = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
				memset(kvm->nitro_data.shadow_idt.table,0,sregs.idt.limit + 1);
				kvm_read_guest_virt_system(sregs.idt.base,kvm->nitro_data.shadow_idt.table,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);
			}
			sregs.idt.limit=32*8-1;
			kvm_arch_vcpu_ioctl_set_sregs(vcpu,&sregs);
		}
	}













/*
	idt_base = 0;

	if(!kvm->nitro_data.no_int){

		//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		kvm_for_each_vcpu(i, vcpu, kvm){
			kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);

			if(sregs.idt.base != idt_base){
				idt_base = sregs.idt.base;

				idt = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
				memset(idt,0,sregs.idt.limit + 1);
				//kvm_read_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit + 1));
				kvm_read_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);

				/*
				kvm->nitro_data.idt_replaced_offset = 0x81;

				//for(j=32;j<(sregs.idt.limit + 1)/8;j++){
				for(j=((sregs.idt.limit + 1)/8) - 1; j>=32;j--){
					//printk("kvm:start_syscall_trace: checking IDT gate 0x%hX, p=0x%X, seg. sel.=%hu\n",j,(idt[(j*8)+5] & 0x80),*((u16*) (idt +  (INT_OFFSET*8) + 2)));
					if((idt[(j*8)+5] & 0x80) == 0){
						kvm->nitro_data.idt_replaced_offset = (u8)j;
						break;
					}
				}

				printk("kvm:start_syscall_trace: using empty gate 0x%hX\n",kvm->nitro_data.idt_replaced_offset);

				memcpy(idt + (kvm->nitro_data.idt_replaced_offset*8), idt + (kvm->nitro_data.idt_int_offset*8), 8);

				original_selector = *((u16*) (idt +  (kvm->nitro_data.idt_int_offset*8) + 2));
				*((u16*) (idt +  (kvm->nitro_data.idt_int_offset*8) + 2)) = DUM_SEG_SELECT;  //set selector
				//idt[(INT_OFFSET*8) + 5] &= 0x7F;  //unset present bit

				//kvm_write_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit));
				kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);

				kfree(idt);
			}

			i++;
		}

	}
*/













	/*
	 * Proc Output
	output_init = nitro_output_init();

	if (output_init != 0) {
		stop_syscall_trace(kvm);
		return 1;
	}
	 */

	return 0;
}

int nitro_temp_restore_idt(struct kvm *kvm, struct kvm_vcpu *vcpu) {
	int i;
	struct kvm_sregs sregs;

	if(!kvm->nitro_data.no_int){
		kvm_for_each_vcpu(i, vcpu, kvm){
			printk("Temporarily restored IDT for cpu%u.\n", i);
			kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
			sregs.idt.limit = kvm->nitro_data.shadow_idt.limit;
			kvm_arch_vcpu_ioctl_set_sregs(vcpu,&sregs);
		}
	}
	return 0;
}

int nitro_temp_rehook_idt(struct kvm *kvm, struct kvm_vcpu *vcpu) {
	int i;
	int error;
	struct kvm_sregs sregs;

	if(!kvm->nitro_data.no_int){
		kvm_for_each_vcpu(i, vcpu, kvm){
			printk("Temporarily rehooked IDT for cpu%u.\n", i);
			kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
			sregs.idt.limit = 255;
			kvm_arch_vcpu_ioctl_set_sregs(vcpu,&sregs);
		}
	}
	return 0;
}

int stop_nitro(struct kvm *kvm){
	int i;
	struct kvm_sregs sregs;
	u8 *idt;
	u64 idt_base;
	u32 error;

	if(!kvm->nitro_data.running){
		printk("kvm:stop_syscall_trace: WARNING: nitro is not started, stop will be aborted.\n");
		return 1;
	}

	nitro_output_exit();
	//sctrace_kvm_init(kvm);

	kvm->nitro_data.running = 0;

	//code to unset #GP trap
	i=0;
	while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		vcpu_load(kvm->vcpus[i]);
		kvm_x86_ops->unset_gp_trap(kvm->vcpus[i]);
		printk("kvm:start_syscall_trace: cpu%d: GP trap unset\n",i);
		vcpu_put(kvm->vcpus[i]);

		i++;
	}


	//code to cause sysenter not to cause #GP
	i=0;
	while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		vcpu_load(kvm->vcpus[i]);
		kvm_x86_ops->set_msr(kvm->vcpus[i], MSR_IA32_SYSENTER_CS, kvm->nitro_data.sysenter_cs_val);
		vcpu_put(kvm->vcpus[i]);

		i++;
	}

	//code to cause syscall not to cause #UD (64 bit ubuntu)
	i=0;
	while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		vcpu_load(kvm->vcpus[i]);
		kvm_set_msr_common(kvm->vcpus[i], MSR_EFER, kvm->nitro_data.efer_val);
		vcpu_put(kvm->vcpus[i]);

		i++;
	}


	//old code to cause int x not to cause #GP/#NP
	/*
	i=0;
	idt_base = 0;

	if(!kvm->nitro_data.no_int){

		while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
			kvm_arch_vcpu_ioctl_get_sregs(kvm->vcpus[i],&sregs);

			if(sregs.idt.base != idt_base){
				idt_base = sregs.idt.base;

				idt = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
				memset(idt,0,sregs.idt.limit + 1);
				//kvm_read_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit + 1));
				kvm_read_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),kvm->vcpus[i],&error);

				memcpy(idt + (kvm->nitro_data.idt_int_offset*8), idt + (kvm->nitro_data.idt_replaced_offset*8), 8);

				//kvm_write_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit));
				kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),kvm->vcpus[i],&error);

				kfree(idt);
			}

			i++;
		}

	}
	*/


	return 0;
}

int sctrace_print_trace(char prefix, struct kvm_vcpu *vcpu){
	unsigned long cr3, dir_base, pde, screg;
	u32 i;
	u32 verifier=0, pde_32;
	char *sctrace_line;

	screg = kvm_register_read(vcpu, vcpu->kvm->nitro_data.syscall_reg);
	cr3 = vcpu->arch.cr3;
	//pdptr0 = kvm_pdptr_read(vcpu,0);

	if (vcpu->kvm->nitro_data.pae == 1){//PAE
		dir_base = cr3 & 0xFFFFFFFFFFFFFFE0;	//see section 4.3 in intel manual

		for (i=0;i<4*8;i+=8){
			kvm_read_guest(vcpu->kvm,dir_base+i,&pde,8);
				//printk("kvm:handle_gp: kvm_read_guest_virt_system error: %u\n",error);
			if((pde & PT_PRESENT_MASK)){//  &&  !(pde & PT_WRITABLE_MASK)){
				verifier=i;
				goto FOUND;
			}
		}
	}
	else if (vcpu->kvm->nitro_data.pae == 2){//IA-32E
		dir_base = cr3 & 0x000FFFFFFFFFF000;	//see section 4.3 in intel manual

		for (i=0;i<512*8;i+=8){
			kvm_read_guest(vcpu->kvm,dir_base+i,&pde,8);
				//printk("kvm:handle_gp: kvm_read_guest_virt_system error: %u\n",error);
			if((pde & PT_PRESENT_MASK)){//  &&  !(pde & PT_WRITABLE_MASK)){
				verifier=i;
				goto FOUND;
			}
		}
	}
	else{//32-bit
		dir_base = cr3 & 0xFFFFFFFFFFFFF000;  	//see section 4.3 in intel manual

		for (i=0;i<1024*4;i+=4){
			kvm_read_guest(vcpu->kvm,dir_base+i,&pde_32,4);
				//printk("kvm:handle_gp: kvm_read_guest_virt_system error: %u\n",error);
			if((pde_32 & PT_PRESENT_MASK)){//  &&  !(pde & PT_WRITABLE_MASK)){
				verifier=i;
				pde = (unsigned long)pde_32;
				goto FOUND;
			}
		}
	}
	pde=0;

FOUND:
/*
 * Proc Output
	sctrace_line = (char *) kmalloc(256, GFP_KERNEL);
	if (sctrace_line == NULL) {
		return -1;
	}

	snprintf(sctrace_line, 255, "kvm:syscall trace(%c): %s:0x%lX:%u:0x%lX %lu\n", prefix, vcpu->kvm->nitro_data.id, cr3, verifier, pde, screg);
	nitro_output_append(sctrace_line, 255);
*/

printk("kvm:syscall trace(%c): %s:0x%lX:%u:0x%lX %lu\n", prefix, vcpu->kvm->nitro_data.id, cr3, verifier, pde, screg);

	return 0;
}

int print_trace_proxy(char prefix, struct kvm_vcpu *vcpu){
	int ret;

	ret = 0;
	if (vcpu->kvm->nitro_data.running == 1) {
		ret = sctrace_print_trace(prefix, vcpu);
	}
	else if (vcpu->kvm->nitro_data.running == 2) {
		ret = scmon_print_trace(prefix, vcpu);
	}

	return ret;
}

/* Ugly 32bit arch specific push emulation. sucks. */
int push(struct kvm_vcpu *vcpu, unsigned long value) {

	u32 error;

	/* decrease the value of esp by 4 */
	kvm_register_write(
			vcpu,
			VCPU_REGS_RSP,
			kvm_register_read(vcpu, VCPU_REGS_RSP) - sizeof(value)
			);

	/* write the new data on top of the stack */
	kvm_write_guest_virt_system(
			kvm_register_read(vcpu, VCPU_REGS_RSP),
			&value,
			sizeof(value),
			vcpu,
			error);

	printk("Pushing %08X onto the stack. New ESP is %08X.\n", value, kvm_register_read(vcpu, VCPU_REGS_RSP));
}

static inline void
setup_syscalls_segments(struct x86_emulate_ctxt *ctxt,
			struct x86_emulate_ops *ops, struct kvm_desc_struct *cs,
			struct kvm_desc_struct *ss)
{
	memset(cs, 0, sizeof(struct kvm_desc_struct));
	ops->get_cached_descriptor(cs, VCPU_SREG_CS, ctxt->vcpu);
	memset(ss, 0, sizeof(struct kvm_desc_struct));

	cs->l = 0;		/* will be adjusted later */
	kvm_set_desc_base(cs, 0);	/* flat segment */
	cs->g = 1;		/* 4kb granularity */
	kvm_set_desc_limit(cs, 0xfffff);	/* 4GB limit */
	cs->type = 0x0b;	/* Read, Execute, Accessed */
	cs->s = 1;
	cs->dpl = 0;		/* will be adjusted later */
	cs->p = 1;
	cs->d = 1;

	kvm_set_desc_base(ss, 0);	/* flat segment */
	kvm_set_desc_limit(ss, 0xfffff);	/* 4GB limit */
	ss->g = 1;		/* 4kb granularity */
	ss->s = 1;
	ss->type = 0x03;	/* Read/Write, Accessed */
	ss->d = 1;		/* 32bit stack segment */
	ss->dpl = 0;
	ss->p = 1;
}

int handle_user_interrupt(struct kvm_vcpu *vcpu, u32 int_nr){
	struct gate_descriptor int_gate;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_desc_struct desc_new_cs;
	struct kvm_desc_struct desc_new_ss;
	u32 offset, error, newESP;
	u16 newSS;
	u8 gateType = 0;
	u8 dpl = 0;
	u8 cpl = 0;

	unsigned long ss, esp, eflags, cs, eip;
	struct tss_segment_32 tss_segment;
	//struct decode_cache *c = &vcpu->arch.emulate_ctxt.decode;

	setup_syscalls_segments(&vcpu->arch.emulate_ctxt, vcpu->arch.emulate_ctxt.ops, &desc_new_cs, &desc_new_ss);

	//int_nr=128;

	/*if (int_nr == 45) {
		kvm_arch_vcpu_ioctl_get_regs(vcpu,&regs);
		regs.rip += 2;
		kvm_arch_vcpu_ioctl_set_regs(vcpu,&regs);
		return 0;
	}*/

	kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
	kvm_arch_vcpu_ioctl_get_regs(vcpu,&regs);
	kvm_read_guest_virt_system(sregs.idt.base + (int_nr * 8),&int_gate,8,vcpu,&error);
	dpl = (int_gate.flags & 0x60) >> 5;
	//cpl = sregs.cs.dpl;
	cpl = vcpu->arch.emulate_ctxt.ops->cpl(vcpu);
	//cpl = 3;
	gateType = (int_gate.flags >> 8) & 0xf;


	printk("CPL = 0x%x, DPL = 0x%x\n", cpl, dpl);
	if (dpl == cpl) printk("Handling INTRA_PRIVILEGE_LEVEL_INTERRUPT\n");
	printk("EFER = 0x%llx\n", sregs.efer);

	/*
	if(kvm->nitro_data.shadow_idt.table != NULL)
		kfree(kvm->nitro_data.shadow_idt.table);
	kvm->nitro_data.shadow_idt.table = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
	memset(kvm->nitro_data.shadow_idt.table,0,sregs.idt.limit + 1);
	kvm_read_guest_virt_system(sregs.idt.base,kvm->nitro_data.shadow_idt.table,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);
	*/

	printk("kvm:handle_user_interrupt: int_nr=%u kvm->nitro_data.shadow_idt.limit=%u 8*int_nr=%u\n",int_nr,vcpu->kvm->nitro_data.shadow_idt.limit,8*int_nr);

	//int_gate = (struct gate_descriptor *) vcpu->kvm->nitro_data.shadow_idt.table + (int_nr * 8);

	//nitro_output_print_gdt_entries(vcpu);
	//nitro_output_print_idt_entries(vcpu);

	/* Okay, here we go. Let's try to keep as close as possible to the
	 * Intel-Doc.
	 */

	/* Step 1:  Temporarily saves (internally) the current contents of the
	 * SS, ESP, EFLAGS, CS, and EIP registers.
	 */

	ss = sregs.ss.selector;
	esp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	eflags = vcpu->arch.emulate_ctxt.eflags;
	cs = sregs.cs.selector;
	eip = kvm_register_read(vcpu, VCPU_REGS_RIP);

	printk("EIP is at 0x%08X.\n", eip);

	/* Step 2: Loads the segment selector and stack pointer for the new stack
	 * (that is, the stack for the privilege level being called) from the
	 * TSS into the SS and ESP registers and switches to the new stack.
	 */

	//printk("TSR is 0x%08X.\n", sregs.tr.base);
	//printk("TSR limit is 0x%X.\n", sregs.tr.limit);

	kvm_read_guest_virt_system(
			sregs.tr.base,
			&tss_segment,
			sizeof (struct tss_segment_32),
			vcpu,
			&error);

	/*printk("TSS contents:\n");
	nitro_output_hexdump(
			&tss_segment,
			sizeof(struct tss_segment_32) / 16,
			sregs.tr.base);*/
	/* IMPORTANT: SET ALL SELECTORS YOU WISH TO CHANGE BEFORE LOADING ANY SINGLE SEGMENT DESC!! */
	//vcpu->arch.emulate_ctxt.ops->set_segment_selector(/*int_gate.seg_selector*/original_selector, VCPU_SREG_CS, vcpu);

	if (dpl < cpl) {
		printk("INT: Switching to new privilege level %x stack!\n", dpl);
		newESP = *((u32 *)((u8 *)(&tss_segment) + (dpl << 3) + 4));
		newSS = *((u16 *)((u8 *)(&tss_segment) + (dpl << 3) + 4 + 4));

		newSS &= ~SELECTOR_RPL_MASK;
		original_selector &= ~SELECTOR_RPL_MASK;

		printk("New privilege level %x stack segment is 0x%04X\n", dpl, newSS);
		printk("New privilege level %x stack pointer is 0x%08X\n", dpl, newESP);


		vcpu->arch.emulate_ctxt.ops->set_cached_descriptor(&desc_new_ss, VCPU_SREG_SS, vcpu);
		vcpu->arch.emulate_ctxt.ops->set_cached_descriptor(&desc_new_cs, VCPU_SREG_CS, vcpu);
		vcpu->arch.emulate_ctxt.ops->set_segment_selector(newSS, VCPU_SREG_SS, vcpu);
		vcpu->arch.emulate_ctxt.ops->set_segment_selector(original_selector, VCPU_SREG_CS, vcpu);

		if (load_segment_descriptor(&(vcpu->arch.emulate_ctxt), vcpu->arch.emulate_ctxt.ops, newSS, VCPU_SREG_SS) != 0) {
			printk("Failed to load new stack segment!\n");
		}

		/* Write the new stack pointer */
		kvm_register_write(vcpu, VCPU_REGS_RSP, newESP);

		/* Step 3: Pushes the temporarily saved SS, ESP, EFLAGS, CS, and
		 * EIP values for the interrupted procedure’s stack onto the new stack.
		 */

		push(vcpu, ss);
		push(vcpu, esp);
	}

	push(vcpu, eflags);
	push(vcpu, cs);
	push(vcpu, eip);

	/* TODO: Is there any possibility to get the push emulation done
	 * without an ugly helper function?
	 */

	/* Step 4: Pushes an error code on the new stack (if appropriate).
	 *
	 */


	/* TODO: Zero? Nothing at all? */

	/* Step 5: Loads the segment selector for the new code segment and
	 * the new instruction pointer (from the interrupt gate or trap gate)
	 * into the CS and EIP registers, respectively.
	 */

	offset = (((u32)int_gate.offset_high) << 16) | ((u32)int_gate.offset_low);

	printk("Interrupt handler function is at 0x%08X\n", offset);

	/* I had trouble with this one, I don't think that setting the value
	 * of cs.selector is sufficient, because the rest of the cs structure
	 * will be left untouched. This method seems to work, it's the same
	 * code which is used for task switches.
	 */

	kvm_arch_vcpu_ioctl_set_sregs(vcpu,&sregs);
/*
	printk("New code segment is 0x%04X\n", int_gate.seg_selector);

	load_segment_descriptor(&(vcpu->arch.emulate_ctxt), vcpu->arch.emulate_ctxt.ops, int_gate.seg_selector & ~3, VCPU_SREG_CS);
*/
	printk("New code segment is 0x%04X\n", original_selector);


	if (load_segment_descriptor(&(vcpu->arch.emulate_ctxt), vcpu->arch.emulate_ctxt.ops, original_selector, VCPU_SREG_CS)) {
		printk("Failed to load new code segment!\n");
	}

	kvm_arch_vcpu_ioctl_get_regs(vcpu, &regs);
	regs.rip = (__u64)offset;
	kvm_arch_vcpu_ioctl_set_regs(vcpu,&regs);

	/* Step 6: If the call is through an interrupt gate, clears the IF flag
	 * in the EFLAGS register.
	 */

	printk("gateType: 0x%X\n", gateType);
	printk("Updating RFLAGS from 0x%016lX to ", regs.rflags);

	kvm_arch_vcpu_ioctl_get_regs(vcpu, &regs);

	if (dpl == cpl) {
		if (gateType == 0x6 || gateType == 0xE) {
			regs.rflags &= ~(__u64)(bit(9)); // IF
			//vcpu->arch.emulate_ctxt.eflags &= ~bit(9); // IF
			vcpu->arch.emulate_ctxt.eflags &= ~X86_EFLAGS_IF;
		}
	} else {
		regs.rflags &= ~(__u64)(bit(9));
		vcpu->arch.emulate_ctxt.eflags &= ~bit(9); // IF
		sregs.cs.selector &= ~0x3;
		//sregs.cs.selector |= dpl;
		//printk("Updating new code segment privilege level to %x.\n", dpl);
	}

	//regs.rflags &= ~bit(9);
	regs.rflags &= ~bit(8);
	regs.rflags &= ~bit(17);
	regs.rflags &= ~bit(16);
	regs.rflags &= ~bit(14);

	printk("0x%016lX\n", regs.rflags);

	printk("Continuing at CPL %X\n", vcpu->arch.emulate_ctxt.ops->cpl(vcpu));

	//vcpu->arch.emulate_ctxt.eflags &= ~bit(9); // IF
	vcpu->arch.emulate_ctxt.eflags &= ~bit(8); // TF
	vcpu->arch.emulate_ctxt.eflags &= ~bit(17); // VM
	vcpu->arch.emulate_ctxt.eflags &= ~bit(16); // RF
	vcpu->arch.emulate_ctxt.eflags &= ~bit(14); // NT


	kvm_arch_vcpu_ioctl_set_regs(vcpu, &regs);
	/* Step 7: Begins execution of the handler procedure at the new privilege
	 * level.
	 */

	printk("kvm:handle_user_interrupt: int_gate->offset_low=%x int_gate->seg_selector=%x int_gate->flags=%x int_gate->offset_high=%x offset=%x\n",int_gate.offset_low,int_gate.seg_selector,int_gate.flags,int_gate.offset_high,offset);
	//sregs.cs.dpl = 0xff; // kernel privilege HACK
	return 0;
}

int handle_gp(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run){
	int er;
	u8 *stack_contents;


	//printk("kvm:handle_gp: #GP trapped\n");

	//x86_decode_insn(&vcpu->arch.emulate_ctxt);

	if (!vcpu->kvm->nitro_data.running)
		return 1;

	stack_contents = kmalloc(16*16,GFP_KERNEL);

	if (is_sysenter_sysreturn(vcpu)) {//sysenter/sysreturn
		er = emulate_instruction(vcpu, 0, 0, 0);
		if (er != EMULATE_DONE){
			kvm_clear_exception_queue(vcpu);
			kvm_clear_interrupt_queue(vcpu);
			kvm_queue_exception_e(vcpu, GP_VECTOR, kvm_run->ex.error_code);
		}
	}
	else if (vcpu->arch.interrupt.pending && vcpu->arch.interrupt.nr > 31) {//interrupt
		printk("trapped int 0x%X\n", vcpu->arch.interrupt.nr);
		DEBUG_PRINT("begin_int_handling: EIP is now 0x%08lX.\n", kvm_register_read(vcpu, VCPU_REGS_RIP))
		if (is_int(vcpu)) {
			er = emulate_instruction(vcpu, 0, 0, 0);
		} else {
			DEBUG_PRINT("Asynchronous interrupt detected.\n")
			er = handle_asynchronous_interrupt(vcpu);
		}
		kvm_clear_exception_queue(vcpu);
		kvm_clear_interrupt_queue(vcpu);
		if (er != EMULATE_DONE) {
			kvm_queue_exception_e(vcpu, GP_VECTOR, kvm_run->ex.error_code);
		}
		DEBUG_PRINT("Emulation returned %X.\n", er)
		/*printk("Stack contents:\n");
		stack_contents = kmalloc(16 * 16, 1);
		kvm_read_guest_virt_system(kvm_register_read(vcpu, VCPU_REGS_RSP) - (8 * 16),stack_contents,16 * 16,vcpu,&er);
		nitro_output_hexdump(stack_contents, 16, kvm_register_read(vcpu, VCPU_REGS_RSP) - (8 * 16));
		kfree(stack_contents);*/
		DEBUG_PRINT("end_int_handling: EIP is now 0x%08lX.\n", kvm_register_read(vcpu, VCPU_REGS_RIP))
	}
	else if (vcpu->arch.interrupt.pending) {
		kvm_clear_exception_queue(vcpu);
		kvm_clear_interrupt_queue(vcpu);
		kvm_queue_interrupt(vcpu,vcpu->arch.interrupt.nr,true);
	}
	else {
		printk("kvm:handle_gp: natural #GP trapped, EC=%u\n",kvm_run->ex.error_code);
		printk("EIP is now 0x%08lX.\n", kvm_register_read(vcpu, VCPU_REGS_RIP));
		kvm_clear_exception_queue(vcpu);
		kvm_clear_interrupt_queue(vcpu);
		kvm_queue_exception_e(vcpu, GP_VECTOR, kvm_run->ex.error_code);
	}
	kfree(stack_contents);
	return 1;
}
EXPORT_SYMBOL_GPL(handle_gp);


int syscall_hook(char prefix, struct x86_emulate_ctxt *ctxt){
	if(ctxt->vcpu->kvm->nitro_data.running){
		print_trace_proxy(prefix,ctxt->vcpu);
		return 0;
	}
	return 1;
}
