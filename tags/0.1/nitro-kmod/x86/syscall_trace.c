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

#define DUM_SEG_SELECT 0xFFFF

extern int kvm_write_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);
extern int kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);
extern int is_sysenter_sysreturn(struct kvm_vcpu *vcpu);

int sctrace_mod_init(void){
	return 0;

}

int sctrace_mod_exit(void){
	return 0;
	//nitro_output_exit();
}

int sctrace_kvm_init(struct kvm *kvm){
	kvm->sctd.running = 0;
	kvm->sctd.id[0] = '\0';
	kvm->sctd.sysenter_cs_val = 0;
	kvm->sctd.efer_val = 0;
	kvm->sctd.idt_int_offset = 0;
	kvm->sctd.idt_replaced_offset = 0;
	kvm->sctd.pae = 0;
	kvm->sctd.no_int = 0;
	kvm->sctd.syscall_reg = VCPU_REGS_RAX;
	return 0;
}

int start_syscall_trace(struct kvm *kvm,int64_t idt_index,char* syscall_reg,enum nitro_mode nitro_mode){
	int i, output_init;
	u16 j;
	struct kvm_sregs sregs;
	u8 *idt;
	u64 idt_base,efer;
	u32 error;
	unsigned long cr4,cr0;
	struct kvm_vcpu *vcpu;

	printk("idt_index = %ld, syscall_reg = %s\n", (long int) idt_index, syscall_reg);

	if(kvm->sctd.running){
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
		kvm->sctd.no_int = 1;
	}
	else if(idt_index<32 || idt_index>(sregs.idt.limit+1)/8){
		printk("kvm:start_syscall_trace: ERROR: invalid idt_index passed, start will be aborted.\n");
		return 2;
	}
	else{
		kvm->sctd.idt_int_offset = (u8) idt_index;
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
			kvm->sctd.pae = 2;
			printk("kvm:start_syscall_trace: starting syscall trace with IA32-E on.\n");
		}
		else{
			kvm->sctd.pae = 1;
			printk("kvm:start_syscall_trace: starting syscall trace with PAE on.\n");
		}
	}
	else{
		kvm->sctd.pae = 0;
		printk("kvm:start_syscall_trace: starting syscall trace with PAE/IA32-E off.\n");
	}

	// set syscall_reg
	printk("set syscall_reg\n");
	if (strcmp(syscall_reg, "rbx") == 0) {
		kvm->sctd.syscall_reg = VCPU_REGS_RBX;
	}
	else if (strcmp(syscall_reg, "rcx") == 0) {
		kvm->sctd.syscall_reg = VCPU_REGS_RCX;
	}
	else if (strcmp(syscall_reg, "rdx") == 0) {
		kvm->sctd.syscall_reg = VCPU_REGS_RDX;
	}
	else {
		kvm->sctd.syscall_reg = VCPU_REGS_RAX;
	}
	printk("kvm:start_syscall_trace: starting syscall trace with syscall_reg = %d, name='%s'\n", kvm->sctd.syscall_reg, syscall_reg);

	if (nitro_mode == NITRO_MODE_TRACE) {
		kvm->sctd.running = 1;
	}
	else if (nitro_mode == NITRO_MODE_MONITORING) {
		kvm->sctd.running = 2;
	}

	//code to set #GP trap
	//i=0;
	//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->set_gp_trap(vcpu);
		printk("kvm:start_syscall_trace: cpu%d: GP trap set\n",i);
		vcpu_put(vcpu);

		i++;
	}


	//code to cause sysenter to cause #GP
	//i=0;
	//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->get_msr(vcpu, MSR_IA32_SYSENTER_CS, &(kvm->sctd.sysenter_cs_val));
		kvm_x86_ops->set_msr(vcpu, MSR_IA32_SYSENTER_CS, 0);
		vcpu_put(vcpu);

		i++;
	}

	//code to cause syscall to cause #UD (64 bit ubuntu)
	//i=0;
	//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_get_msr_common(vcpu, MSR_EFER, &(kvm->sctd.efer_val));
		kvm_set_msr_common(vcpu, MSR_EFER, kvm->sctd.efer_val & ~EFER_SCE);
		vcpu_put(vcpu);

		i++;
	}


	//code to cause int x to cause #GP/#NP
	//i=0;
	idt_base = 0;

	if(!kvm->sctd.no_int){

		//while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		kvm_for_each_vcpu(i, vcpu, kvm){
			kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);

			if(sregs.idt.base != idt_base){
				idt_base = sregs.idt.base;

				idt = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
				memset(idt,0,sregs.idt.limit + 1);
				//kvm_read_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit + 1));
				kvm_read_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);


				kvm->sctd.idt_replaced_offset = 0x81;

				//for(j=32;j<(sregs.idt.limit + 1)/8;j++){
				for(j=((sregs.idt.limit + 1)/8) - 1; j>=32;j--){
					//printk("kvm:start_syscall_trace: checking IDT gate 0x%hX, p=0x%X, seg. sel.=%hu\n",j,(idt[(j*8)+5] & 0x80),*((u16*) (idt +  (INT_OFFSET*8) + 2)));
					if((idt[(j*8)+5] & 0x80) == 0){
						kvm->sctd.idt_replaced_offset = (u8)j;
						break;
					}
				}

				printk("kvm:start_syscall_trace: using empty gate 0x%hX\n",kvm->sctd.idt_replaced_offset);

				memcpy(idt + (kvm->sctd.idt_replaced_offset*8), idt + (kvm->sctd.idt_int_offset*8), 8);

				*((u16*) (idt +  (kvm->sctd.idt_int_offset*8) + 2)) = DUM_SEG_SELECT;  //set selector
				//idt[(INT_OFFSET*8) + 5] &= 0x7F;  //unset present bit

				//kvm_write_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit));
				kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);

				kfree(idt);
			}

			i++;
		}

	}
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

int stop_syscall_trace(struct kvm *kvm){
	int i;
	struct kvm_sregs sregs;
	u8 *idt;
	u64 idt_base;
	u32 error;

	if(!kvm->sctd.running){
		printk("kvm:stop_syscall_trace: WARNING: nitro is not started, stop will be aborted.\n");
		return 1;
	}

	nitro_output_exit();
	sctrace_kvm_init(kvm);

	kvm->sctd.running = 0;

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
		kvm_x86_ops->set_msr(kvm->vcpus[i], MSR_IA32_SYSENTER_CS, kvm->sctd.sysenter_cs_val);
		vcpu_put(kvm->vcpus[i]);

		i++;
	}

	//code to cause syscall not to cause #UD (64 bit ubuntu)
	i=0;
	while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		vcpu_load(kvm->vcpus[i]);
		kvm_set_msr_common(kvm->vcpus[i], MSR_EFER, kvm->sctd.efer_val);
		vcpu_put(kvm->vcpus[i]);

		i++;
	}


	//code to cause int x not to cause #GP/#NP
	i=0;
	idt_base = 0;

	if(!kvm->sctd.no_int){

		while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
			kvm_arch_vcpu_ioctl_get_sregs(kvm->vcpus[i],&sregs);

			if(sregs.idt.base != idt_base){
				idt_base = sregs.idt.base;

				idt = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
				memset(idt,0,sregs.idt.limit + 1);
				//kvm_read_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit + 1));
				kvm_read_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),kvm->vcpus[i],&error);

				memcpy(idt + (kvm->sctd.idt_int_offset*8), idt + (kvm->sctd.idt_replaced_offset*8), 8);

				//kvm_write_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit));
				kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),kvm->vcpus[i],&error);

				kfree(idt);
			}

			i++;
		}

	}

	return 0;
}

int sctrace_print_trace(char prefix, struct kvm_vcpu *vcpu){
	unsigned long cr3, dir_base, pde, screg;
	u32 i;
	u32 verifier=0, pde_32;
	char *sctrace_line;

	screg = kvm_register_read(vcpu, vcpu->kvm->sctd.syscall_reg);
	cr3 = vcpu->arch.cr3;
	//pdptr0 = kvm_pdptr_read(vcpu,0);

	if (vcpu->kvm->sctd.pae == 1){//PAE
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
	else if (vcpu->kvm->sctd.pae == 2){//IA-32E
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

	snprintf(sctrace_line, 255, "kvm:syscall trace(%c): %s:0x%lX:%u:0x%lX %lu\n", prefix, vcpu->kvm->sctd.id, cr3, verifier, pde, screg);
	nitro_output_append(sctrace_line, 255);
*/

printk("kvm:syscall trace(%c): %s:0x%lX:%u:0x%lX %lu\n", prefix, vcpu->kvm->sctd.id, cr3, verifier, pde, screg);

	return 0;
}

int print_trace_proxy(char prefix, struct kvm_vcpu *vcpu){
	int ret;

	ret = 0;
	if (vcpu->kvm->sctd.running == 1) {
		ret = sctrace_print_trace(prefix, vcpu);
	}
	else if (vcpu->kvm->sctd.running == 2) {
		ret = scmon_print_trace(prefix, vcpu);
	}

	return ret;
}

int handle_gp(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run){
	int er;

	if(!vcpu->kvm->sctd.running)
		return 1;

	if(is_sysenter_sysreturn(vcpu)){//sysenter/sysreturn
		er = emulate_instruction(vcpu, 0, 0, 0);
		if (er != EMULATE_DONE){
			kvm_clear_exception_queue(vcpu);
			kvm_clear_interrupt_queue(vcpu);
			kvm_queue_exception_e(vcpu,GP_VECTOR,kvm_run->ex.error_code);
		}
	}
	else if(((DUM_SEG_SELECT & 0xFFF8) == (kvm_run->ex.error_code & 0xFFF8)) && !vcpu->kvm->sctd.no_int){  //check if its our expected error code for int handling
																	     //(disregard bottom 3 bits as these are status)

		print_trace_proxy('i',vcpu);

		kvm_clear_exception_queue(vcpu);
		kvm_clear_interrupt_queue(vcpu);
		kvm_queue_interrupt(vcpu,vcpu->kvm->sctd.idt_replaced_offset,true);
	}
	else{
		//printk("kvm:handle_gp: natural #GP trapped, EC=%u\n",kvm_run->ex.error_code);
		kvm_clear_exception_queue(vcpu);
		kvm_clear_interrupt_queue(vcpu);
		kvm_queue_exception_e(vcpu,GP_VECTOR,kvm_run->ex.error_code);
	}
	return 1;
}
EXPORT_SYMBOL_GPL(handle_gp);


int syscall_hook(char prefix, struct x86_emulate_ctxt *ctxt){
	if(ctxt->vcpu->kvm->sctd.running){
		print_trace_proxy(prefix,ctxt->vcpu);
		return 0;
	}
	return 1;
}
