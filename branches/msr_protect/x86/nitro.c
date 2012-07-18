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
//#include "nitro_output.h"
#include "nitro.h"
#include "syscall_monitor.h"
#include "tss.h"

#define DUM_SEG_SELECT 0xFFFF


extern int kvm_write_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);
extern int kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);
extern int is_sysenter_sysreturn(struct kvm_vcpu *vcpu);
extern int is_int(struct kvm_vcpu *vcpu);

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
	//kvm->nitro_data.pae = 0;
	kvm->nitro_data.mode = UNDEF;
	kvm->nitro_data.idt_entry_size = 0;
	kvm->nitro_data.no_int = 0;
	kvm->nitro_data.syscall_reg = VCPU_REGS_RAX;
	//kvm->nitro_data.singlestep = kmalloc(sizeof(struct sctrace_singlestep), GFP_KERNEL);
	kvm->nitro_data.singlestep.singlestep = 0;
	kvm->nitro_data.singlestep.need_exit_to_qemu = 0;
	//kvm->nitro_data.singlestep->exit_reason = 0;
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

	//printk("idt_index = %ld, syscall_reg = %s\n", (long int) idt_index, syscall_reg);

	if(kvm->nitro_data.running){
		printk("kvm:start_syscall_trace: WARNING: nitro is already running, start will be aborted.\n");
		return 1;
	}



	vcpu=kvm_get_vcpu(kvm,0);

	if(!is_protmode(vcpu)){
		printk("kvm:start_syscall_trace: ERROR: guest is running in real mode, nitro can not function.\n");
		return 3;
	}

	kvm->nitro_data.mode = PROT;
	kvm->nitro_data.idt_entry_size=8;

	if(is_pae(vcpu)){
		kvm->nitro_data.mode = PAE;
		printk("kvm:start_syscall_trace: system running in PAE mode\n");
	}
	if(is_long_mode(vcpu)){
		kvm->nitro_data.mode = LONG;
		kvm->nitro_data.idt_entry_size=16;
		printk("kvm:start_syscall_trace: system running in long mode (x86_64)\n");
	}


/*
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
	*/

	// check if idt_index is an intelligent value
	//printk("check if idt index is an intelligent value\n");
	vcpu_load(vcpu);
	kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
	vcpu_put(vcpu);

	if(idt_index == 0){
		kvm->nitro_data.no_int = 1;
	}
	else if(idt_index<32 || idt_index>(sregs.idt.limit+1)/kvm->nitro_data.idt_entry_size){
		printk("kvm:start_syscall_trace: ERROR: invalid idt_index passed, start will be aborted.\n");
		return 2;
	}
	else{
		kvm->nitro_data.idt_int_offset = (u8) idt_index;
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
	//printk("kvm:start_syscall_trace: starting syscall trace with syscall_reg = %d, name='%s'\n", kvm->nitro_data.syscall_reg, syscall_reg);

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
		kvm_x86_ops->enable_dte(vcpu);
		printk("kvm:start_syscall_trace: cpu%d: descriptor table trap set\n",i);
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
	
	/* Set MSR trap */
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->set_msr_trap(vcpu);
		vcpu_put(vcpu);
	}
	
#ifdef SHADOW_IDT
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
			sregs.idt.limit=32*kvm->nitro_data.idt_entry_size-1;
			kvm_arch_vcpu_ioctl_set_sregs(vcpu,&sregs);
		}
	}
#else

	//old code to cause int x to cause #GP/#NP
	//i=0;

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

				//printk("kvm:start_syscall_trace: idt size: %d\n", (unsigned int)(sregs.idt.limit + 1));

				kvm->nitro_data.idt_replaced_offset = 0x81;

				//for(j=32;j<(sregs.idt.limit + 1)/kvm->nitro_data.idt_entry_size;j++){
				for(j=((sregs.idt.limit + 1)/kvm->nitro_data.idt_entry_size) - 1; j>=32;j--){
					//printk("kvm:start_syscall_trace: checking IDT gate 0x%hX, p=0x%X, seg. sel.=%hu\n",j,(idt[(j*kvm->nitro_data.idt_entry_size)+5] & 0x80),*((u16*) (idt +  (INT_OFFSET*kvm->nitro_data.idt_entry_size) + 2)));
					if((idt[(j*kvm->nitro_data.idt_entry_size)+5] & 0x80) == 0){
						kvm->nitro_data.idt_replaced_offset = (u8)j;
						break;
					}
				}

				printk("kvm:start_syscall_trace: using empty gate 0x%hX\n",kvm->nitro_data.idt_replaced_offset);

				memcpy(idt + (kvm->nitro_data.idt_replaced_offset*kvm->nitro_data.idt_entry_size), idt + (kvm->nitro_data.idt_int_offset*kvm->nitro_data.idt_entry_size), kvm->nitro_data.idt_entry_size);

				*((u16*) (idt +  (kvm->nitro_data.idt_int_offset*kvm->nitro_data.idt_entry_size) + 2)) = DUM_SEG_SELECT;  //set selector
				//idt[(INT_OFFSET*kvm->nitro_data.idt_entry_size) + 5] &= 0x7F;  //unset present bit

				//kvm_write_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit));
				kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);

				kfree(idt);
			}
		}

	}
#endif




	/*
	 * Proc Output
	output_init = nitro_output_init();

	if (output_init != 0) {
		stop_syscall_trace(kvm);
		return 1;
	}
	 */

	//kfree(kvm->nitro_data.singlestep);

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

	//nitro_output_exit();
	//sctrace_kvm_init(kvm);

	kvm->nitro_data.running = 0;

	//code to unset #GP trap
	i=0;
	while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		vcpu_load(kvm->vcpus[i]);
		kvm_x86_ops->unset_gp_trap(kvm->vcpus[i]);
		printk("kvm:start_syscall_trace: cpu%d: GP trap unset\n",i);
		kvm_x86_ops->disable_dte(kvm->vcpus[i]);
		printk("kvm:start_syscall_trace: cpu%d: descriptor table trap unset\n",i);
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

	/* Unset MSR trap */
	i=0;
	while(kvm->vcpus[i] && i<KVM_MAX_VCPUS){
		vcpu_load(kvm->vcpus[i]);
		kvm_x86_ops->unset_msr_trap(kvm->vcpus[i]);
		vcpu_put(kvm->vcpus[i]);
		i++;
	}
	
#ifdef SHADOW_IDT

#else

	//old code to cause int x not to cause #GP/#NP

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

				memcpy(idt + (kvm->nitro_data.idt_int_offset*kvm->nitro_data.idt_entry_size), idt + (kvm->nitro_data.idt_replaced_offset*kvm->nitro_data.idt_entry_size), kvm->nitro_data.idt_entry_size);

				//kvm_write_guest(kvm,kvm->vcpus[i]->arch.mmu.gva_to_gpa(kvm->vcpus[i],sregs.idt.base),idt,(unsigned long)(sregs.idt.limit));
				kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),kvm->vcpus[i],&error);

				kfree(idt);
			}

			i++;
		}

	}
#endif


	return 0;
}

void get_process_hardware_id(struct kvm_vcpu *vcpu, unsigned long *cr3, u32 *verifier, unsigned long *pde){

	unsigned long dir_base;
	u32 i;
	u32 pde_32;

	*verifier = 0;

	*cr3 = vcpu->arch.cr3;

	if (vcpu->kvm->nitro_data.mode == PAE){//PAE
		dir_base = (*cr3) & 0xFFFFFFFFFFFFFFE0;	//see section 4.3 in intel manual

		for (i=0;i<4*8;i+=8){
			kvm_read_guest(vcpu->kvm, dir_base+i, pde, 8);
			//printk("kvm:handle_gp: kvm_read_guest_virt_system error: %u\n",error);
			if(((*pde) & PT_PRESENT_MASK)){//  &&  !(pde & PT_WRITABLE_MASK)){
				*verifier=i;
				goto FOUND;
			}
		}
	}
	else if (vcpu->kvm->nitro_data.mode == LONG){//IA-32E
		dir_base = (*cr3) & 0x000FFFFFFFFFF000;	//see section 4.3 in intel manual

		for (i=0;i<512*8;i+=8){
			kvm_read_guest(vcpu->kvm, dir_base+i, pde, 8);
			//printk("kvm:handle_gp: kvm_read_guest_virt_system error: %u\n",error);
			if(((*pde) & PT_PRESENT_MASK)){//  &&  !(pde & PT_WRITABLE_MASK)){
				*verifier=i;
				goto FOUND;
			}
		}
	}
	else{//32-bit Protected
		dir_base = (*cr3) & 0xFFFFFFFFFFFFF000;  	//see section 4.3 in intel manual

		for (i=0;i<1024*4;i+=4){
			kvm_read_guest(vcpu->kvm, dir_base+i, &pde_32, 4);
			//printk("kvm:handle_gp: kvm_read_guest_virt_system error: %u\n",error);
			if((pde_32 & PT_PRESENT_MASK)){//  &&  !(pde & PT_WRITABLE_MASK)){
				*verifier=i;
				*pde = (unsigned long)pde_32;
				goto FOUND;
			}
		}
	}
	*pde=0;

FOUND:
	/* end copy and paste */
	return;
}

int sctrace_print_trace(char prefix, struct kvm_vcpu *vcpu){
	unsigned long cr3, pde, screg;
	u32 verifier;
	char *sctrace_line;

	screg = kvm_register_read(vcpu, vcpu->kvm->nitro_data.syscall_reg);

	get_process_hardware_id(vcpu, &cr3, &verifier, &pde);

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

	vcpu->kvm->nitro_data.singlestep.need_exit_to_qemu = 1;
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

int handle_gp(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run){
	int er;
	struct kvm_sregs sregs;

	//printk("kvm:handle_gp: #GP trapped\n");

	if(!vcpu->kvm->nitro_data.running)
		return 1;

	if(is_sysenter_sysreturn(vcpu)){//sysenter/sysreturn
		er = emulate_instruction(vcpu, 0, 0, 0);
		if (er != EMULATE_DONE){
			kvm_clear_exception_queue(vcpu);
			kvm_clear_interrupt_queue(vcpu);
			kvm_queue_exception_e(vcpu,GP_VECTOR,kvm_run->ex.error_code);
		}
	}
#ifdef SHADOW_IDT
	else if(vcpu->arch.interrupt.pending && vcpu->arch.interrupt.nr > 31){//int shadow_idt
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
	}
#else
	else if(((DUM_SEG_SELECT & 0xFFF8) == (kvm_run->ex.error_code & 0xFFF8)) && !vcpu->kvm->nitro_data.no_int){ //int no shadow_idt
																		 //check if its our expected error code for int handling
																	     //(disregard bottom 3 bits as these are status)

		print_trace_proxy('i',vcpu);

		kvm_clear_exception_queue(vcpu);
		kvm_clear_interrupt_queue(vcpu);
		kvm_queue_interrupt(vcpu,vcpu->kvm->nitro_data.idt_replaced_offset,true);
	}
#endif
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
	if(ctxt->vcpu->kvm->nitro_data.running){
		print_trace_proxy(prefix,ctxt->vcpu);
		return 0;
	}
	return 1;
}

int nitro_check_singlestep(struct kvm_vcpu *vcpu){
	if(vcpu->kvm->nitro_data.singlestep.singlestep && vcpu->kvm->nitro_data.singlestep.need_exit_to_qemu){
		vcpu->run->exit_reason = 42; /* nitro singlestepping mode */
		vcpu->kvm->nitro_data.singlestep.need_exit_to_qemu = 0;
		return 1;
	}else{
		return 0;
	}

}
EXPORT_SYMBOL_GPL(nitro_check_singlestep);



int start_syscall_singlestep(struct kvm *kvm){
	kvm->nitro_data.singlestep.singlestep = 1;
	kvm->nitro_data.singlestep.need_exit_to_qemu = 0;
	return 0;
}

int stop_syscall_singlestep(struct kvm *kvm){
	kvm->nitro_data.singlestep.singlestep = 0;
	kvm->nitro_data.singlestep.need_exit_to_qemu = 0;
	return 0;
}
