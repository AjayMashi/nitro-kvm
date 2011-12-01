#include "htfu.h"
#include "x86.h"

#ifdef HTFU_64BIT
int idt_entry_size = 16; /* 8 if 32bit, 16 if 64bit */
#else
int idt_entry_size = 8;
#endif


extern int kvm_write_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);
extern int kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);

int htfu_init(struct kvm *kvm){
	kvm->htfu_data.hardened = 0;
	kvm->htfu_data.idt_offset = 0;
	kvm->htfu_data.dummy_idt_offset = 0;
	kvm->htfu_data.sysenter_cs_val = 0;
	kvm->htfu_data.efer_val = 0;

	return 0;
}

int htfu_exit(struct kvm *kvm){

	return 0;
}

int htfu_harden(struct kvm *kvm, uint32_t interrupt){
	int i,j;
	struct kvm_sregs sregs;
	struct kvm_vcpu *vcpu;
	u64 idt_base;
	u8 *idt;
	u32 error;

	if(kvm->htfu_data.hardened != 0){
		printk(KERN_INFO "kvm:htfu: System is already hardened.\n");
		return 1;
	}

	printk(KERN_INFO "kvm:htfu: Hardening system with syscall interrupt %u...\n",interrupt);

	vcpu=kvm_get_vcpu(kvm,0);

	vcpu_load(vcpu);
	kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
	vcpu_put(vcpu);

	if(interrupt>(sregs.idt.limit+1)/idt_entry_size){
		printk("kvm:htfu: ERROR: invalid interrupt passed, cannot block.\n");
		return 2;
	}


	//set #GP trap
	kvm->htfu_data.hardened = 1;
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->update_trap_exceptions(vcpu);
		printk("kvm:htfu: cpu%d: GP trap set\n",i);
		vcpu_put(vcpu);
	}


	//code to cause sysenter to cause #GP
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->get_msr(vcpu, MSR_IA32_SYSENTER_CS, &(kvm->htfu_data.sysenter_cs_val));
		kvm_x86_ops->set_msr(vcpu, MSR_IA32_SYSENTER_CS, 0);
		vcpu_put(vcpu);
	}

	//code to cause syscall to cause #UD (64 bit ubuntu)
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_get_msr_common(vcpu, MSR_EFER, &(kvm->htfu_data.efer_val));
		kvm_set_msr_common(vcpu, MSR_EFER, kvm->htfu_data.efer_val & ~EFER_SCE);
		vcpu_put(vcpu);
	}

	//code to cause int to cause #GP
	kvm->htfu_data.idt_offset=interrupt;
	idt_base = 0;

	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
		vcpu_put(vcpu);

		if(sregs.idt.base != idt_base){
			idt_base = sregs.idt.base;

			idt = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
			memset(idt,0,sregs.idt.limit + 1);

			kvm_read_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);

			kvm->htfu_data.dummy_idt_offset = 0x81;

			for(j=((sregs.idt.limit + 1)/idt_entry_size) - 1; j>=32;j--){
				if((idt[(j*idt_entry_size)+5] & 0x80) == 0){
					kvm->htfu_data.dummy_idt_offset = (u8)j;
					break;
				}
			}

			printk("kvm:htfu: using empty gate 0x%hX\n",kvm->htfu_data.dummy_idt_offset);

			memcpy(idt + (kvm->htfu_data.dummy_idt_offset*idt_entry_size), idt + (kvm->htfu_data.idt_offset*idt_entry_size), idt_entry_size);



			kvm->htfu_data.int_selector=*((u16*) (idt +  (kvm->htfu_data.idt_offset*idt_entry_size) + 2)); //save selector
			*((u16*) (idt +  (kvm->htfu_data.idt_offset*idt_entry_size) + 2)) = 0; //mangle selector

			//idt[(kvm->htfu_data.idt_offset*idt_entry_size) + 5] &= 0x7F;  //unset present bit

			kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);

			kfree(idt);
		}
	}
	printk(KERN_INFO "kvm:htfu: done.\n");

	return 0;
}

int htfu_unharden(struct kvm *kvm){
	int i;
	struct kvm_sregs sregs;
	struct kvm_vcpu *vcpu;
	u64 idt_base;
	u8 *idt;
	u32 error;

	if(kvm->htfu_data.hardened == 0){
		printk(KERN_INFO "kvm:htfu: System is not hardened.\n");
		return 1;
	}

	printk(KERN_INFO "kvm:htfu: Unhardening system...\n");

	//unset #GP trap
	kvm->htfu_data.hardened = 0;
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->update_trap_exceptions(vcpu);
		vcpu_put(vcpu);
	}


	//code to uncause sysenter to cause #GP
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_x86_ops->set_msr(vcpu, MSR_IA32_SYSENTER_CS, kvm->htfu_data.sysenter_cs_val);
		vcpu_put(vcpu);
	}

	//code to uncause syscall to cause #UD (64 bit ubuntu)
	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_set_msr_common(vcpu, MSR_EFER, kvm->htfu_data.efer_val);
		vcpu_put(vcpu);
	}

	//code to cause int to cause #GP
	idt_base = 0;

	kvm_for_each_vcpu(i, vcpu, kvm){
		vcpu_load(vcpu);
		kvm_arch_vcpu_ioctl_get_sregs(vcpu,&sregs);
		vcpu_put(vcpu);

		if(sregs.idt.base != idt_base){
			idt_base = sregs.idt.base;

			idt = kmalloc(sregs.idt.limit + 1,GFP_KERNEL);
			memset(idt,0,sregs.idt.limit + 1);

			kvm_read_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);


			memcpy(idt + (kvm->htfu_data.idt_offset*idt_entry_size), idt + (kvm->htfu_data.dummy_idt_offset*idt_entry_size), idt_entry_size);


			kvm_write_guest_virt_system(sregs.idt.base,idt,(unsigned int)(sregs.idt.limit + 1),vcpu,&error);

			kfree(idt);
		}
	}
	printk(KERN_INFO "kvm:htfu: done.\n");

	return 0;
}

int htfu_warn_int(struct kvm *kvm){
	printk(KERN_INFO "kvm:htfu: htfu_warn_int \n");

	return 0;
}

int htfu_unwarn_int(struct kvm *kvm){
	printk(KERN_INFO "kvm:htfu: htfu_unwarn_int \n");

	return 0;
}

int htfu_block_sc(struct kvm *kvm, uint32_t sc_nr){
	printk(KERN_INFO "kvm:htfu: htfu_block_sc %u\n",sc_nr);

	return 0;
}

int htfu_unblock_sc(struct kvm *kvm, uint32_t sc_nr){
	printk(KERN_INFO "kvm:htfu: htfu_unblock_sc %u\n",sc_nr);

	return 0;
}

bool do_syscall(struct kvm_vcpu *vcpu){
	unsigned long sc_nr = kvm_register_read(vcpu, VCPU_REGS_RAX);

	if(sc_nr == 127 || sc_nr == 128){
		printk(KERN_INFO "kvm:htfu: Blocking system call %lu\n",sc_nr);
		return false;
	}
	else
		return true;
}

void htfu_handle_gp(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run){

	if(is_sysenter(vcpu)){
		if(do_syscall(vcpu)){
			if (emulate_instruction(vcpu, 0, 0, 0) != EMULATE_DONE){
				kvm_clear_exception_queue(vcpu);
				kvm_clear_interrupt_queue(vcpu);
				kvm_queue_exception_e(vcpu,GP_VECTOR,kvm_run->ex.error_code);
			}
		}
		else{
			kvm_queue_exception(vcpu, UD_VECTOR);
		}
	}
	else if(is_sysexit(vcpu)){
		if (emulate_instruction(vcpu, 0, 0, 0) != EMULATE_DONE){
			kvm_clear_exception_queue(vcpu);
			kvm_clear_interrupt_queue(vcpu);
			kvm_queue_exception_e(vcpu,GP_VECTOR,kvm_run->ex.error_code);
		}

	}
	else if(is_int(vcpu)){
		printk(KERN_INFO "int trapped %lu\n",kvm_register_read(vcpu, VCPU_REGS_RAX));
		if(do_syscall(vcpu)){
			kvm_clear_exception_queue(vcpu);
			kvm_clear_interrupt_queue(vcpu);
			kvm_queue_interrupt(vcpu,vcpu->kvm->htfu_data.dummy_idt_offset,true);
		}
		else{
			kvm_queue_exception(vcpu, UD_VECTOR);
		}
	}
	else{
		kvm_clear_exception_queue(vcpu);
		kvm_clear_interrupt_queue(vcpu);
		kvm_queue_exception_e(vcpu,GP_VECTOR,kvm_run->ex.error_code);
	}
}
EXPORT_SYMBOL_GPL(htfu_handle_gp);

void htfu_handle_syscall(struct kvm_vcpu *vcpu){
	if (emulate_instruction(vcpu, 0, 0, EMULTYPE_TRAP_UD) != EMULATE_DONE)
		kvm_queue_exception(vcpu, UD_VECTOR);
}
EXPORT_SYMBOL_GPL(htfu_handle_syscall);

//kvm_queue_exception(vcpu, UD_VECTOR);
