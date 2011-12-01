#include "htfu.h"

int htfu_init(struct kvm *kvm){
	kvm->htfu_data.test = 1;
}

int htfu_exit(struct kvm *kvm){
	kvm->htfu_data.test = 0;
}

int htfu_block_int(struct kvm *kvm, uint32_t interrupt){
	printk(KERN_INFO "kvm:htfu: htfu_block_int %u\n",interrupt);

	return 0;
}

int htfu_unblock_int(struct kvm *kvm, uint32_t interrupt){
	printk(KERN_INFO "kvm:htfu: htfu_unblock_int %u\n",interrupt);

	return 0;
}

int htfu_warn_int(struct kvm *kvm, uint32_t interrupt){
	printk(KERN_INFO "kvm:htfu: htfu_warn_int %u\n",interrupt);

	return 0;
}

int htfu_unwarn_int(struct kvm *kvm, uint32_t interrupt){
	printk(KERN_INFO "kvm:htfu: htfu_unwarn_int %u\n",interrupt);

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


