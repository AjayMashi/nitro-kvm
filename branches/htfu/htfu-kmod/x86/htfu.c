
#include "htfu.h"



int htfu_block_int(uint32_t interrupt){
	printk(KERN_INFO "kvm:htfu: htfu_block_int %u\n", interrupt);
}

int htfu_unblock_int(uint32_t interrupt){
	printk(KERN_INFO "kvm:htfu: htfu_unblock_int %u\n", interrupt);
}

int htfu_warn_int(uint32_t interrupt){
	printk(KERN_INFO "kvm:htfu: htfu_warn_int %u\n", interrupt);
}

int htfu_unwarn_int(uint32_t interrupt){
	printk(KERN_INFO "kvm:htfu: htfu_unwarn_int %u\n", interrupt);
}

int htfu_block_sc(uint32_t sc_nr){
	printk(KERN_INFO "kvm:htfu: htfu_block_sc %u\n", sc_nr);
}

int htfu_unblock_sc(uint32_t sc_nr){
	printk(KERN_INFO "kvm:htfu: htfu_unblock_sc %u\n", sc_nr);
}
