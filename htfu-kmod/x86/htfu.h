#ifndef HTFU_H_
#define HTFU_H_

#include "htfu-common.h"

#include <linux/kvm_host.h>

int htfu_init(struct kvm *kvm);
int htfu_exit(struct kvm *kvm);

int htfu_block_int(struct kvm *kvm, uint32_t interrupt);
int htfu_unblock_int(struct kvm *kvm, uint32_t interrupt);
int htfu_warn_int(struct kvm *kvm, uint32_t interrupt);
int htfu_unwarn_int(struct kvm *kvm, uint32_t interrupt);
int htfu_block_sc(struct kvm *kvm, uint32_t sc_nr);
int htfu_unblock_sc(struct kvm *kvm, uint32_t sc_nr);

#endif




