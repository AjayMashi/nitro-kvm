#ifndef HTFU_H_
#define HTFU_H_

//#define HTFU_64BIT

#include "htfu-common.h"

#include <linux/kvm_host.h>

int htfu_init(struct kvm *kvm);
int htfu_exit(struct kvm *kvm);

int htfu_harden(struct kvm *kvm, uint32_t interrupt);
int htfu_unharden(struct kvm *kvm);
int htfu_warn_int(struct kvm *kvm);
int htfu_unwarn_int(struct kvm *kvm);
int htfu_block_sc(struct kvm *kvm, uint32_t sc_nr);
int htfu_unblock_sc(struct kvm *kvm, uint32_t sc_nr);

void htfu_handle_gp(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run);
void htfu_handle_syscall(struct kvm_vcpu *vcpu);

#endif




