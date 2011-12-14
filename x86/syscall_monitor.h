/*
 * sctrace_output.h
 *
 *  Created on: 22.12.2010
 *      Author: fenma
 */

#ifndef SYSCALL_MONITOR_H_
#define SYSCALL_MONITOR_H_

#include <linux/kvm_host.h>

extern struct scmon_rule *scmon_first_rule;

enum scmon_action {
	SCMON_ACTION_HEX,
	SCMON_ACTION_INT,
	SCMON_ACTION_UINT,
	SCMON_ACTION_DEREFHEX,
	SCMON_ACTION_DEREFINT,
	SCMON_ACTION_DEREFUINT,
	SCMON_ACTION_DEREFSTR
};

struct scmon_rule {
	enum kvm_reg cond_reg;
	unsigned long int cond_val;
	enum kvm_reg action_reg;
	int64_t action_reg_offset;
	enum scmon_action action;
	struct scmon_rule *next;
	struct scmon_rule *prev;
};

int scmon_flush_rules(void);
int scmon_add_rule(enum kvm_reg cond_reg, unsigned long int cond_val, enum kvm_reg action_reg, int64_t action_reg_offset, enum scmon_action action);
int scmon_delete_rule(unsigned int id);
//int scmon_start(struct kvm *kvm, int64_t idt_index, char *syscall_reg);
//int scmon_stop(struct kvm *kvm);
int scmon_list_rules(char *buffer, unsigned int buffer_length);
int scmon_print_trace(char prefix, struct kvm_vcpu *vcpu);

void scmon_register_to_name(enum kvm_reg reg, char* str);
void scmon_action_to_name(enum scmon_action action, char *str);

#endif /* SCTRACE_OUTPUT_H_ */
