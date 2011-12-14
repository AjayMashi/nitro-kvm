/*
 * syscall_monitor.c
 *
 *  Created on: 22.12.2010
 *      Author: fenma
 */

#include <linux/kvm_host.h>
#include "syscall_trace.h"
#include "kvm_cache_regs.h"
#include "nitro_output.h"

#define NITRO_SCMON_ACTION_VALUE_MAX_SIZE 256
#define NITRO_SCMON_OUTPUT_LINE_MAX_SIZE 384

extern int kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);

struct scmon_rule *scmon_last_rule = NULL;
struct scmon_rule *scmon_first_rule = NULL;

void scmon_register_to_name(enum kvm_reg reg, char *str) {
	char *tmp;

	tmp = kmalloc(4, GFP_KERNEL);
	switch (reg) {
		case VCPU_REGS_RAX: tmp = "rax"; break;
		case VCPU_REGS_RBX: tmp = "rbx"; break;
		case VCPU_REGS_RCX: tmp = "rcx"; break;
		case VCPU_REGS_RDX: tmp = "rdx"; break;
		case VCPU_REGS_RSP: tmp = "rsp"; break;
		case VCPU_REGS_RBP: tmp = "rbp"; break;
		case VCPU_REGS_RSI: tmp = "rsi"; break;
		case VCPU_REGS_RDI: tmp = "rdi"; break;
		default: tmp = "";
	}

	strncpy(str, tmp, 4);
}

void scmon_action_to_name(enum scmon_action action, char *str) {
	char *tmp;

	tmp = kmalloc(10, GFP_KERNEL);
	switch (action) {
		case SCMON_ACTION_HEX: 		tmp = "hex"; break;
		case SCMON_ACTION_INT: 		tmp = "int"; break;
		case SCMON_ACTION_UINT: 	tmp = "uint"; break;
		case SCMON_ACTION_DEREFHEX: tmp = "derefhex"; break;
		case SCMON_ACTION_DEREFINT: tmp = "derefint"; break;
		case SCMON_ACTION_DEREFUINT:tmp = "derefuint"; break;
		case SCMON_ACTION_DEREFSTR: tmp = "derefstr"; break;
		default: 		tmp = "";
	}

	strncpy(str, tmp, 9);
}

int scmon_add_rule(enum kvm_reg cond_reg, unsigned long int cond_val, enum kvm_reg action_reg, int64_t action_reg_offset, enum scmon_action action) {
	struct scmon_rule *rule;
	char *cond_reg_name, *action_reg_name, *action_name;

	rule = kmalloc(sizeof(struct scmon_rule), GFP_KERNEL);
	if (rule == NULL) {
		return 1;
	}

	cond_reg_name = kmalloc(4, GFP_KERNEL);
	if (cond_reg_name == NULL) {
		kfree(rule);
		return 1;
	}

	action_reg_name = kmalloc(4, GFP_KERNEL);
	if (action_reg_name == NULL) {
		kfree(rule);
		kfree(cond_reg_name);
		return 1;
	}

	action_name = kmalloc(10, GFP_KERNEL);
	if (action_name == NULL) {
		kfree(rule);
		kfree(cond_reg_name);
		kfree(action_reg_name);
		return 1;
	}

	scmon_register_to_name(cond_reg, cond_reg_name);
	scmon_register_to_name(action_reg, action_reg_name);
	scmon_action_to_name(action, action_name);

	printk("kvm:scmon: added rule: if (%s == %lu) => %s%+ld %s\n", cond_reg_name, cond_val, action_reg_name, (long int) action_reg_offset, action_name);

	rule->cond_reg = cond_reg;
	rule->cond_val = cond_val;
	rule->action_reg = action_reg;
	rule->action_reg_offset = action_reg_offset;
	rule->action = action;
	rule->next = NULL;

	if (scmon_first_rule != NULL) {
		scmon_last_rule->next = rule;
		rule->prev = scmon_last_rule;
	}
	else {
		scmon_first_rule = rule;
		rule->prev = NULL;
	}

	scmon_last_rule = rule;

	kfree(cond_reg_name);
	kfree(action_reg_name);
	kfree(action_name);

	return 0;
}

int scmon_delete_rule(unsigned int id) {
	struct scmon_rule *current_rule;
	int i;

	printk("scmon_delete_rule(%u)\n", id);
	if (id < 0 || scmon_first_rule == NULL) {
		return 1;
	}

	current_rule = scmon_first_rule;
	i = 0;
	while (current_rule != NULL) {
		if (id == i) {
			if (current_rule->prev != NULL) {
				current_rule->prev->next = current_rule->next;
			}
			else {
				// trying to remove first item of list => reset first-pointer
				scmon_first_rule = current_rule->next;
			}

			if (current_rule->next != NULL) {
				current_rule->next->prev = current_rule->prev;
			}
			else {
				// trying to remove last item of list => reset last-pointer
				scmon_last_rule = current_rule->prev;
			}

			kfree(current_rule);
			return 0;
		}

		i++;
		current_rule = current_rule->next;
	}

	return 1;
}

int scmon_flush_rules() {
	struct scmon_rule *current_rule = scmon_first_rule;
	struct scmon_rule *next;
	unsigned int flushed_rules_count = 0;

	while (current_rule != NULL) {
		next = current_rule->next;
		kfree(current_rule);
		current_rule = next;
		flushed_rules_count++;
	}
	printk("flushed %u rules\n", flushed_rules_count);

	scmon_last_rule = NULL;
	scmon_first_rule = NULL;

	return 0;
}

int scmon_print_trace(char prefix, struct kvm_vcpu *vcpu) {
	unsigned long scmonreg, scmonactionreg, scmonderef, len, abs_offset;
	char *buffer, *cond_reg_name, *action_reg_name, *action_name, *output_line, *action_value;
	struct scmon_rule *current_rule;
	u32 error;

	len = 0;
	current_rule = scmon_first_rule;
	if (current_rule == NULL) {
		return 0;
	}

	cond_reg_name = kmalloc(4, GFP_KERNEL);
	if (cond_reg_name == NULL) {
		return 1;
	}

	action_reg_name = kmalloc(4, GFP_KERNEL);
	if (action_reg_name == NULL) {
		kfree(cond_reg_name);
		return 1;
	}

	action_name = kmalloc(9, GFP_KERNEL);
	if (action_name == NULL) {
		kfree(cond_reg_name);
		kfree(action_reg_name);
		return 1;
	}

	output_line = kmalloc(NITRO_SCMON_OUTPUT_LINE_MAX_SIZE, GFP_KERNEL);
	if (output_line == NULL) {
		kfree(cond_reg_name);
		kfree(action_reg_name);
		kfree(action_name);
		return 1;
	}

	action_value = kmalloc(NITRO_SCMON_ACTION_VALUE_MAX_SIZE, GFP_KERNEL);
	if (action_value == NULL) {
		kfree(cond_reg_name);
		kfree(action_reg_name);
		kfree(action_name);
		kfree(output_line);
		return 1;
	}

	current_rule = scmon_first_rule;
	while (current_rule != NULL) {
		scmonreg = kvm_register_read(vcpu, current_rule->cond_reg);
		if (scmonreg == current_rule->cond_val) {
			scmonactionreg = kvm_register_read(vcpu, current_rule->action_reg);
			abs_offset = abs(current_rule->action_reg_offset);

			if (current_rule->action_reg_offset <= 0) {
				if (abs_offset > scmonactionreg) {
					printk("kvm:syscall_mon: offset is to big\n");
					continue;
				}
				scmonactionreg -= abs_offset;
			}
			else {
				scmonactionreg += abs_offset;
			}

			scmon_register_to_name(current_rule->cond_reg, cond_reg_name);
			scmon_register_to_name(current_rule->action_reg, action_reg_name);
			scmon_action_to_name(current_rule->action, action_name);

			snprintf(output_line, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1, "kvm:syscall_mon: %s == %lX occured: %s%+ld %s = ", cond_reg_name, current_rule->cond_val, action_reg_name, (long int) current_rule->action_reg_offset, action_name);
			switch (current_rule->action) {
				case SCMON_ACTION_HEX:
					snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "0x%lX\n", scmonactionreg);
				break;
				case SCMON_ACTION_INT:
					snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%ld\n", scmonactionreg);
				break;
				case SCMON_ACTION_UINT:
					snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%lu\n", scmonactionreg);
				break;
				case SCMON_ACTION_DEREFHEX:
					kvm_read_guest_virt_system(scmonactionreg, &scmonderef, 8, vcpu, &error);
					snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "0x%lX\n", scmonderef);
				break;
				case SCMON_ACTION_DEREFINT:
					kvm_read_guest_virt_system(scmonactionreg, &scmonderef, 8, vcpu, &error);
					snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%ld\n", scmonderef);
				break;
				case SCMON_ACTION_DEREFUINT:
					kvm_read_guest_virt_system(scmonactionreg, &scmonderef, 8, vcpu, &error);
					snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%lu\n", scmonderef);
				break;
				case SCMON_ACTION_DEREFSTR:
					buffer = kmalloc(NITRO_SCMON_ACTION_VALUE_MAX_SIZE, GFP_KERNEL);
					if (buffer == NULL) {
						printk("kvm:syscall_mon: could not allocate memory for string buffer\n");
						continue;
					}
					kvm_read_guest_virt_system(scmonactionreg, buffer, NITRO_SCMON_ACTION_VALUE_MAX_SIZE, vcpu, &error);
					buffer[NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1] = '\0';
					len = snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%s\n", buffer);
					kfree(buffer);
				break;
			}

			// check for truncation
			if (len >= NITRO_SCMON_ACTION_VALUE_MAX_SIZE-2) {
				action_value[NITRO_SCMON_ACTION_VALUE_MAX_SIZE-2] = '\n';
				action_value[NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1] = '\0';
			}

			strlcat(output_line, action_value, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1);
			//Proc Output
			//nitro_output_append(output_line, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1);
			printk(output_line);
		}

		current_rule = current_rule->next;
	}

	kfree(cond_reg_name);
	kfree(action_reg_name);
	kfree(action_name);
	kfree(output_line);
	kfree(action_value);

	return 0;
}

int scmon_list_rules(char *buffer, unsigned int buffer_length) {
	struct scmon_rule *current_rule;
	char *local_buffer;
	char cond_reg_name[4];
	char action_reg_name[4];
	char action_name[9];
	char tmp[64];
	unsigned int local_buffer_length, rule_index;

	local_buffer = kmalloc(buffer_length, GFP_KERNEL);
	if (local_buffer == NULL) {
		printk("scmon_list_rules could not allocate enough memory!\n");
		return -1;
	}

	local_buffer_length = 1;
	current_rule = scmon_first_rule;
	rule_index = 0;
	while (current_rule != NULL) {
		tmp[0] = '\0';

		if (local_buffer_length >= buffer_length) {
			printk("scmon_list_rules output: %s\n", local_buffer);
			memcpy(buffer, local_buffer, buffer_length);

			kfree(local_buffer);
			return 0;
		}

		scmon_register_to_name(current_rule->cond_reg, cond_reg_name);
		scmon_register_to_name(current_rule->action_reg, action_reg_name);
		scmon_action_to_name(current_rule->action, action_name);

		snprintf(tmp, 64, "[%d] (%s == %lX) => %s%+ld %s\n", rule_index, cond_reg_name, current_rule->cond_val, action_reg_name, (long int) current_rule->action_reg_offset, action_name);
		local_buffer_length += strnlen(tmp, 64);
		strncat(local_buffer, tmp, 64);

		current_rule = current_rule->next;
		rule_index++;
	}
	memcpy(buffer, local_buffer, local_buffer_length);

	kfree(local_buffer);
	return 0;
}

/*
int scmon_start(struct kvm *kvm, int64_t idt_index,char* syscall_reg) {
	start_nitro(kvm, idt_index, syscall_reg, 1);
	return 0;
}

int scmon_stop(struct kvm *kvm) {
	stop_syscall_trace(kvm);
	return 0;
}
*/
