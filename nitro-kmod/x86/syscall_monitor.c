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
//old value: 384
#define NITRO_SCMON_OUTPUT_LINE_MAX_SIZE 512

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
#ifdef CONFIG_X86_64
		case VCPU_REGS_R8: tmp = "r8 "; break;
		case VCPU_REGS_R9: tmp = "r9 "; break;
		case VCPU_REGS_R10: tmp = "r10"; break;
		case VCPU_REGS_R11: tmp = "r11"; break;
		case VCPU_REGS_R12: tmp = "r12"; break;
		case VCPU_REGS_R13: tmp = "r13"; break;
		case VCPU_REGS_R14: tmp = "r14"; break;
		case VCPU_REGS_R15: tmp = "r15"; break;
#endif
		case VCPU_SCMON_REGS_ANY: tmp = "any"; break;  //WARNING TO BE EXPECTED: warning: case value ‘42’ not in enumerated type ‘enum kvm_reg’
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

static void snprint_action_register_headerline(char *output_line,
		enum kvm_reg action_reg, struct scmon_rule *current_rule,
		/* memory allocated by scmon_print_trace: */
		char *cond_reg_name, char *action_reg_name, char *action_name,
		/*kvm data */
		struct kvm_vcpu *vcpu
)
{


	scmon_register_to_name(action_reg, action_reg_name);
	scmon_action_to_name(current_rule->action, action_name);

	if(current_rule->cond_reg == VCPU_SCMON_REGS_ANY){
		// create default nitro like output line
		unsigned long cr3, pde, screg;
		u32 verifier;
		screg = kvm_register_read(vcpu, vcpu->kvm->nitro_data.syscall_reg);

		get_process_hardware_id(vcpu, &cr3, &verifier, &pde);

		snprintf(output_line, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1,
				"kvm:syscall_mon(any): %s:0x%lX:%u:0x%lX %lu cr3=0x%lX ",
				vcpu->kvm->nitro_data.id, cr3, verifier, pde, screg, cr3);
	}else{
		snprintf(output_line, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1, "kvm:syscall_mon: %s == %lX occured: %s%+ld %s = ", cond_reg_name, current_rule->cond_val, action_reg_name, (long int) current_rule->action_reg_offset, action_name);
	}
}


static int snprint_action_register(char *action_value,
		enum kvm_reg action_reg, struct scmon_rule *current_rule,
		/* memory allocated by scmon_print_trace: */
		char *cond_reg_name, char *action_reg_name, char *action_name,
		/*kvm data */
		struct kvm_vcpu *vcpu
)
{
	unsigned long scmonactionreg, scmonderef, len, abs_offset;
	char *buffer;
	u32 error;

	len = 0;

	scmonactionreg = kvm_register_read(vcpu, action_reg);
	abs_offset = abs(current_rule->action_reg_offset);

	if (current_rule->action_reg_offset <= 0) {
		if (abs_offset > scmonactionreg) {
			printk("kvm:syscall_mon: offset is to big\n");
			return -1;
		}
		scmonactionreg -= abs_offset;
	}
	else {
		scmonactionreg += abs_offset;
	}


	// update if if(current_rule->cond_reg == VCPU_SCMON_REGS_ANY){
	scmon_register_to_name(action_reg, action_reg_name);


	switch (current_rule->action) {
	case SCMON_ACTION_HEX:
		snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%s=0x%lX ", action_reg_name, scmonactionreg);
		break;
	case SCMON_ACTION_INT:
		snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%s=%ld\n", action_reg_name, scmonactionreg);
		break;
	case SCMON_ACTION_UINT:
		snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%s=%lu\n", action_reg_name, scmonactionreg);
		break;
	case SCMON_ACTION_DEREFHEX:
		kvm_read_guest_virt_system(scmonactionreg, &scmonderef, 8, vcpu, &error);
		snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%s=0x%lX\n", action_reg_name, scmonderef);
		break;
	case SCMON_ACTION_DEREFINT:
		kvm_read_guest_virt_system(scmonactionreg, &scmonderef, 8, vcpu, &error);
		snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%s=%ld\n", action_reg_name, scmonderef);
		break;
	case SCMON_ACTION_DEREFUINT:
		kvm_read_guest_virt_system(scmonactionreg, &scmonderef, 8, vcpu, &error);
		snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%s=%lu\n", action_reg_name, scmonderef);
		break;
	case SCMON_ACTION_DEREFSTR:
		buffer = kmalloc(NITRO_SCMON_ACTION_VALUE_MAX_SIZE, GFP_KERNEL);
		if (buffer == NULL) {
			printk("kvm:syscall_mon: could not allocate memory for string buffer\n");
			return -1;
		}
		kvm_read_guest_virt_system(scmonactionreg, buffer, NITRO_SCMON_ACTION_VALUE_MAX_SIZE, vcpu, &error);
		buffer[NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1] = '\0';
		len = snprintf(action_value, NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1, "%s=%s\n", action_reg_name, buffer);
		kfree(buffer);
		break;
	}

	// check for truncation
	if (len >= NITRO_SCMON_ACTION_VALUE_MAX_SIZE-2) {
		//action_value[NITRO_SCMON_ACTION_VALUE_MAX_SIZE-2] = '\n';
		action_value[NITRO_SCMON_ACTION_VALUE_MAX_SIZE-2] = ' ';
		action_value[NITRO_SCMON_ACTION_VALUE_MAX_SIZE-1] = '\0';
	}

	return 0;
}

int scmon_print_trace(char prefix, struct kvm_vcpu *vcpu) {
	unsigned long scmonreg, len;
	char *cond_reg_name, *action_reg_name, *action_name, *output_line, *action_value;
	struct scmon_rule *current_rule;
	int rule_matches = 0;

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
		rule_matches = 0;
		if(current_rule->cond_reg == VCPU_SCMON_REGS_ANY){
			// if cond_reg is any, we trigger on any value in the sysCall register
			// vcpu->kvm->sctd->syscall_reg
			//printk("kvm_register_read any %d\n", vcpu->kvm->sctd.syscall_reg);

			scmonreg = kvm_register_read(vcpu, vcpu->kvm->nitro_data.syscall_reg);
			scmon_register_to_name(vcpu->kvm->nitro_data.syscall_reg, cond_reg_name);

			rule_matches = 1;
		}else{
			scmonreg = kvm_register_read(vcpu, current_rule->cond_reg);
			scmon_register_to_name(current_rule->cond_reg, cond_reg_name);

			if(scmonreg == current_rule->cond_val){
				rule_matches = 1;
			}
		}
		if (rule_matches) {
			if(current_rule->action_reg == VCPU_SCMON_REGS_ANY){
				// iterate over all registers
				enum kvm_reg all_registers[] =  {
						VCPU_REGS_RAX,
						VCPU_REGS_RCX,
						VCPU_REGS_RDX,
						VCPU_REGS_RBX,
						VCPU_REGS_RSP,
						VCPU_REGS_RBP,
						VCPU_REGS_RSI,
						VCPU_REGS_RDI,
#ifdef CONFIG_X86_64
						VCPU_REGS_R8,
						VCPU_REGS_R9,
						VCPU_REGS_R10,
						VCPU_REGS_R11,
						VCPU_REGS_R12,
						VCPU_REGS_R13,
						VCPU_REGS_R14,
						VCPU_REGS_R15,
#endif
				};
				int i;
				int cont = 0;

				snprint_action_register_headerline(output_line, current_rule->action_reg, current_rule, cond_reg_name, action_reg_name, action_name, vcpu);

				for(i=0; i < VCPU_REGS_RIP; ++i){
					if(snprint_action_register(action_value, all_registers[i], current_rule,
							cond_reg_name, action_reg_name, action_name, vcpu) != 0){
						cont = 1;
					}

					strlcat(output_line, action_value, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1);
				}
				if(cont) continue;
			}else{
				snprint_action_register_headerline(output_line, current_rule->action_reg, current_rule, cond_reg_name, action_reg_name, action_name, vcpu);
				if(snprint_action_register(action_value, current_rule->action_reg, current_rule,
						cond_reg_name, action_reg_name, action_name, vcpu) != 0) continue;


				strlcat(output_line, action_value, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1);
			}
			//add \n and correctly end string
			len = snprintf(output_line, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1, "%s\n", output_line);
			if (len >= NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-2) {
				output_line[NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-2] = '\n';
				output_line[NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1] = '\0';
			}
			//Proc Output
			//nitro_output_append(output_line, NITRO_SCMON_OUTPUT_LINE_MAX_SIZE-1);
			printk(output_line);

			vcpu->kvm->nitro_data.singlestep.need_exit_to_qemu = 1;
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
