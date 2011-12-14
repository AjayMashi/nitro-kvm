/*
 * nitro_output.h
 *
 *  Created on: Nov 30, 2010
 *      Author: fensterer
 */

#ifndef NITRO_OUTPUT_H_
#define NITRO_OUTPUT_H_

#include <linux/kvm_host.h>

struct nitro_output {
	struct list_head list;
	char *line;
};

int nitro_output_init(void);
int nitro_output_exit(void);
int nitro_output_append(char *string, int string_length);
int nitro_output_print_idt_entries(struct kvm_vcpu *vcpu);
int nitro_output_print_gdt_entries(struct kvm_vcpu *vcpu);
int nitro_output_hexdump(u8 *data, int lines, int optionalPrintAddress);

#endif /* NITRO_OUTPUT_H_ */
