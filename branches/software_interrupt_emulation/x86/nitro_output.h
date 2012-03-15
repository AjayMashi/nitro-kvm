/*
 * nitro_output.h
 *
 *  Created on: Nov 30, 2010
 *      Author: fensterer
 */

#ifndef NITRO_OUTPUT_H_
#define NITRO_OUTPUT_H_


int nitro_output_append(char *msg);
int nitro_output_init(void);
int nitro_output_exit(void);

#ifdef USE_NETLINK
#define NITRO_OUTPUT(...) { \
	char *str; \
	str = (char *) kmalloc(OUTPUT_MAX_CHARS, GFP_KERNEL); \
	sprintf(str, __VA_ARGS__); \
	nitro_output_append(str); \
	kfree(str); \
}
#else
#define NITRO_OUTPUT(...)	printk(__VA_ARGS__);
#endif

#ifdef DEBUG_INTERRUPTS
#define DEBUG_PRINT(...)	NITRO_OUTPUT(...)
#else
#define DEBUG_PRINT(...)	while (0) {}
#endif

#endif /* NITRO_OUTPUT_H_ */
