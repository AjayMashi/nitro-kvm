/*
 * nitro_output.h
 *
 *  Created on: Nov 30, 2010
 *      Author: fensterer
 */

#ifndef NITRO_OUTPUT_H_
#define NITRO_OUTPUT_H_

int nitro_output_init(void);
int nitro_output_exit(void);

extern int nitro_output_data(u8 *, int, int);

#define NITRO_MSG_TYPE_BINARY		0
#define NITRO_MSG_TYPE_TEXT		1

#ifdef USE_NETLINK

#define MAX_LINKS 			32	/* see include/linux/netlink.h */

#if NETLINK_NITRO > MAX_LINKS
#define NETLINK_NITRO MAX_LINKS
#endif

#define NITRO_OUTPUT(...) { \
	char *str; \
	str = (char *) kmalloc(OUTPUT_MAX_CHARS, GFP_KERNEL); \
	sprintf(str, __VA_ARGS__); \
	nitro_output_data(str, strlen(str), NITRO_MSG_TYPE_TEXT); \
	kfree(str); \
}
#else
#define NITRO_OUTPUT(...)	printk(__VA_ARGS__);	/* speed hack */
#endif

#define NITRO_OUTPUT_BINARY(data, len) { \
	nitro_output_data(data, len, NITRO_MSG_TYPE_BINARY); \
}

#ifdef DEBUG_INTERRUPTS
#define DEBUG_PRINT(...)		NITRO_OUTPUT(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)		while (0) {}
#endif

#endif /* NITRO_OUTPUT_H_ */
