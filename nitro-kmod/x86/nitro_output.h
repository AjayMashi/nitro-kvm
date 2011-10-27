/*
 * nitro_output.h
 *
 *  Created on: Nov 30, 2010
 *      Author: fensterer
 */

#ifndef NITRO_OUTPUT_H_
#define NITRO_OUTPUT_H_

struct nitro_output {
	struct list_head list;
	char *line;
};

int nitro_output_init(void);
int nitro_output_exit(void);
int nitro_output_append(char *string, int string_length);

#endif /* NITRO_OUTPUT_H_ */
