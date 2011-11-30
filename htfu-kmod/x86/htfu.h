#ifndef HTFU_H_
#define HTFU_H_


#include <stdint.h>

	int htfu_block_int(uint32_t interrupt);
	int htfu_unblock_int(uint32_t interrupt);
	int htfu_warn_int(uint32_t interrupt);
	int htfu_unwarn_int(uint32_t interrupt);
	int htfu_block_sc(uint32_t sc_nr);
	int htfu_unblock_sc(uint32_t sc_nr);

#endif
