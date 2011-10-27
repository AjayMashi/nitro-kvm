/*
 * nitro_output.c
 *
 *  Created on: Nov 30, 2010
 *      Author: fensterer
 */
#include "nitro_output.h"
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/kvm_host.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/list.h>

#define NITRO_OUTPUT_LIST_MAX_LENGTH 8192
#define NITRO_OUTPUT_LIST_ENTRY_MAX_LENGTH 256

/**
 * Initialize Output-List
 */
struct nitro_output nitro_output;
struct proc_dir_entry *nitro_output_procfile;
unsigned int nitro_output_list_length = 0;

static DEFINE_MUTEX(nitro_output_lock);
DECLARE_WAIT_QUEUE_HEAD(nitro_output_wait);

static ssize_t nitro_output_procfile_read(struct file *filep, char *buffer, size_t length, loff_t *offset) {
	int error;
	char msg[NITRO_OUTPUT_LIST_ENTRY_MAX_LENGTH];
	char *localBuffer;
	struct list_head *pos, *tmp_head;
	struct nitro_output *list_elem;
	unsigned int elem_count, bytesRead, sclen;

	bytesRead = 0;
	sclen = 0;
	error = 0;
	elem_count = 0;
	length = 8192;
	msg[0] = '\0';

	if (length == 0 || buffer == NULL) {
		return error;
	}

	if (nitro_output_list_length == 0) {
		error = wait_event_interruptible(nitro_output_wait, (nitro_output_list_length > 0));
		if (error) {
			return error;
		}
	}

	localBuffer = (char *) kmalloc(length, GFP_KERNEL);
	if (localBuffer == NULL) {
		return error;
	}

	mutex_lock(&nitro_output_lock);
	list_for_each_safe(pos, tmp_head, &nitro_output.list) {
		if (bytesRead >= length) break;

		list_elem = list_entry(pos, struct nitro_output, list);

		if (list_elem == NULL) {
			continue;
		}

		if (list_elem->line == NULL) {
			continue;
		}

		bytesRead = strlcat(localBuffer, list_elem->line, length);
		list_del(pos);
		kfree(list_elem);

		nitro_output_list_length--;
	}

	localBuffer[length - 1] = '\0';

	if (bytesRead > 0) {
		memcpy(buffer, localBuffer, bytesRead);
		error = bytesRead;
	}

	mutex_unlock(&nitro_output_lock);
	kfree(localBuffer);

	return error;
}

static int nitro_output_procfile_open(struct inode *inode, struct file *file) {
	return 0;
}

static int nitro_output_procfile_close(struct inode *inode, struct file *file) {
	return 0;
}

static struct file_operations nitro_output_procfile_fops = {
		.owner	= THIS_MODULE,
		.open = nitro_output_procfile_open,
		.release = nitro_output_procfile_close,
		.read = nitro_output_procfile_read,
		.llseek = generic_file_llseek,
};

int nitro_output_init() {
	nitro_output_procfile = create_proc_entry("nitro", S_IRUGO, NULL);
	if (nitro_output_procfile) {
		nitro_output_procfile->proc_fops = &nitro_output_procfile_fops;
		printk("kvm:sctrace_output_init: created proc file /proc/nitro\n");

		INIT_LIST_HEAD(&nitro_output.list);
		return 0;
	}
	else {
		printk("kvm:sctrace_output_init: could not create proc file /proc/nitro");
		return -1;
	}
}

int nitro_output_exit(void) {
	struct list_head *pos;
	struct nitro_output *list_elem;

	printk("kvm:sctrace_output_exit\n");
	if (nitro_output_procfile) {
		remove_proc_entry("nitro", NULL);
	}

	list_for_each(pos, &nitro_output.list){
		list_elem = list_entry(pos, struct nitro_output, list);
		list_del(pos);
		kfree(list_elem);
	}

	return 0;
}

int nitro_output_append(char *string, int string_length) {
	struct nitro_output *tmp = (struct nitro_output *) kmalloc(sizeof(struct nitro_output), GFP_KERNEL);
	size_t line_size = ((string_length+1) > NITRO_OUTPUT_LIST_ENTRY_MAX_LENGTH) ? NITRO_OUTPUT_LIST_ENTRY_MAX_LENGTH : (string_length+1);

	tmp->line = (char *) kmalloc(line_size, GFP_KERNEL);
	if (tmp->line == NULL) {
		printk("kvm:nitro_output_append: could not allocate memory");
		return -1;
	}

	mutex_lock(&nitro_output_lock);
	if (nitro_output_list_length >= NITRO_OUTPUT_LIST_MAX_LENGTH) {
		list_rotate_left(&nitro_output.list);
		nitro_output_list_length--;
	}

	memcpy(tmp->line, string, line_size);
	tmp->line[line_size - 1] = '\0';

	list_add(&(tmp->list), &(nitro_output.list));
	nitro_output_list_length++;

	mutex_unlock(&nitro_output_lock);
	wake_up_interruptible_poll(&nitro_output_wait, POLLIN);

	return 0;
}
