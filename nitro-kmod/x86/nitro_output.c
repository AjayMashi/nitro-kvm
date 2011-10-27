/*
 * nitro_output.c
 *
 *  Created on: Nov 30, 2010
 *      Author: fensterer
 */
#include "nitro_output.h"
// NOTE: nitro_output.h includes <linux/kvm_host.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/list.h>

#define NITRO_OUTPUT_LIST_MAX_LENGTH 8192
#define NITRO_OUTPUT_LIST_ENTRY_MAX_LENGTH 256

extern int kvm_write_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);
extern int kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes, struct kvm_vcpu *vcpu, u32 *error);

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

/*
 * KIRSCH: I wrote several debug print functions which I use
 * to verify the results of certain kvm_functions(). Maybe someone
 * else finds them useful. (There are more sophisticated ways to
 * realize this, I know, but the dirty method is enough for now.)
 */
int nitro_output_print_idt_entries(struct kvm_vcpu *vcpu) {

	struct kvm_sregs sregs;
	u8 *idt;
	u32 error, i;

	if (vcpu == NULL) return -1;

	kvm_arch_vcpu_ioctl_get_sregs(vcpu, &sregs);

	idt = kmalloc(sregs.idt.limit + 1, GFP_KERNEL);
	memset(idt, 0, sregs.idt.limit + 1);
	kvm_read_guest_virt_system(
			sregs.idt.base,
			idt,
			(unsigned int)(sregs.idt.limit + 1),
			vcpu,
			&error);

	for (i = 0; i < (sregs.idt.limit >> 3) - 1; i++) {
		printk("idt-entry 0x%04X: base_low: 0x%04X selector: 0x%04X zero: 0x%02X flags: 0x%02X base_hi: 0x%04X\n",
				i,
				*(u16*)(idt + 0 + i * 8),
				*(u16*)(idt + 2 + i * 8),
				*(u8*) (idt + 3 + i * 8),
				*(u8*) (idt + 4 + i * 8),
				*(u16*)(idt + 6 + i * 8));
	}

	kfree(idt);

	return 0;
}

int nitro_output_print_gdt_entries(struct kvm_vcpu *vcpu) {

	struct kvm_sregs sregs;
	u8 *gdt;
	u32 error, i;

	if (vcpu == NULL) return -1;

	kvm_arch_vcpu_ioctl_get_sregs(vcpu, &sregs);

	gdt = kmalloc(sregs.gdt.limit + 1, GFP_KERNEL);
	memset(gdt, 0, sregs.gdt.limit + 1);
	kvm_read_guest_virt_system(
			sregs.gdt.base,
			gdt,
			(unsigned int)(sregs.gdt.limit + 1),
			vcpu,
			&error);

	for (i = 0; i < (sregs.gdt.limit >> 3) - 1; i++) {
		printk("gdt-entry 0x%04X: limit_low: 0x%04X base_low: 0x%04X base_mid: 0x%02X access: 0x%02X attr: 0x%02X base_high: 0x%02X\n",
				i,
				*(u16*)(gdt + 0 + i * 8),
				*(u16*)(gdt + 2 + i * 8),
				*(u8*) (gdt + 4 + i * 8),
				*(u8*) (gdt + 5 + i * 8),
				*(u8*) (gdt + 6 + i * 8),
				*(u8*) (gdt + 7 + i * 8));
		}

	kfree(gdt);

	return 0;
}

/* Pretty much the same as the output of x /20x 0xaddress of the qemu
 * monitor, but this one can be triggered at any time from within the code.
 * IMPORTANT: 16d BYTES PER LINE!!
 */
int nitro_output_hexdump(u8 *data, int lines, __u64 optionalPrintAddress) {
	int i = 0;

	// if no address is given, assume the virtual address of the data should be taken
	if (optionalPrintAddress == 0) optionalPrintAddress = (__u64) data;
	if (data == NULL) return -1;

	for (i = 0; i < lines; i++) {
		printk("0x%08llX    %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
				optionalPrintAddress + 16 * i,
				*(data + i * 16 + 0),
				*(data + i * 16 + 1),
				*(data + i * 16 + 2),
				*(data + i * 16 + 3),
				*(data + i * 16 + 4),
				*(data + i * 16 + 5),
				*(data + i * 16 + 6),
				*(data + i * 16 + 7),
				*(data + i * 16 + 8),
				*(data + i * 16 + 9),
				*(data + i * 16 + 10),
				*(data + i * 16 + 11),
				*(data + i * 16 + 12),
				*(data + i * 16 + 13),
				*(data + i * 16 + 14),
				*(data + i * 16 + 15));
	}

	return 0;
}
