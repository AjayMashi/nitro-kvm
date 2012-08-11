/*  
 *  - The simplest kernel module.
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

int init_module(void)
{
	struct {
		short limit;
		int base;
	} __attribute__((packed)) idt;
	
	struct {
		short limit;
		int base;
	} __attribute__((packed)) gdt;
	
	struct {
		short limit;
		int base;
	} __attribute__((packed)) ldt;
	
	short seg_task = 0;
	
	printk("------------\n");
	printk("Testing SIDT\n");
	printk("------------\n");
	printk("Storing values to 0x%x ...\n", (unsigned int)&idt);
	asm("sidt %0" : "=m" (idt));
	printk("idt.base: 0x%x\nidt.limit: 0x%x\n", idt.base, idt.limit);
	
	printk("\n------------\n");
	printk("Testing LIDT\n");
	printk("------------\n");
	printk("Reading values from 0x%x ...\n", (unsigned int)&idt);
	asm("lidt %0" : "=m" (idt));
	
	printk("\n------------\n");
	printk("Testing SGDT\n");
	printk("------------\n");
	printk("Storing values to 0x%x ...\n", (unsigned int)&gdt);
	asm("sgdt %0" : "=m" (gdt));
	printk("gdt.base: 0x%x\ngdt.limit: 0x%x\n", gdt.base, gdt.limit);
	
	printk("\n------------\n");
	printk("Testing LGDT\n");
	printk("------------\n");
	printk("Reading values from 0x%x ...\n", (unsigned int)&gdt);
	asm("lgdt %0" : "=m" (gdt));
	
	printk("\n------------\n");
	printk("Testing SLDT\n");
	printk("------------\n");
	printk("Storing values to 0x%x ...\n", (unsigned int)&ldt);
	asm("sldt %0" : "=m" (ldt));
	printk("ldt.base: 0x%x\nldt.limit: 0x%x\n", ldt.base, ldt.limit);
	
	printk("\n------------\n");
	printk("Testing LLDT\n");
	printk("------------\n");
	printk("Reading values from 0x%x ...\n", (unsigned int)&ldt);
	asm("lldt %0" : "=m" (ldt));
	
	printk("\n------------\n");
	printk("Testing STR\n");
	printk("------------\n");
	printk("Storing values to 0x%x ...\n", (unsigned int)&seg_task);
	asm("str %0" : "=m" (seg_task));
	printk("Task register segment: 0x%x\n", seg_task);
	
	printk("\n------------\n");
	printk("Testing LTR\n");
	printk("------------\n");
	printk("Reading values from 0x%x ...\n", (unsigned int)&seg_task);
	asm("ltr %0" : "=m" (seg_task));
	
	return 0;
}

void cleanup_module(void)
{
	return;
}