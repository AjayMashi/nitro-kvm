
/*
 * Compatibility header for building as an external module.
 */

#include <linux/compiler.h>
#include <linux/version.h>

#include <linux/types.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

typedef u64 phys_addr_t;

#endif

#include "../external-module-compat-comm.h"

#include <asm/msr.h>
#include <asm/asm.h>

#ifndef CONFIG_HAVE_KVM_EVENTFD
#define CONFIG_HAVE_KVM_EVENTFD 1
#endif

#ifndef CONFIG_KVM_APIC_ARCHITECTURE
#define CONFIG_KVM_APIC_ARCHITECTURE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#ifdef CONFIG_X86_64
#define DECLARE_ARGS(val, low, high)	unsigned low, high
#define EAX_EDX_VAL(val, low, high)	((low) | ((u64)(high) << 32))
#define EAX_EDX_ARGS(val, low, high)	"a" (low), "d" (high)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
#else
#define DECLARE_ARGS(val, low, high)	unsigned long long val
#define EAX_EDX_VAL(val, low, high)	(val)
#define EAX_EDX_ARGS(val, low, high)	"A" (val)
#define EAX_EDX_RET(val, low, high)	"=A" (val)
#endif

#ifndef __ASM_EX_SEC
# define __ASM_EX_SEC	" .section __ex_table,\"a\"\n"
#endif

#ifndef _ASM_EXTABLE
# define _ASM_EXTABLE(from,to) \
        __ASM_EX_SEC    \
        _ASM_ALIGN "\n" \
        _ASM_PTR #from "," #to "\n" \
        " .previous\n"
#endif

#ifndef __ASM_SEL
#ifdef CONFIG_X86_32
# define __ASM_SEL(a,b) __ASM_FORM(a)
#else
# define __ASM_SEL(a,b) __ASM_FORM(b)
#endif
#endif

#ifndef __ASM_FORM
# define __ASM_FORM(x)	" " #x " "
#endif

#ifndef _ASM_PTR
#define _ASM_PTR	__ASM_SEL(.long, .quad)
#endif

#ifndef _ASM_ALIGN
#define _ASM_ALIGN	__ASM_SEL(.balign 4, .balign 8)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) || defined(CONFIG_X86_64)

static inline unsigned long long native_read_msr_safe(unsigned int msr,
						      int *err)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("2: rdmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=r" (*err), EAX_EDX_RET(val, low, high)
		     : "c" (msr), [fault] "i" (-EFAULT));
	return EAX_EDX_VAL(val, low, high);
}

#endif

static inline int kvm_native_write_msr_safe(unsigned int msr,
					    unsigned low, unsigned high)
{
	int err;
	asm volatile("2: wrmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=a" (err)
		     : "c" (msr), "0" (low), "d" (high),
		       [fault] "i" (-EIO)
		     : "memory");
	return err;
}

static inline unsigned long long kvm_native_read_tsc(void)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdtsc" : EAX_EDX_RET(val, low, high));
	return EAX_EDX_VAL(val, low, high);
}

#else /* >= 2.6.25 */

#define kvm_native_write_msr_safe	native_write_msr_safe
#define kvm_native_read_tsc		native_read_tsc

#endif /* >= 2.6.25 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

static inline int rdmsrl_safe(unsigned msr, unsigned long long *p)
{
	int err;

	*p = native_read_msr_safe(msr, &err);
	return err;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#ifndef _EFER_SCE
#define _EFER_SCE		0  /* SYSCALL/SYSRET */
#endif

#ifndef EFER_SCE
#define EFER_SCE		(1<<_EFER_SCE)
#endif

#endif

#ifndef MSR_KERNEL_GS_BASE
#define MSR_KERNEL_GS_BASE              0xc0000102
#endif

#ifndef MSR_VM_CR
#define MSR_VM_CR                       0xc0010114
#endif

#ifndef MSR_VM_HSAVE_PA
#define MSR_VM_HSAVE_PA                 0xc0010117
#endif

#ifndef _EFER_SVME
#define _EFER_SVME		12
#define EFER_SVME		(1<<_EFER_SVME)
#endif

#ifndef _EFER_FFXSR
#define _EFER_FFXSR		14 /* Enable Fast FXSAVE/FXRSTOR */
#define EFER_FFXSR		(1<<_EFER_FFXSR)
#endif

#ifndef MSR_STAR
#define MSR_STAR                0xc0000081
#endif

#ifndef MSR_K8_INT_PENDING_MSG
#define MSR_K8_INT_PENDING_MSG  0xc0010055
#endif

#include <asm/cpufeature.h>

#ifndef X86_FEATURE_SVM
#define X86_FEATURE_SVM               (6*32+ 2) /* Secure virtual machine */
#endif

#ifndef X86_FEATURE_FXSR_OPT
#define X86_FEATURE_FXSR_OPT  (1*32+25)
#endif

#ifndef X86_FEATURE_GBPAGES
#define X86_FEATURE_GBPAGES	(1*32+26) /* GB pages */
#endif

#ifndef X86_FEATURE_SSSE3
#define X86_FEATURE_SSSE3	(4*32+ 9) /* Supplemental SSE-3 */
#endif

#ifndef X86_FEATURE_XMM4_1
#define X86_FEATURE_XMM4_1	(4*32+19) /* "sse4_1" SSE-4.1 */
#endif

#ifndef X86_FEATURE_XMM4_2
#define X86_FEATURE_XMM4_2	(4*32+20) /* "sse4_2" SSE-4.2 */
#endif

#ifndef X86_FEATURE_MOVBE
#define X86_FEATURE_MOVBE	(4*32+22) /* MOVBE instruction */
#endif

#ifndef X86_FEATURE_POPCNT
#define X86_FEATURE_POPCNT      (4*32+23) /* POPCNT instruction */
#endif

#ifndef X86_FEATURE_CR8_LEGACY
#define X86_FEATURE_CR8_LEGACY	(6*32+ 4) /* CR8 in 32-bit mode */
#endif

#ifndef X86_FEATURE_ABM
#define X86_FEATURE_ABM		(6*32+ 5) /* Advanced bit manipulation */
#endif

#ifndef X86_FEATURE_SSE4A
#define X86_FEATURE_SSE4A	(6*32+ 6) /* SSE-4A */
#endif

#ifndef X86_FEATURE_MISALIGNSSE
#define X86_FEATURE_MISALIGNSSE (6*32+ 7) /* Misaligned SSE mode */
#endif

#ifndef X86_FEATURE_3DNOWPREFETCH
#define X86_FEATURE_3DNOWPREFETCH (6*32+ 8) /* 3DNow prefetch instructions */
#endif

#ifndef X86_FEATURE_XOP
#define X86_FEATURE_XOP		(6*32+11) /* extended AVX instructions */
#endif

#ifndef X86_FEATURE_FMA4
#define X86_FEATURE_FMA4	(6*32+16) /* 4 operands MAC instructions */
#endif

#ifndef X86_FEATURE_TBM
#define X86_FEATURE_TBM		(6*32+21) /* trailing bit manipulations */
#endif

#ifndef X86_FEATURE_X2APIC
#define X86_FEATURE_X2APIC    (4*32+21) /* x2APIC */
#endif

#ifndef X86_FEATURE_AES
#define X86_FEATURE_AES		(4*32+25) /* AES instructions */
#endif

#ifndef X86_FEATURE_F16C
#define X86_FEATURE_F16C	(4*32+29) /* 16-bit fp conversions */
#endif

#ifndef MSR_AMD64_PATCH_LOADER
#define MSR_AMD64_PATCH_LOADER         0xc0010020
#endif

#include <linux/smp.h>

#ifndef X86_CR0_PE
#define X86_CR0_PE 0x00000001
#endif

#ifndef X86_CR0_MP
#define X86_CR0_MP 0x00000002
#endif

#ifndef X86_CR0_EM
#define X86_CR0_EM 0x00000004
#endif

#ifndef X86_CR0_TS
#define X86_CR0_TS 0x00000008
#endif

#ifndef X86_CR0_ET
#define X86_CR0_ET 0x00000010
#endif

#ifndef X86_CR0_NE
#define X86_CR0_NE 0x00000020
#endif

#ifndef X86_CR0_WP
#define X86_CR0_WP 0x00010000
#endif

#ifndef X86_CR0_AM
#define X86_CR0_AM 0x00040000
#endif

#ifndef X86_CR0_NW
#define X86_CR0_NW 0x20000000
#endif

#ifndef X86_CR0_CD
#define X86_CR0_CD 0x40000000
#endif

#ifndef X86_CR0_PG
#define X86_CR0_PG 0x80000000
#endif

#ifndef X86_CR3_PWT
#define X86_CR3_PWT 0x00000008
#endif

#ifndef X86_CR3_PCD
#define X86_CR3_PCD 0x00000010
#endif

#ifndef X86_CR4_VMXE
#define X86_CR4_VMXE 0x00002000
#endif

#undef X86_CR8_TPR
#define X86_CR8_TPR 0x0f

#ifdef CONFIG_X86_32

#include <asm/cmpxchg.h>

static inline unsigned long long __kvm_cmpxchg64(volatile void *ptr,
						 unsigned long long old,
						 unsigned long long new)
{
	unsigned long long prev;
	__asm__ __volatile__("lock cmpxchg8b %3"
			     : "=A"(prev)
			     : "b"((unsigned long)new),
			       "c"((unsigned long)(new >> 32)),
			       "m"(*__xg(ptr)),
			       "0"(old)
			     : "memory");
	return prev;
}

#define kvm_cmpxchg64(ptr,o,n)\
	((__typeof__(*(ptr)))__kvm_cmpxchg64((ptr),(unsigned long long)(o),\
					(unsigned long long)(n)))

#undef cmpxchg64
#define cmpxchg64(ptr, o, n) kvm_cmpxchg64(ptr, o, n)

#endif

#ifndef CONFIG_PREEMPT_NOTIFIERS
/*
 * Include sched|preempt.h before defining CONFIG_PREEMPT_NOTIFIERS to avoid
 * a miscompile.
 */
#include <linux/sched.h>
#include <linux/preempt.h>
#define CONFIG_PREEMPT_NOTIFIERS
#define CONFIG_PREEMPT_NOTIFIERS_COMPAT

struct preempt_notifier;

struct preempt_ops {
	void (*sched_in)(struct preempt_notifier *notifier, int cpu);
	void (*sched_out)(struct preempt_notifier *notifier,
			  struct task_struct *next);
};

struct preempt_notifier {
	struct list_head link;
	struct task_struct *tsk;
	struct preempt_ops *ops;
};

void preempt_notifier_register(struct preempt_notifier *notifier);
void preempt_notifier_unregister(struct preempt_notifier *notifier);

static inline void preempt_notifier_init(struct preempt_notifier *notifier,
				     struct preempt_ops *ops)
{
	notifier->ops = ops;
}

void start_special_insn(void);
void end_special_insn(void);
void in_special_section(void);

void preempt_notifier_sys_init(void);
void preempt_notifier_sys_exit(void);

#else

static inline void start_special_insn(void) {}
static inline void end_special_insn(void) {}
static inline void in_special_section(void) {}

static inline void preempt_notifier_sys_init(void) {}
static inline void preempt_notifier_sys_exit(void) {}

#endif

/* CONFIG_HAS_IOMEM is apparently fairly new too (2.6.21 for x86_64). */
#ifndef CONFIG_HAS_IOMEM
#define CONFIG_HAS_IOMEM 1
#endif

/* X86_FEATURE_NX is missing in some x86_64 kernels */

#include <asm/cpufeature.h>

#ifndef X86_FEATURE_NX
#define X86_FEATURE_NX (1*32+20)
#endif

/* EFER_LMA and EFER_LME are missing in pre 2.6.24 i386 kernels */
#ifndef EFER_LME
#define _EFER_LME           8  /* Long mode enable */
#define _EFER_LMA           10 /* Long mode active (read-only) */
#define EFER_LME            (1<<_EFER_LME)
#define EFER_LMA            (1<<_EFER_LMA)
#endif

struct kvm_desc_struct {
	union {
		struct { unsigned int a, b; };
		struct {
			u16 limit0;
			u16 base0;
			unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
			unsigned limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
		};

	};
} __attribute__((packed));

struct kvm_ldttss_desc64 {
	u16 limit0;
	u16 base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	u32 base3;
	u32 zero1;
} __attribute__((packed));

struct kvm_desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed));

static inline unsigned long kvm_get_desc_base(const struct kvm_desc_struct *desc)
{
	return (unsigned)(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline unsigned long kvm_get_desc_limit(const struct kvm_desc_struct *desc)
{
	return desc->limit0 | (desc->limit << 16);
}

static inline void kvm_load_gdt(const struct kvm_desc_ptr *dtr)
{
	asm volatile("lgdt %0"::"m" (*dtr));
}

static inline void kvm_store_gdt(struct kvm_desc_ptr *dtr)
{
	asm volatile("sgdt %0":"=m" (*dtr));
}

#include <asm/msr.h>
#ifndef MSR_FS_BASE
#define MSR_FS_BASE 0xc0000100
#endif
#ifndef MSR_GS_BASE
#define MSR_GS_BASE 0xc0000101
#endif

/* undefine lapic */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)

#undef lapic

#endif

#include <asm/hw_irq.h>
#ifndef NMI_VECTOR
#define NMI_VECTOR 2
#endif

#ifndef MSR_MTRRcap
#define MSR_MTRRcap            0x0fe
#define MSR_MTRRfix64K_00000   0x250
#define MSR_MTRRfix16K_80000   0x258
#define MSR_MTRRfix16K_A0000   0x259
#define MSR_MTRRfix4K_C0000    0x268
#define MSR_MTRRfix4K_C8000    0x269
#define MSR_MTRRfix4K_D0000    0x26a
#define MSR_MTRRfix4K_D8000    0x26b
#define MSR_MTRRfix4K_E0000    0x26c
#define MSR_MTRRfix4K_E8000    0x26d
#define MSR_MTRRfix4K_F0000    0x26e
#define MSR_MTRRfix4K_F8000    0x26f
#define MSR_MTRRdefType        0x2ff
#endif

#ifndef MSR_IA32_CR_PAT
#define MSR_IA32_CR_PAT        0x00000277
#endif

#ifndef MSR_VM_IGNNE
#define MSR_VM_IGNNE                    0xc0010115
#endif

/* Define DEBUGCTLMSR bits */
#ifndef DEBUGCTLMSR_LBR

#define _DEBUGCTLMSR_LBR	0 /* last branch recording */
#define _DEBUGCTLMSR_BTF	1 /* single-step on branches */

#define DEBUGCTLMSR_LBR		(1UL << _DEBUGCTLMSR_LBR)
#define DEBUGCTLMSR_BTF		(1UL << _DEBUGCTLMSR_BTF)

#endif

#ifndef MSR_FAM10H_MMIO_CONF_BASE
#define MSR_FAM10H_MMIO_CONF_BASE      0xc0010058
#endif

#ifndef MSR_AMD64_NB_CFG
#define MSR_AMD64_NB_CFG               0xc001001f
#endif

#include <asm/asm.h>

#ifndef __ASM_SIZE
# define ____ASM_FORM(x) " " #x " "
# ifdef CONFIG_X86_64
#  define __ASM_SIZE(inst) ____ASM_FORM(inst##q)
# else
#  define __ASM_SIZE(inst) ____ASM_FORM(inst##l)
# endif
#endif

#ifndef _ASM_PTR
# ifdef CONFIG_X86_64
#  define _ASM_PTR ".quad"
# else
#  define _ASM_PTR ".long"
# endif
#endif

/* Intel VT MSRs */
#ifndef MSR_IA32_VMX_BASIC
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#endif

#ifndef MSR_IA32_FEATURE_CONTROL
#define MSR_IA32_FEATURE_CONTROL        0x0000003a

#define FEATURE_CONTROL_LOCKED		(1<<0)
#define FEATURE_CONTROL_VMXON_ENABLED	(1<<2)
#endif

#ifndef FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX	(1<<1)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1<<2)
#endif

#ifndef MSR_IA32_TSC
#define MSR_IA32_TSC                    0x00000010
#endif

#ifndef MSR_K7_HWCR
#define MSR_K7_HWCR                     0xc0010015
#endif

#ifndef MSR_K8_SYSCFG
#define MSR_K8_SYSCFG                   0xc0010010
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25) && defined(__x86_64__)

#undef set_debugreg
#define set_debugreg(value, register) \
	__asm__("movq %0,%%db" #register \
		: /* no output */ \
		:"r" ((unsigned long)value))

#endif

#if !defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define kvm_compat_debugreg(x) debugreg[x]
#else
#define kvm_compat_debugreg(x) debugreg##x
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)

struct mtrr_var_range {
	u32 base_lo;
	u32 base_hi;
	u32 mask_lo;
	u32 mask_hi;
};

/* In the Intel processor's MTRR interface, the MTRR type is always held in
   an 8 bit field: */
typedef u8 mtrr_type;

#define MTRR_NUM_FIXED_RANGES 88
#define MTRR_MAX_VAR_RANGES 256

struct mtrr_state_type {
	struct mtrr_var_range var_ranges[MTRR_MAX_VAR_RANGES];
	mtrr_type fixed_ranges[MTRR_NUM_FIXED_RANGES];
	unsigned char enabled;
	unsigned char have_fixed;
	mtrr_type def_type;
};

#endif

#ifndef CONFIG_HAVE_KVM_IRQCHIP
#define CONFIG_HAVE_KVM_IRQCHIP 1
#endif

#include <asm/mce.h>

#ifndef MCG_CTL_P
#define MCG_CTL_P        (1ULL<<8)
#define MCG_STATUS_MCIP  (1ULL<<2)
#define MCI_STATUS_VAL   (1ULL<<63)
#define MCI_STATUS_OVER  (1ULL<<62)
#define MCI_STATUS_UC    (1ULL<<61)
#endif

/* do_machine_check() exported in 2.6.31 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

static inline void kvm_do_machine_check(struct pt_regs *regs, long error_code)
{
	panic("kvm machine check!\n");
}

#else

#define kvm_do_machine_check do_machine_check

#endif

/* pt_regs.flags was once pt_regs.eflags */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define kvm_pt_regs_flags eflags

#  ifdef CONFIG_X86_64
#    define kvm_pt_regs_cs cs
#  else
#    define kvm_pt_regs_cs xcs
#  endif

#else

#define kvm_pt_regs_flags flags
#define kvm_pt_regs_cs cs

#endif

/* boot_cpu_data.x86_phys_bits only appeared for i386 in 2.6.30 */

#if !defined(CONFIG_X86_64) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))

#define kvm_x86_phys_bits 40

#else

#define kvm_x86_phys_bits (boot_cpu_data.x86_phys_bits)

#endif

#include <asm/apicdef.h>

#ifndef APIC_BASE_MSR
#define APIC_BASE_MSR    0x800
#endif

#ifndef APIC_SPIV_DIRECTED_EOI
#define APIC_SPIV_DIRECTED_EOI          (1 << 12)
#endif

#ifndef APIC_LVR_DIRECTED_EOI
#define APIC_LVR_DIRECTED_EOI   (1 << 24)
#endif

#ifndef APIC_SELF_IPI
#define APIC_SELF_IPI    0x3F0
#endif

#ifndef X2APIC_ENABLE
#define X2APIC_ENABLE    (1UL << 10)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) && KERNEL_EXTRAVERSION < 16)
#define kvm_tboot_enabled()	0
#else
#define kvm_tboot_enabled	tboot_enabled
#endif

#ifndef MSR_AMD64_DC_CFG
#define MSR_AMD64_DC_CFG		0xc0011022
#endif

#ifndef MSR_IA32_MCx_STATUS
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24) && defined(CONFIG_X86_64)
#define savesegment(seg, value)				\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24) && defined(CONFIG_X86_64)
#define kvm_check_tsc_unstable()	1
#else
#define kvm_check_tsc_unstable		check_tsc_unstable
#endif

#ifdef CONFIG_X86_64
static inline void kvm_set_64bit(unsigned long *ptr, u64 val)
#else
static inline void kvm_set_64bit(unsigned long long *ptr, u64 val)
#endif
{
	unsigned int low = val;
	unsigned int high = val >> 32;

	__asm__ __volatile__ (
		"\n1:\t"
		"movl (%0), %%eax\n\t"
		"movl 4(%0), %%edx\n\t"
		"lock cmpxchg8b (%0)\n\t"
		"jnz 1b"
		: /* no outputs */
		:	"D"(ptr),
			"b"(low),
			"c"(high)
		:	"ax","dx","memory");
}
