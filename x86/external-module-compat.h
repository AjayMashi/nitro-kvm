
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

#ifndef CONFIG_KVM_MMIO
#define CONFIG_KVM_MMIO
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

#ifndef MSR_KERNEL_GS_BASE
#define MSR_KERNEL_GS_BASE              0xc0000102
#endif

#ifndef MSR_TSC_AUX
#define MSR_TSC_AUX                     0xc0000103
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

#ifndef X86_FEATURE_PCLMULQDQ
#define X86_FEATURE_PCLMULQDQ	(4*32+ 1) /* PCLMULQDQ instruction */
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

#ifndef X86_FEATURE_AVX
#define X86_FEATURE_AVX		(4*32+28) /* Advanced Vector Extensions */
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

#ifndef X86_CR4_OSXSAVE
#define X86_CR4_OSXSAVE 0x00040000
#endif

#undef X86_CR8_TPR
#define X86_CR8_TPR 0x0f

#ifndef CONFIG_PREEMPT_NOTIFIERS

#ifdef CONFIG_HAVE_HW_BREAKPOINT
#error Preemption notifier emulation does not work for this kernel.
#endif

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

#include <asm/cpufeature.h>

#ifndef X86_FEATURE_NX
#define X86_FEATURE_NX		(1*32+20)
#endif

#ifndef X86_FEATURE_XSAVE
#define X86_FEATURE_XSAVE	(4*32+26)
#endif

#ifndef X86_FEATURE_OSXSAVE
#define X86_FEATURE_OSXSAVE	(4*32+27)
#endif

#ifndef cpu_has_xsave
#define cpu_has_xsave boot_cpu_has(X86_FEATURE_XSAVE)
#endif

/* EFER_LMA and EFER_LME are missing in pre 2.6.24 i386 kernels */
#ifndef EFER_LME
#define _EFER_LME           8  /* Long mode enable */
#define _EFER_LMA           10 /* Long mode active (read-only) */
#define EFER_LME            (1<<_EFER_LME)
#define EFER_LMA            (1<<_EFER_LMA)
#endif

#ifndef EFER_LMSLE
#define _EFER_LMSLE		13 /* Long Mode Segment Limit Enable */
#define EFER_LMSLE		(1<<_EFER_LMSLE)
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

static inline unsigned long
kvm_get_desc_base(const struct kvm_desc_struct *desc)
{
	return (unsigned)(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline void
kvm_set_desc_base(struct kvm_desc_struct *desc, unsigned long base)
{
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = (base >> 24) & 0xff;
}

static inline unsigned long
kvm_get_desc_limit(const struct kvm_desc_struct *desc)
{
	return desc->limit0 | (desc->limit << 16);
}

static inline void
kvm_set_desc_limit(struct kvm_desc_struct *desc, unsigned long limit)
{
	desc->limit0 = limit & 0xffff;
	desc->limit = (limit >> 16) & 0xf;
}

static inline void kvm_load_gdt(const struct kvm_desc_ptr *dtr)
{
	asm volatile("lgdt %0"::"m" (*dtr));
}

#define kvm_store_gdt	kvm_native_store_gdt

static inline void kvm_native_store_gdt(struct kvm_desc_ptr *dtr)
{
	asm volatile("sgdt %0":"=m" (*dtr));
}

static inline void kvm_native_store_idt(struct kvm_desc_ptr *dtr)
{
	asm volatile("sidt %0":"=m" (*dtr));
}

#include <asm/msr.h>
#ifndef MSR_FS_BASE
#define MSR_FS_BASE 0xc0000100
#endif
#ifndef MSR_GS_BASE
#define MSR_GS_BASE 0xc0000101
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

#ifndef MCG_SER_P
#define MCG_SER_P	 	(1ULL<<24)   /* MCA recovery/new status bits */
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

static inline int hw_breakpoint_active(void)
{
	return test_thread_flag(TIF_DEBUG);
}

static inline void hw_breakpoint_restore(void)
{
	set_debugreg(current->thread.kvm_compat_debugreg(0), 0);
	set_debugreg(current->thread.kvm_compat_debugreg(1), 1);
	set_debugreg(current->thread.kvm_compat_debugreg(2), 2);
	set_debugreg(current->thread.kvm_compat_debugreg(3), 3);
	set_debugreg(current->thread.kvm_compat_debugreg(6), 6);
	set_debugreg(current->thread.kvm_compat_debugreg(7), 7);
}

#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24) && defined(CONFIG_X86_64)
#define kvm_check_tsc_unstable()	1
#else
#define kvm_check_tsc_unstable		check_tsc_unstable
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define percpu_read(t)		__get_cpu_var(t)
#define percpu_write(t, v)	__get_cpu_var(t) = v
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) && \
     KERNEL_EXTRAVERSION < 16) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,33) && \
     KERNEL_EXTRAVERSION < 6) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,34) && \
     KERNEL_EXTRAVERSION < 1)
#define kvm_tboot_enabled()	0
#else
#define kvm_tboot_enabled	tboot_enabled
#define KVM_TBOOT_ENABLED_WORKS	1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
struct kvm_pvclock_vcpu_time_info {
	u32   version;
	u32   pad0;
	u64   tsc_timestamp;
	u64   system_time;
	u32   tsc_to_system_mul;
	s8    tsc_shift;
	u8    flags;
	u8    pad[2];
} __attribute__((__packed__)); /* 32 bytes */
#else
#define kvm_pvclock_vcpu_time_info	pvclock_vcpu_time_info
#endif

#ifndef MSR_AMD64_DC_CFG
#define MSR_AMD64_DC_CFG		0xc0011022
#endif

#ifndef MSR_IA32_MCx_STATUS
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#endif

#include <asm/i387.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
struct kvm_i387_fxsave_struct {
	u16	cwd;
	u16	swd;
	u16	twd;
	u16	fop;
	u64	rip;
	u64	rdp;
	u32	mxcsr;
	u32	mxcsr_mask;
	u32	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
#ifdef CONFIG_X86_64
	u32	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
#else
	u32	xmm_space[32];	/* 8*16 bytes for each XMM-reg = 128 bytes */
#endif
} __aligned(16);

struct kvm_ymmh_struct {
	/* 16 * 16 bytes for each YMMH-reg = 256 bytes */
	u32 ymmh_space[64];
};

struct kvm_xsave_hdr_struct {
	u64 xstate_bv;
	u64 reserved1[2];
	u64 reserved2[5];
} __attribute__((packed));

struct kvm_xsave_struct {
	struct kvm_i387_fxsave_struct i387;
	struct kvm_xsave_hdr_struct xsave_hdr;
	struct kvm_ymmh_struct ymmh;
	/* new processor state extensions will go here */
} __attribute__ ((packed, aligned (64)));

union kvm_thread_xstate {
	struct kvm_i387_fxsave_struct fxsave;
	struct kvm_xsave_struct xsave;
};

#else /* >= 2.6.35 */

#define kvm_i387_fxsave_struct	i387_fxsave_struct
#define kvm_xsave_struct	xsave_struct
#define kvm_thread_xstate	thread_xstate

#endif /* >= 2.6.35 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

struct kvm_compat_fpu {
	union kvm_thread_xstate state_buffer;
	union kvm_thread_xstate *state;
};

static inline int kvm_fpu_alloc(struct kvm_compat_fpu *fpu)
{
	fpu->state = &fpu->state_buffer;
	return 0;
}

static inline void kvm_fpu_free(struct kvm_compat_fpu *fpu)
{
}

static inline void kvm_fx_save(struct kvm_i387_fxsave_struct *image)
{
	asm("fxsave (%0)":: "r" (image));
}

static inline void kvm_fx_restore(struct kvm_i387_fxsave_struct *image)
{
	asm("fxrstor (%0)":: "r" (image));
}

static inline void kvm_fx_finit(void)
{
	asm("finit");
}

static inline void kvm_fpu_finit(struct kvm_compat_fpu *fpu)
{
	unsigned after_mxcsr_mask;

	preempt_disable();
	kvm_fx_finit();
	kvm_fx_save(&fpu->state->fxsave);
	preempt_enable();

	after_mxcsr_mask = offsetof(struct kvm_i387_fxsave_struct, st_space);
	fpu->state->fxsave.mxcsr = 0x1f80;
	memset((void *)&fpu->state->fxsave + after_mxcsr_mask,
	       0, sizeof(struct kvm_i387_fxsave_struct) - after_mxcsr_mask);
}

static inline int kvm_fpu_restore_checking(struct kvm_compat_fpu *fpu)
{
	kvm_fx_restore(&fpu->state->fxsave);
	return 0;
}

static inline void kvm_fpu_save_init(struct kvm_compat_fpu *fpu)
{
	kvm_fx_save(&fpu->state->fxsave);
}

extern unsigned int kvm_xstate_size;

void kvm_xstate_size_init(void);

#else /* >= 2.6.36 */

#define kvm_compat_fpu			fpu
#define kvm_fpu_alloc			fpu_alloc
#define kvm_fpu_free			fpu_free
#define kvm_fpu_restore_checking	fpu_restore_checking
#define kvm_fpu_save_init		fpu_save_init
#define kvm_fpu_finit			fpu_finit

#define kvm_xstate_size			xstate_size

static inline void kvm_xstate_size_init(void)
{
}

#endif /* >= 2.6.36 */

#ifndef XSTATE_FP
#define XSTATE_FP       0x1
#define XSTATE_SSE      0x2
#define XSTATE_FPSSE    (XSTATE_FP | XSTATE_SSE)
#endif

#ifndef XSTATE_YMM
#define XSTATE_YMM      0x4
#endif

#ifndef XSAVE_HDR_OFFSET
#define XSAVE_HDR_OFFSET    512
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#define kvm_cpu_has_xsave	0
#else /* >= 2.6.28 */
#define kvm_cpu_has_xsave	cpu_has_xsave
#endif /* >= 2.6.28 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

#ifndef AMD_OSVW_ERRATUM
#define AMD_OSVW_ERRATUM(osvw_id, ...)	{ osvw_id, __VA_ARGS__, 0 }
#endif

#ifndef AMD_MODEL_RANGE
#define AMD_MODEL_RANGE(f, m_start, s_start, m_end, s_end) \
	((f << 24) | (m_start << 16) | (s_start << 12) | (m_end << 4) | (s_end))
#define AMD_MODEL_RANGE_FAMILY(range)	(((range) >> 24) & 0xff)
#define AMD_MODEL_RANGE_START(range)	(((range) >> 12) & 0xfff)
#define AMD_MODEL_RANGE_END(range)	((range) & 0xfff)
#endif

#ifndef X86_FEATURE_OSVW
#define X86_FEATURE_OSVW	(6*32+ 9) /* OS Visible Workaround */
#endif

#ifndef MSR_AMD64_OSVW_ID_LENGTH
#define MSR_AMD64_OSVW_ID_LENGTH	0xc0010140
#define MSR_AMD64_OSVW_STATUS		0xc0010141
#endif

extern const int kvm_amd_erratum_383[];

static inline bool kvm_cpu_has_amd_erratum(const int *erratum)
{
	struct cpuinfo_x86 *cpu = &current_cpu_data;
	int osvw_id = *erratum++;
	u32 range;
	u32 ms;

	/*
	 * If called early enough that current_cpu_data hasn't been initialized
	 * yet, fall back to boot_cpu_data.
	 */
	if (cpu->x86 == 0)
		cpu = &boot_cpu_data;

	if (cpu->x86_vendor != X86_VENDOR_AMD)
		return false;

	if (osvw_id >= 0 && osvw_id < 65536 &&
	    cpu_has(cpu, X86_FEATURE_OSVW)) {
		u64 osvw_len;

		rdmsrl(MSR_AMD64_OSVW_ID_LENGTH, osvw_len);
		if (osvw_id < osvw_len) {
			u64 osvw_bits;

			rdmsrl(MSR_AMD64_OSVW_STATUS + (osvw_id >> 6),
			    osvw_bits);
			return osvw_bits & (1ULL << (osvw_id & 0x3f));
		}
	}

	/* OSVW unavailable or ID unknown, match family-model-stepping range */
	ms = (cpu->x86_model << 4) | cpu->x86_mask;
	while ((range = *erratum++))
		if ((cpu->x86 == AMD_MODEL_RANGE_FAMILY(range)) &&
		    (ms >= AMD_MODEL_RANGE_START(range)) &&
		    (ms <= AMD_MODEL_RANGE_END(range)))
			return true;

	return false;
}

#else /* >= 2.6.36 */

#define kvm_cpu_has_amd_erratum	cpu_has_amd_erratum
#define kvm_amd_erratum_383	amd_erratum_383

#endif /* >= 2.6.36 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
static inline u64 pvclock_scale_delta(u64 delta, u32 mul_frac, int shift)
{
	u64 product;
#ifdef __i386__
	u32 tmp1, tmp2;
#endif

	if (shift < 0)
		delta >>= -shift;
	else
		delta <<= shift;

#ifdef __i386__
	__asm__ (
		"mul  %5       ; "
		"mov  %4,%%eax ; "
		"mov  %%edx,%4 ; "
		"mul  %5       ; "
		"xor  %5,%5    ; "
		"add  %4,%%eax ; "
		"adc  %5,%%edx ; "
		: "=A" (product), "=r" (tmp1), "=r" (tmp2)
		: "a" ((u32)delta), "1" ((u32)(delta >> 32)), "2" (mul_frac) );
#elif defined(__x86_64__)
	__asm__ (
		"mul %%rdx ; shrd $32,%%rdx,%%rax"
		: "=a" (product) : "0" (delta), "d" ((u64)mul_frac) );
#else
#error implement me!
#endif

	return product;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34) && \
    LINUX_VERSION_CODE != KERNEL_VERSION(2,6,32) && defined(CONFIG_X86_64)
#define kvm_set_64bit(ptr, val)	set_64bit((unsigned long *)ptr, val)
#else
#define kvm_set_64bit		set_64bit
#endif

#ifndef MSR_EBC_FREQUENCY_ID
#define MSR_EBC_FREQUENCY_ID	0x0000002c
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24) && defined(CONFIG_X86_64)
#define savesegment(seg, value)				\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")
#endif
