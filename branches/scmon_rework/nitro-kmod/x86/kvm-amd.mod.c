#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x42cca074, "module_layout" },
	{ 0xfba6df8b, "alloc_pages_current" },
	{ 0x1523f3fe, "kmalloc_caches" },
	{ 0x39c54477, "kvm_mmu_load" },
	{ 0x4db118ec, "kvm_release_page_dirty" },
	{ 0x5102cf94, "__tracepoint_kvm_nested_vmexit_inject" },
	{ 0xa90c928a, "param_ops_int" },
	{ 0x340e77f2, "kvm_set_msr_common" },
	{ 0x49506237, "kvm_mmu_invlpg" },
	{ 0x251f571e, "kvm_vcpu_init" },
	{ 0x6cad4c34, "boot_cpu_data" },
	{ 0x48ed8464, "kvm_emulate_cpuid" },
	{ 0x22e40f0, "__tracepoint_kvm_exit" },
	{ 0x5598d38f, "is_error_page" },
	{ 0x10359887, "kvm_queue_exception_e" },
	{ 0xe9818b32, "kvm_read_guest" },
	{ 0xc0a3d105, "find_next_bit" },
	{ 0x4aabc7c4, "__tracepoint_kmalloc" },
	{ 0x1adfd455, "kvm_vcpu_on_spin" },
	{ 0xa2a272c4, "kvm_mmu_unload" },
	{ 0xf4983863, "kvm_mmu_reset_context" },
	{ 0xa722a819, "cpu_has_amd_erratum" },
	{ 0x79254016, "kvm_mmu_page_fault" },
	{ 0x47c7b0d2, "cpu_number" },
	{ 0x288873c9, "__tracepoint_kvm_nested_intercepts" },
	{ 0x56869095, "__tracepoint_kvm_invlpga" },
	{ 0xf7ca55ae, "kvm_set_cr8" },
	{ 0x35adbf3b, "kvm_set_cr0" },
	{ 0x7023960f, "kvm_get_cs_db_l_bits" },
	{ 0x85e2e68, "kvm_release_page_clean" },
	{ 0xfe7c4287, "nr_cpu_ids" },
	{ 0x24cd7a8b, "kvm_mmu_unprotect_page_virt" },
	{ 0xbd86163a, "kvm_handle_fault_on_reboot" },
	{ 0xba97c396, "load_pdptrs" },
	{ 0x4d138ff0, "kmem_cache_alloc_notrace" },
	{ 0x9227f4b3, "__tracepoint_kvm_skinit" },
	{ 0x831a4a94, "kvm_write_tsc" },
	{ 0x161dbc76, "current_task" },
	{ 0xea147363, "printk" },
	{ 0x29444f0, "native_read_tsc" },
	{ 0x406813bc, "__tracepoint_kvm_msr" },
	{ 0x546f78f4, "kvm_emulate_hypercall" },
	{ 0x3cb6f890, "kvm_vcpu_cache" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x1b00316d, "kvm_is_linear_rip" },
	{ 0xb4390f9a, "mcount" },
	{ 0x870ea1b7, "kvm_x86_ops" },
	{ 0x34b6d5, "kvm_get_cr8" },
	{ 0xd837d82d, "kmem_cache_free" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x5a358eba, "kvm_set_cr3" },
	{ 0x328a8b26, "kvm_cpu_has_interrupt" },
	{ 0x99905e08, "__tracepoint_kvm_inj_virq" },
	{ 0xcecd28b4, "__tracepoint_kvm_page_fault" },
	{ 0xa8039c29, "fx_init" },
	{ 0x552b4da5, "__tracepoint_kvm_nested_intr_vmexit" },
	{ 0x9e1876d6, "kmem_cache_alloc" },
	{ 0x78764f4e, "pv_irq_ops" },
	{ 0x17eb42b8, "__free_pages" },
	{ 0xf888700, "emulate_instruction" },
	{ 0xe69e427b, "kvm_queue_exception" },
	{ 0xb2e55898, "cpu_possible_mask" },
	{ 0xd2f1b59a, "kvm_init_shadow_mmu" },
	{ 0x3d9ee9f0, "clear_page" },
	{ 0x86187982, "kvm_requeue_exception_e" },
	{ 0xab0260a9, "pv_cpu_ops" },
	{ 0xaaf935, "kvm_disable_tdp" },
	{ 0x8ce4f3ab, "kvm_enable_tdp" },
	{ 0xf0f891e0, "kvm_task_switch" },
	{ 0xc5844fb8, "__per_cpu_offset" },
	{ 0xe52947e7, "__phys_addr" },
	{ 0x5affceb8, "__tracepoint_kvm_nested_vmrun" },
	{ 0xb98d596e, "kvm_emulate_halt" },
	{ 0xf65907b1, "kvm_vcpu_uninit" },
	{ 0x37a0cba, "kfree" },
	{ 0x1bee93fe, "kvm_get_msr_common" },
	{ 0xf4c9d7c2, "pv_mmu_ops" },
	{ 0x6128b5fc, "__printk_ratelimit" },
	{ 0x3d9d0520, "gfn_to_page" },
	{ 0xceeaa13, "kvm_fast_pio_out" },
	{ 0x317f9e6b, "kvm_enable_efer_bits" },
	{ 0xd7be16af, "__tracepoint_kvm_nested_vmexit" },
	{ 0x714e6f8, "kvm_init" },
	{ 0x7a7c5175, "amd_erratum_383" },
	{ 0x27046576, "kvm_exit" },
	{ 0x3d9a22e7, "kvm_requeue_exception" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=kvm";


MODULE_INFO(srcversion, "E7A2D714BEFF6FC169CF9B0");
