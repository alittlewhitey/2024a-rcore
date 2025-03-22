.section .text.entry
.globl _start
_start:
    # set sp (use a fixed stack since no multi-core)
    la sp, boot_stack_top

    # set up page table for high address mapping
    # satp: 8 << 60 | boot_pagetable
    la t0, boot_pagetable
    li t1, 8 << 60
    srli t0, t0, 12
    or t0, t0, t1
    csrw satp, t0
    sfence.vma

    call setbootsp

.section .bss.stack

.globl boot_stack_lower_bound
boot_stack_lower_bound:
    .space 4096 * 8  # Use one stack for single core, 8 CPUS removed

.globl boot_stack_top
boot_stack_top:

.section .data
.align 12
boot_pagetable:
    # Set up page table with high address mapping (e.g., 0xffff_ffc0_0000_0000 -> 0x80000000)
    .quad 0
    .quad 0
    .quad (0x80000 << 10) | 0xcf  # VRWXAD permissions for high addresses
    .zero 8 * 255
    .quad (0x80000 << 10) | 0xcf  # VRWXAD permissions for high addresses
    .zero 8 * 253

.section .text.trampoline
.align 12

    ecall