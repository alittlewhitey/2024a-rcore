//! Constants in the kernel

#[allow(unused)]

/// user app's stack size
pub const USER_STACK_SIZE: usize = 1024 * 16;
/// kernel stack size
pub const KERNEL_STACK_SIZE: usize = 4096 * 16;
/// kernel heap size
pub const KERNEL_HEAP_SIZE: usize = 0x100_0000;
///于allocuserres中于分配页数
pub const PRE_ALLOC_PAGES: usize = 8;
/// page size : 4KB
pub const PAGE_SIZE: usize = 0x1000;
/// page size bits: 12
pub const PAGE_SIZE_BITS: usize = 0xc;
/// the max number of syscall
pub const MAX_SYSCALL_NUM: usize = 500;
/// the virtual addr of trapoline
pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
/// clock frequency
pub const CLOCK_FREQ: usize = 12500000;
/// the physical memory end
pub const MEMORY_END: usize = 0x13fffffff +  KERNEL_DIRECT_OFFSET;
/// The base address of control registers in Virtio_Block device
pub const MMIO: &[(usize, usize)] = &[(0x10001000, 0x1000)];
/// Kerneladress offset
pub const KERNEL_DIRECT_OFFSET: usize = 0xffff_ffc0_0000_0000;
/// When directly map: vpn = ppn + kernel direct offset
pub const KERNEL_PGNUM_OFFSET: usize = KERNEL_DIRECT_OFFSET >> PAGE_SIZE_BITS;
/// 定义用户堆的大小，  4MB
pub const USER_HEAP_SIZE: usize = 0x400_0000;
/// 定义协程堆栈的大小，  4MB
pub const TASK_STACK_SIZE: usize=0x40000;
/// 定义用户空间的总大小，48GB
pub const USER_SPACE_SIZE: usize = 0x30_0000_0000;
/// 定义最大线程数，3000
pub const THREAD_MAX_NUM: usize = 3000;
/// User Space layout
/// TrapContext GuardPage Stack GuardPage Mmap Heap Elf
/// 定义用户空间布局的顶部地址，即用户空间的起始地址
pub const USER_TRAP_CONTEXT_TOP: usize = USER_SPACE_SIZE;

/// 定义用户栈的顶部地址
/// 用户栈的顶部地址是用户空间布局的顶部地址减去线程最大数乘以页面大小
pub const USER_STACK_TOP: usize = USER_TRAP_CONTEXT_TOP - PAGE_SIZE * THREAD_MAX_NUM;

/// 定义内存映射（Mmap）区域的顶部地址
/// 内存映射区域的顶部地址也是用户空间布局的顶部地址减去线程最大数乘以页面大小
pub const MMAP_TOP: usize = USER_TRAP_CONTEXT_TOP
    - PAGE_SIZE * THREAD_MAX_NUM
    - USER_STACK_SIZE * THREAD_MAX_NUM
    - PAGE_SIZE;
/// Kernel Stack Start
pub const KSTACK_TOP: usize = usize::MAX - PAGE_SIZE + 1;
///temp data
pub const IS_ASYNC: usize = 0x5f5f5f5f;