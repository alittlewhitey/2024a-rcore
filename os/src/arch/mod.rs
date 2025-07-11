cfg_if::cfg_if! {
    if #[cfg(target_arch = "riscv64")] {
        mod riscv64;
        pub use riscv64::*;
        pub use riscv64::trap::RiscV64Trap as CurrentTrap;
        pub type Exception = riscv::interrupt::supervisor::Exception;
        pub fn root_page_addr()->usize{
         0
        }
        pub type Interrupt = riscv::interrupt::supervisor::Interrupt;
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64;
        pub use loongarch64::*;
        pub use loongarch64::trap::LoongArch64Trap as CurrentTrap;     
        pub type Exception = loongArch64::register::estat::Exception;
        pub type Interrupt = loongArch64::register::estat::Interrupt;
         pub fn root_page_addr()->usize{
          loongArch64::register::pgdl::read().raw()
        }
    } else {
        compile_error!("Unsupported target architecture");
    }
}

pub trait ArchInit {
    fn arch_init();
    fn set_boot_stack();
    fn jump_to_rust_main() -> !;
}

pub trait TrapArch {
    type Scause;
    type Exception;
    type Interrupt;
    
    fn init_trap();
    fn set_trap_vector();
    fn enable_irqs();
    fn disable_irqs();
    fn enable_kernel_irqs();
    fn disable_kernel_irqs();
    fn wait_for_irqs();
    fn set_sum();
    fn read_scause() -> Self::Scause;
    fn read_stval() -> usize;
    fn read_sepc() -> usize;
    fn read_satp() -> usize;
 
    fn syscall_instruction_len() -> usize;
}