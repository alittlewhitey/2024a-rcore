use core::arch::global_asm;
use riscv::register::{
    mstatus::FS,
    mtvec::TrapMode,
    sie, sstatus, stvec,
    scause::{self ,Trap, Scause},
    stval, sepc, satp,
   
};
use riscv::interrupt::{Exception, Interrupt};
use super::super::TrapArch;

global_asm!(include_str!("trap.S"));

extern "C" {
    fn trap_vector_base();
}

pub struct RiscV64Trap;

impl TrapArch for RiscV64Trap {
    type Scause = Scause;
    type Exception = Exception;
    type Interrupt = Interrupt;
    
    fn init_trap() {
        Self::set_trap_vector();
        unsafe {
            sstatus::set_fs(FS::Clean);
        }
    }
    
    fn set_trap_vector() {
        unsafe {
            
            let mut stvec = stvec::Stvec::from_bits(0);
            stvec.set_address(trap_vector_base as usize);
            stvec.set_trap_mode(stvec::TrapMode::Direct);
            stvec::write(stvec);
        }
    }
    
    fn enable_irqs() {
        unsafe {
            sie::set_stimer();
        }
    }
    
    fn disable_irqs() {
        unsafe {
            sie::clear_stimer();
        }
    }
    
    fn enable_kernel_irqs() {
        unsafe { 
            sstatus::set_sie() 
        }
    }
    
    fn disable_kernel_irqs() {
        unsafe { 
            sstatus::clear_sie() 
        }
    }
    
    fn wait_for_irqs() {
        unsafe {
            riscv::asm::wfi()
        }
    }
    
    fn set_sum() {
        unsafe { 
            sstatus::set_sum() 
        };
    }
    
    fn read_scause() -> Self::Scause {
        scause::read()
    }
    
    fn read_stval() -> usize {
        stval::read()
    }
    
    fn read_sepc() -> usize {
        sepc::read()
    }
    
    fn read_satp() -> usize {
        satp::read().bits()
    }
    
   
    
  
    fn syscall_instruction_len() -> usize { 4 }
}
