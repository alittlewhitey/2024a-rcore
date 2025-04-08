//! Implementation of [`TrapContext`]
use riscv::register::sstatus::{self, Sstatus, SPP};

use super::trap_loop;

#[repr(C)]
#[derive(Debug,Clone)]
///trap context structure containing sstatus, sepc and registers
pub struct TrapContext {
    /// General-Purpose Register x0-31
    pub x: [usize; 32],
    /// Supervisor Status Register
    pub sstatus: Sstatus,
    /// Supervisor Exception Program Counter
    pub sepc: usize,
    /// Kernel stack pointer of the current application
    pub kernel_sp: usize,

    /// trap_loop 
    pub kernel_ra :usize,
    /// s registers
    pub kernel_s: [usize; 12], // 36 - 47
   
    /// float regs 51-82, fcsr 83
    pub kernel_fp: usize,      // 48
    /// kernel hart address
    pub kernel_tp: usize, // 49
    /// A copy of register a0, useful when we need to restart syscall
    pub origin_a0: usize, // 50
    /// float regs 51-82, fcsr 83
    pub fp: [usize; 32], // 51-82
    /// floating-point control and status register
    pub fcsr: usize, // 83
}

impl TrapContext {
    /// put the sp(stack pointer) into x\[2\] field of TrapContext
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    /// init the trap context of an application
    pub fn app_init_context(
        entry: usize,
        sp: usize,
        kernel_sp: usize,
    ) -> Self {
        let mut sstatus = sstatus::read();
        // set CPU privilege to User after trapping back
        sstatus.set_spp(SPP::User);

        trace!("read Sstaus in app_init_trapcontext,{:#?}",sstatus.bits());
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry,  // entry point of app
          
            kernel_ra: trap_loop as usize,

            kernel_sp,    // kernel stack
            kernel_s: [0; 12],
            kernel_fp: 0,
            kernel_tp: 0,
            origin_a0: 0,
            fp: [0; 32],
            fcsr: 0,
        
        };
        cx.set_sp(sp); // app's user stack pointer
        cx // return initial Trap Context of app
    }
}
