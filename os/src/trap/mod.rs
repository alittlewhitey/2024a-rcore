//! Trap handling functionality
//!
//! For rCore, we have a single trap entry point, namely `__alltraps`. At
//! initialization in [`init()`], we set the `stvec` CSR to point to it.
//!
//! All traps go through `__alltraps`, which is defined in `trap.S`. The
//! assembly language code does just enough work restore the kernel space
//! context, ensuring that Rust code safely runs, and transfers control to
//! [`trap_handler()`].
//!
//! It then calls different functionality based on what exactly the exception
//! was. For example, timer interrupts trigger task preemption, and syscalls go
//! to [`syscall()`].
// use crate::mm::activate_kernel_space;
//use crate::config:: TRAP_CONTEXT_BASE;

mod context;
use crate::syscall:: syscall;
use crate::task::{
    current_task, current_task_trapctx_ptr, exit_current_and_run_next, pick_next_task, run_task2, suspend_current_and_run_next, CurrentTask
};
pub use context::user_return;
use alloc::sync::Arc;
pub use context::TrapStatus;
use crate::utils::backtrace;
use crate::timer::set_next_trigger;
use core::arch:: global_asm;
use core::future::poll_fn;
use core::panic;
use core::task::Poll;
use riscv::register::{satp, sepc, sstatus};
use riscv::register::{
    mtvec::TrapMode,
    scause::{self, Exception, Interrupt, Trap},
    sie, stval, stvec,
    mstatus::FS,
};
global_asm!(include_str!("trap.S"));

/// Initialize trap handling
pub fn init() {
    set_trap_entry();
    unsafe {
        sstatus::set_fs(FS::Clean);
    }
}

extern "C" {
    fn trap_vector_base();
}

fn set_trap_entry(){
    unsafe {
        stvec::write(trap_vector_base as usize, TrapMode::Direct);
    }
}
// fn set_kernel_trap_entry() {
//     unsafe {
//         stvec::write(trap_from_kernel as usize, TrapMode::Direct);
//     }

//         trace!("stvec_kernel:{:#x},true adress :{:#x}",stvec::read().bits(),trap_from_kernel as usize);
// }

// fn set_user_trap_entry() {
//     unsafe {
//         stvec::write(__trap_from_user as usize, TrapMode::Direct);
//     }

//         trace!("stvec_user:{:#x},true adress :{:#x}",stvec::read().bits(),__trap_from_user as usize);
// }

/// enable timer interrupt in supervisor mode
pub fn enable_timer_interrupt() {
    unsafe {
        sie::set_stimer();
    }
}
/// disable timer interrupt in supervisor mode
pub fn disable_timer_interrupt() {
    unsafe {
        sie::clear_stimer();
    }
}
/// 开启全局中断（允许响应中断）
#[inline]
pub fn enable_irqs() {
    unsafe { sstatus::set_sie() }
}

///  关闭全局中断（允许响应中断）.
#[inline]
pub fn disable_irqs() {
    unsafe { sstatus::clear_sie() }
}
/// Relaxes the current CPU and waits for interrupts.
///
/// It must be called with interrupts enabled, otherwise it will never return.
#[inline]
pub fn wait_for_irqs() {
    unsafe { riscv::asm::wfi() }
}




    
    

///方便调试
#[no_mangle]
pub fn trap_loop() {
    loop {
        trap_return();
       
    }
}
#[no_mangle]
/// return to user space

pub fn trap_return()   {
    // set_user_trap_entry();
    // let trap_cx_ptr = TRAP_CONTEXT_BASE;
    // let user_satp = current_user_token();
    // extern "C" {
    //     fn __alltraps();
    //     fn __restore();
    // }
    // let restore_va = __restore as usize - __alltraps as usize ;
    // // trace!("[kernel] trap_return: ..before return");
    // unsafe {
    //     asm!(
    //         "fence.i",
    //         "jr {restore_va}",
    //         restore_va = in(reg) restore_va,
    //         in("a0") trap_cx_ptr,
    //         in("a1") user_satp,
    //         options(noreturn)
    //     );
    // }
    extern "C" {
        #[allow(improper_ctypes)]
        fn __return_to_user(cx: *mut TrapContext);
    }
}

#[no_mangle]
/// handle trap from kernel
/// Unimplement: traps/interrupts/exceptions from kernel mode
/// Todo: Chapter 9: I/O device
#[link_section = ".text.trap_entries"]

pub fn trap_from_kernel() {
    backtrace();
    let stval = stval::read();
    let sepc = sepc::read();
    // let stval_vpn = VirtPageNum::from(stval);
    // let sepc_vpn = VirtPageNum::from(sepc);
    panic!(
        "stval = {:#x}, sepc = {:#x},
        a trap {:?} from kernel",
        stval,
        
        sepc,
        
        scause::read().cause()
    );
}

pub use context::TrapContext;
/// 进入 Trampoline 的方式：
///   1. 初始化后函数调用：没有 Trap，但存在就绪任务
///   2. 内核发生 Trap：存在任务被打断（CurrentTask 不为空），或者没有任务被打断（CurrentTask 为空）
///   3. 用户态发生 Trap：任务被打断，CurrentTask 不为空
///
/// 内核发生 Trap 时，将 TrapFrame 保存在内核栈上
/// 在用户态发生 Trap 时，将 TrapFrame 直接保存在任务控制块中，而不是在内核栈上
///
/// 只有通过 trap 进入这个入口时，是处于关中断的状态，剩下的任务切换是没有关中断
#[no_mangle]
pub fn trampoline(_tc: &mut TrapContext, has_trap: bool, from_user: bool) {
    loop {
        if !from_user && has_trap {
            // 在内核中发生了 Trap，只处理中断，目前还不支持抢占，因此是否有任务被打断是不做处理的
            trap_from_kernel();
            return;
        } else {
            // debug!("into trampoline from taskcount:{},task",get_task_count());
            // 用户态发生了 Trap 或者需要调度
            if let Some(curr) = current_task().or_else(|| {
                if let Some(task) = pick_next_task() {
                    unsafe {
                        CurrentTask::init_current(task.clone());
                         
                        //  debug!("get and init next task");

                    }
                    Some(task)
                } else {
                    None
                }
            }) {
 debug!("run_task pid:{},Arc count:{}",curr.pid.0,
                  
                   Arc::strong_count(&curr)
                       );
                run_task2(CurrentTask::from(curr));
            } else {
                enable_irqs();
                debug!("no tasks available in run_tasks");

                wait_for_irqs();
            }
        }
    }
}
///a future to handle user trap
/// IMPO
pub async fn user_task_top() -> i32 {
    loop {

        // debug!("into user_task_top");
        let curr = current_task().unwrap();
        let inner = curr.inner_exclusive_access();
        let  tf =  inner.trap_cx.get();
        drop(inner);
        // debug!("trap_status:{:?}",tf.trap_status);
        if (unsafe { (*tf) .trap_status })== TrapStatus::Blocked {
            let scause = scause::read();
    let stval = stval::read();
    let sepc = sepc::read();
    trace!(
        "Trap: cause={:?}, addr={:#x}, sepc={:#x}, satp={:#x}",
        scause.cause(),
        stval,
        sepc,
        satp::read().bits()
    );
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            enable_irqs();
            let syscall_id;
            let args;
unsafe {
             syscall_id = (*tf).regs.a7;
 args = [(*tf).regs.a0, (*tf).regs.a1, (*tf).regs.a2, (*tf).regs.a3];

(*tf).sepc += 4;

}
let result = syscall(syscall_id, args).await;

trace!("sys_call end");

    let tf = current_task_trapctx_ptr();
           unsafe {
               (*tf).regs.a0 = result as usize;
           } 

trace!("sys_call end1");
        }
        Trap::Exception(Exception::StoreFault)
        | Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::InstructionFault)
        | Trap::Exception(Exception::InstructionPageFault)
        | Trap::Exception(Exception::LoadFault)
        | Trap::Exception(Exception::LoadPageFault) => {
            
            println!(
                "[kernel] trap_handler:  {:?} in application, bad addr = {:#x}, bad instruction = {:#x}, kernel killed it.",
                scause.cause(),
                stval,
                unsafe { (*tf).sepc },
            );
           
            // page fault exit code

            exit_current_and_run_next(-2);
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            println!("[kernel] IllegalInstruction in application, kernel killed it.");
            // illegal instruction exit code
            exit_current_and_run_next(-3);
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            suspend_current_and_run_next();
        }
        _ => {
            panic!(
                "Unsupported trap {:?}, stval = {:#x}!",
                scause.cause(),
                stval
            );
        }
    }
           
           let tf=current_task_trapctx_ptr();

            unsafe { (*tf).trap_status = TrapStatus::Done };
            trace!("sys_call end3");
            // 判断任务是否退出
            let curr= current_task().unwrap();
            let inner =curr.inner_exclusive_access();

            trace!("sys_call end4");
            if inner.is_zombie() {
                // 任务结束，需要切换至其他任务，关中断
                disable_irqs();
                // info!("return ready");
                return inner.exit_code ;
            }
            drop(inner);
        }

            trace!("sys_call end5");
        
           let tf=current_task_trapctx_ptr();
        //偶数次poll时会从重新运行这个函数开始
        poll_fn(|_cx| {
            if (unsafe { (*tf) .trap_status })== TrapStatus::Done {
                Poll::Pending
            } else {

                Poll::Ready(0)

            }
        })
        .await ;
  
    }
}
