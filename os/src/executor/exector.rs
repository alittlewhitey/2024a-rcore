//!Implementation of [`Processor`] and Intersection of control flow
//!
//! Here, the continuous operation of user apps in CPU is maintained,
//! the current running state of CPU is recorded,
//! and the replacement and transfer of control flow of different applications are executed.


use core::sync::atomic::AtomicU64;

use crate::config;
use crate::fs::File;
use crate::mm::MemorySet;
use crate::task::{PidHandle, RecycleAllocator, TaskContext, TaskControlBlock};
use crate::sync::UPSafeCell;
use crate::trap::TrapContext;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use lazy_static::*;

/// Processor management structure
pub struct Processor {
    ///The task currently executing on the current processor
    current: Option<Arc<TaskControlBlock>>,

    ///The basic control flow of each core, helping to select and switch process
    idle_task_cx: TaskContext,
}
pub struct ProcessControlBlock {
    // immutable
    pub pid: PidHandle,
    // mutable
    inner: UPSafeCell<ProcessControlBlockInner>,
}
pub struct ProcessControlBlockInner {
    pub is_zombie: bool,
    pub memory_set: Arc<MemorySet>,
    pub parent: Option<Weak<ProcessControlBlock>>,
    pub children: Vec<Arc<ProcessControlBlock>>,
    pub exit_code: i32,
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    // pub signals: SignalFlags,
    pub tasks: Vec<Option<Arc<TaskControlBlock>>>,
    pub task_res_allocator: RecycleAllocator,
   /// 用户堆基址，任何时候堆顶都不能比这个值小，理论上讲是一个常量
    pub heap_bottom: AtomicU64,
    /// 当前用户堆的堆顶，不能小于基址，不能大于基址加堆的最大大小
    pub heap_top: AtomicU64,

    pub stack_size: AtomicU64,
    pub main_task: Option<TaskControlBlock>,
}

impl ProcessControlBlockInner {
    /// 创建一个新的 Executor（进程）
    pub fn new(
        parent: Option<Weak<ProcessControlBlock>>,
        memory_set: Arc<MemorySet>,
        heap_bottom: u64,
        fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    ) -> Self {
        // let mut scheduler = Scheduler::new();
        // scheduler.init();
        Self {
            parent,
            children: Vec::new(),
            // scheduler: Arc::new(SpinNoIrq::new(scheduler)),
            fd_table,
            is_zombie:false,
            exit_code: 0,
            memory_set,
            heap_bottom: AtomicU64::new(heap_bottom),
            heap_top: AtomicU64::new(heap_bottom),
            stack_size: AtomicU64::new(config::TASK_STACK_SIZE as _),
            main_task: None,
            tasks: Vec::new(),
            task_res_allocator:RecycleAllocator::new(),
        }
    }
}













// lazy_static! {
//     pub static ref PROCESSOR: UPSafeCell<Processor> = unsafe { UPSafeCell::new(Processor::new()) };
// }

//The main part of process execution and scheduling
//Loop `fetch_task` to get the process that needs to run, and switch the process through `__switch`
// pub fn run_tasks() {
//     loop {
//         let mut processor = PROCESSOR.exclusive_access();
//         if let Some(task) = fetch_task() {
//             let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
//             // access coming task TCB exclusively
//             let mut task_inner = task.inner_exclusive_access();
//             let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
//             task_inner.task_status = TaskStatus::Running;

//             task_inner.memory_set.activate();
//             // release coming task_inner manually
//             trace!("taskcontext.ra:{:#x},sp:{:#x}",unsafe {
//                (*next_task_cx_ptr).ra
//             },unsafe {
//                (*next_task_cx_ptr).sp
//             });
//             drop(task_inner);
//             // release coming task TCB manually
//             processor.current = Some(task);

//             // release processor manually
//             drop(processor);
//             unsafe {
//                 __switch(idle_task_cx_ptr, next_task_cx_ptr);
//             }
//         } else {
//             warn!("no tasks available in run_tasks");
//         }
//     }
// }

// /// Get current task through take, leaving a None in its place
// pub fn take_current_task() -> Option<Arc<TaskControlBlock>> {
//     PROCESSOR.exclusive_access().take_current()
// }

// /// Get a copy of the current task
// pub fn current_task() -> Option<Arc<TaskControlBlock>> {
//     PROCESSOR.exclusive_access().current()
// }

// /// Get the current user token(addr of page table)
// pub fn current_user_token() -> usize {
//     let task = current_task().unwrap();
//     task.get_user_token()
// }

// ///Get the mutable reference to trap context of current task
// pub fn current_trap_cx() -> &'static mut TrapContext {
//     current_task()
//         .unwrap()
//         .inner_exclusive_access()
//         .get_trap_cx()
// }

// ///Return to idle control flow for new scheduling
// pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
//     let mut processor = PROCESSOR.exclusive_access();
//     let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
//     drop(processor);
//     unsafe {
//         __switch(switched_task_cx_ptr, idle_task_cx_ptr);
//     }
// }