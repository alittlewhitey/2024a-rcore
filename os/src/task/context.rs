//! Implementation of [`TaskContext`]


use crate::trap::trap_loop;
use core::fmt;
impl fmt::Debug for TaskContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskContext")
            .field("ra", &format_args!("{:x}", self.ra))
            .field("sp", &format_args!("{:x}", self.sp))     
            .finish()
    }
}

#[repr(C)]
/// task context structure containing some registers
pub struct TaskContext {
    /// Ret position after task switching
    pub ra: usize,
    /// Stack pointer
    pub sp: usize,
    /// s0-11 register, callee saved
    s: [usize; 12],
}

impl TaskContext {
    /// Create a new empty task context
    pub fn zero_init() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: [0; 12],
        }
    }
    /// Create a new task context with a trap return addr and a kernel stack pointer
    pub fn goto_trap_return(kstack_ptr: usize) -> Self {
        Self {
            ra: trap_loop as usize,
            sp: kstack_ptr,
            s: [0; 12],
        }
    }
}
