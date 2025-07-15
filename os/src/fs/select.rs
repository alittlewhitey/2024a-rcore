const FD_SETSIZE: usize = 1024;
const BITS_PER_LONG: usize = 64;
const LONGS_FOR_FDS: usize = (FD_SETSIZE + BITS_PER_LONG - 1) / BITS_PER_LONG;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdSet {
    pub fds_bits: [u64; LONGS_FOR_FDS],
}

impl FdSet {
    // 辅助函数，用于检查、设置、清除某个 fd
    pub fn is_set(&self, fd: usize) -> bool {
        if fd >= FD_SETSIZE { return false; }
        let word = fd / BITS_PER_LONG;
        let bit = fd % BITS_PER_LONG;
        (self.fds_bits[word] & (1 << bit)) != 0
    }

    pub fn set(&mut self, fd: usize) {
        if fd >= FD_SETSIZE { return; }
        let word = fd / BITS_PER_LONG;
        let bit = fd % BITS_PER_LONG;
        self.fds_bits[word] |= 1 << bit;
    }

    pub fn clear(&mut self, fd: usize) {
        if fd >= FD_SETSIZE { return; }
        let word = fd / BITS_PER_LONG;
        let bit = fd % BITS_PER_LONG;
        self.fds_bits[word] &= !(1 << bit);
    }
    
    pub fn zero(&mut self) {
        self.fds_bits.iter_mut().for_each(|x| *x = 0);
    }
}

impl Default for FdSet {
    fn default() -> Self {
        Self { fds_bits: [0; LONGS_FOR_FDS] }
    }
}

use crate::fs::{File, FileDescriptor, PollEvents};
use crate::mm::put_data;
use crate::signal::{SigSet,  SigMaskHow}; // 假设的信号模块
use crate::task::current_process;
use crate::task::sleeplist::{sleep_until, SleepFuture, WakeReason};
use crate::timer::{get_time, get_time_ns, get_time_us, get_usertime, usertime2_timeval, UserTimeSpec};
use crate::utils::error::{SysErrNo, SyscallRet};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use alloc::vec::Vec;
use alloc::sync::Arc;

pub struct PSelectFuture {
    pub fds_to_check: Vec<(usize,FileDescriptor)>,
    pub user_readfds: *mut FdSet,
    pub user_writefds: *mut FdSet,
    pub user_exceptfds: *mut FdSet,
    timeout_sleep_instance: Option<SleepFuture>,
    pub page_table_token: usize,
}
impl PSelectFuture {
    /// 创建一个新的 PSelectFuture 实例。
    ///
    /// # Arguments
    /// * `timeout_deadline`: 一个 `Option<TimeVal>`。
    ///   - `Some(deadline)`: 表示一个具体的超时截止时间。
    ///   - `None`: 表示无限等待。
    pub fn new(
        fds_to_check: Vec<(usize, FileDescriptor)>,
        user_readfds: *mut FdSet,
        user_writefds: *mut FdSet,
        user_exceptfds: *mut FdSet,
        page_table_token: usize,
        timeout_deadline: Option<UserTimeSpec>,
    ) -> Self {
        // 如果提供了超时，则创建一个 SleepFuture。
        // 如果 timeout_deadline 是 None（无限等待），我们依然可以创建一个
        // SleepFuture，sleep_until(None) 会返回一个永远 Pending 的 Future。
        // 这样可以统一处理逻辑，避免在 poll 中对 None 进行特殊判断。
        let sleep_instance = Some(sleep_until(timeout_deadline.map(|f|usertime2_timeval(&f))));

        Self {
            fds_to_check,
            user_readfds,
            user_writefds,
            user_exceptfds,
            page_table_token,
            timeout_sleep_instance: sleep_instance,
        }
    }
    fn write_results_to_user(
        &self,
        readfds: FdSet,
        writefds: FdSet,
        exceptfds: FdSet
    ) -> Result<(), SysErrNo> {
        if !self.user_readfds.is_null() {
            put_data(self.page_table_token, self.user_readfds, readfds)?;
        }
        if !self.user_writefds.is_null() {
            put_data(self.page_table_token, self.user_writefds, writefds)?;
        }
        if !self.user_exceptfds.is_null() {
            put_data(self.page_table_token, self.user_exceptfds, exceptfds)?;
        }
        Ok(())
    }
}
impl Future for PSelectFuture {
    type Output = Result<usize, SysErrNo>; // pselect 返回 Result<count, error>

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        let mut ready_count = 0;
        let mut result_readfds = FdSet::default();
        let mut result_writefds = FdSet::default();
        let mut result_exceptfds = FdSet::default();

        // 1. 检查所有文件描述符的状态
        for (fd, file) in &this.fds_to_check {
            let revents = file.poll(PollEvents::all(), cx.waker());
            let mut is_ready_this_fd = false;

            if revents.intersects(PollEvents::POLLIN) && !this.user_readfds.is_null() {
                result_readfds.set(*fd);
                is_ready_this_fd = true;
            }
            if revents.intersects(PollEvents::POLLOUT) && !this.user_writefds.is_null() {
                result_writefds.set(*fd);
                is_ready_this_fd = true;
            }
            if revents.intersects(PollEvents::POLLPRI) && !this.user_exceptfds.is_null() {
                result_exceptfds.set(*fd);
                is_ready_this_fd = true;
            }
            if revents.intersects(PollEvents::POLLERR | PollEvents::POLLHUP | PollEvents::POLLNVAL) {
                if !this.user_readfds.is_null() { result_readfds.set(*fd); }
                if !this.user_writefds.is_null() { result_writefds.set(*fd); }
                if !this.user_exceptfds.is_null() { result_exceptfds.set(*fd); }
                is_ready_this_fd = true;
            }

            if is_ready_this_fd {
                ready_count += 1;
            }
        }

        if ready_count > 0 {
            return match this.write_results_to_user(result_readfds, result_writefds, result_exceptfds) {
                Ok(_) => Poll::Ready(Ok(ready_count)),
                Err(e) => Poll::Ready(Err(e)),
            };
        }

        // 2. 没有立即就绪的 fd，检查是否超时
        if let Some(sleep_future) = &mut this.timeout_sleep_instance {
            let pinned_sleep = Pin::new(sleep_future);

            match pinned_sleep.poll(cx) {
                Poll::Ready(reason) => {
                    match reason {
                        WakeReason::Timeout => {
                            info!("[PSelectFuture Ready]: Timeout expired.");
                            let zero_fds = FdSet::default();
                            return match this.write_results_to_user(zero_fds, zero_fds, zero_fds) {
                                Ok(_) => Poll::Ready(Ok(0)),
                                Err(e) => Poll::Ready(Err(e)),
                            };
                        }
                        WakeReason::SignalInterrupted => {
                            info!("[PSelectFuture Ready]: Interrupted by signal.");
                            return Poll::Ready(Err(SysErrNo::ERESTART));
                        }
                        WakeReason::None => {
                            // 理论上不应触发，说明被默认唤醒，保守起见直接返回 Ok(0)
                            error!("[PSelectFuture Ready]: Spurious wakeup (None).");
                            let zero_fds = FdSet::default();
                            return match this.write_results_to_user(zero_fds, zero_fds, zero_fds) {
                                Ok(_) => Poll::Ready(Ok(0)),
                                Err(e) => Poll::Ready(Err(e)),
                            };
                        }
                        _ => {
                            unreachable!("Unexpected WakeReason in PSelectFuture");
                        }
                    }
                }
                Poll::Pending => {
                    // 继续等待
                }
            }
        }

        info!("[PSelectFuture Pending]: No FDs ready, waiting for events or timeout.");
        Poll::Pending
    }
}