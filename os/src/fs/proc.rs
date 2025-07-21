use alloc::collections::BTreeMap;
use spin::Lazy;
use spin::RwLock;
use crate::fs::{async_trait,String,File,Kstat,Arc,get_syscall_count_string};
use crate::mm::UserBuffer;
use crate::utils::error::{SysErrNo,TemplateRet,SyscallRet};
use crate::Box;
pub struct ProcFile {
    content_fn: fn() -> String,
    mode: u32,
    offset: RwLock<usize>,
}

impl ProcFile {
    pub fn new(content_fn: fn() -> String, mode: u32) -> Self {
        Self { content_fn, mode, offset: RwLock::new(0),}
    }
}
#[async_trait]
impl File for ProcFile {
    async fn read<'a>(&self, mut buf: UserBuffer<'a>) -> Result<usize, SysErrNo> {
        let content = (self.content_fn)();
        let bytes = content.as_bytes();
        let mut offset = self.offset.write();
        if *offset >= bytes.len() {
            return Ok(0);
        }
        let len = core::cmp::min(buf.len(), bytes.len());
        if len > 0 {
            buf.write(&bytes[..len]);
            *offset += len;
        }
        Ok(len)
    }

    fn fstat(&self) -> Kstat {
        Kstat {
            st_mode: self.mode,
            st_nlink: 1,
            st_size: (self.content_fn)().len() as isize,
            ..Default::default()
        }
    }

    fn lseek(&self, offset: isize, whence: u32) -> SyscallRet {
        let mut current_offset = self.offset.write();
        let file_size = (self.content_fn)().len();

        const SEEK_SET: usize = 0;
        const SEEK_CUR: usize = 1;
        const SEEK_END: usize = 2;

        let new_offset = match whence as usize {
            SEEK_SET => offset,
            SEEK_CUR => *current_offset as isize + offset,
            SEEK_END => file_size as isize + offset,
            _ => return Err(SysErrNo::EINVAL),
        };

        if new_offset < 0 {
            return Err(SysErrNo::EINVAL);
        }
        *current_offset = new_offset as usize;
        Ok(new_offset as usize)
    }

    fn readable<'a>(&'a self) -> TemplateRet<bool> {
        Ok(true)
    }

    fn writable<'a>(&'a self) -> TemplateRet<bool> {
        Ok(false)
    }
}
static PROC_FILES: Lazy<RwLock<BTreeMap<&'static str, Arc<dyn File>>>> =
    Lazy::new(|| RwLock::new(BTreeMap::new()));

pub fn register_proc_file(path: &'static str, file: Arc<dyn File>) {
    PROC_FILES.write().insert(path, file);
}
pub fn open_proc_file(path: &str) -> Option<Arc<dyn File>> {
    PROC_FILES.read().get(path).map(Arc::clone)
}