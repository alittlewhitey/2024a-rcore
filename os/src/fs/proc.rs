use crate::fs::{async_trait, format, Arc, File, Kstat, String};
use crate::mm::UserBuffer;
use crate::utils::error::{SysErrNo, SyscallRet, TemplateRet};
use crate::Box;
use alloc::collections::BTreeMap;
use spin::Lazy;
use spin::RwLock;
pub struct ProcFile {
    pub name: String,
    pub content_fn: fn() -> String,
    pub mode: u32,
    // 这里不再保存 offset
}

// 代表打开的文件描述符，每个打开都会有自己的实例
pub struct ProcFileHandle {
    pub file: Arc<ProcFile>,
    offset: RwLock<usize>, // 每个fd单独维护偏移
}

impl ProcFileHandle {
    pub fn new(file: Arc<ProcFile>) -> Self {
        Self {
            file,
            offset: RwLock::new(0),
        }
    }
}

#[async_trait]
impl File for ProcFileHandle {
    async fn read<'a>(&self, mut buf: UserBuffer<'a>) -> Result<usize, SysErrNo> {
        let content = (self.file.content_fn)();
        let bytes = content.as_bytes();

        let mut offset = self.offset.write();
        if *offset >= bytes.len() {
            return Ok(0);
        }
        let len = core::cmp::min(buf.len(), bytes.len() - *offset);
        if len > 0 {
            buf.write(&bytes[*offset..*offset + len]);
            *offset += len;
        }
        Ok(len)
    }

    fn fstat(&self) -> Kstat {
        Kstat {
            st_mode: self.file.mode,
            st_nlink: 1,
            st_size: (self.file.content_fn)().len() as isize,
            ..Default::default()
        }
    }

    fn lseek(&self, offset: isize, whence: u32) -> SyscallRet {
        let mut current_offset = self.offset.write();
        let file_size = (self.file.content_fn)().len();

        const SEEK_SET: usize = 0;
        const SEEK_CUR: usize = 1;
        const SEEK_END: usize = 2;

        let new_offset = match whence as usize {
            SEEK_SET => offset,
            SEEK_CUR => *current_offset as isize + offset,
            SEEK_END => file_size as isize + offset,
            _ => return Err(SysErrNo::EINVAL),
        };

        if new_offset < 0 || new_offset as usize > file_size {
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

    fn get_path(&self) -> String {
        format!("/proc/{}", self.file.name)
    }
}
static PROC_FILES: Lazy<RwLock<BTreeMap<&'static str, Arc<ProcFile>>>> =
    Lazy::new(|| RwLock::new(BTreeMap::new()));

pub fn register_proc_file(path: &'static str, file: Arc<ProcFile>) {
    PROC_FILES.write().insert(path, file);
}
pub fn open_proc_file(path: &str) -> Option<Arc<ProcFileHandle>> {
    PROC_FILES
        .read()
        .get(path)
        .map(|file| Arc::new(ProcFileHandle::new(Arc::clone(file))))
}
