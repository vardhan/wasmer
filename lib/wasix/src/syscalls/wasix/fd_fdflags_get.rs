use super::*;
use crate::syscalls::*;

impl virtual_fs::LockProcess for crate::os::task::OwnedTaskStatus {
    fn running(&self) -> bool {
        !self.status().is_finished()
    }
}

/// A nonblocking advisory lock. The guest can park between attempts while
/// the lock lifetime is governed by the host descriptor table.
pub fn fd_flock(ctx: FunctionEnvMut<'_, WasiEnv>, fd: WasiFd, op: u32) -> Errno {
    let state = ctx.data().get_wasi_state();
    let entry = wasi_try!(state.fs.get_fd(fd));
    let inode = entry.inode.read();
    let Kind::File {
        handle: Some(handle),
        ..
    } = &*inode
    else {
        return Errno::Notsup;
    };
    let file = handle.read().unwrap();
    let process: std::sync::Arc<dyn virtual_fs::LockProcess> = ctx.data().process.finished.clone();
    match file.try_advisory_lock(
        std::sync::Arc::downgrade(&entry.inner.offset),
        std::sync::Arc::downgrade(&process),
        op,
    ) {
        Ok(()) => Errno::Success,
        Err(err) => fs_error_into_wasi_err(err),
    }
}

/// ### `fd_fdstat_get()`
/// Get metadata of a file descriptor
/// Input:
/// - `Fd fd`
///     The file descriptor whose metadata will be accessed
/// Output:
/// - `Fdstat *buf`
///     The location where the metadata will be written
#[instrument(level = "trace", skip_all, fields(%wasi_fd), ret)]
pub fn fd_fdflags_get<M: MemorySize>(
    ctx: FunctionEnvMut<'_, WasiEnv>,
    wasi_fd: WasiFd,
    buf_ptr: WasmPtr<Fdflagsext, M>,
) -> Errno {
    let env = ctx.data();
    let (memory, state) = unsafe { env.get_memory_and_wasi_state(&ctx, 0) };
    let fd = wasi_try!(state.fs.get_fd(wasi_fd));

    let buf = buf_ptr.deref(&memory);

    wasi_try_mem!(buf.write(fd.inner.fd_flags));

    Errno::Success
}
