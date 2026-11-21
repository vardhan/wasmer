use super::*;
use crate::syscalls::*;

pub fn resolve_to_pipe<M: MemorySize>(
    ctx: FunctionEnvMut<'_, WasiEnv>,
    host: WasmPtr<u8, M>,
    len: M::Offset,
    output: WasiFd,
) -> Errno {
    let env = ctx.data();
    let mem = unsafe { env.memory_view(&ctx) };
    let name = match host.read_utf8_string(&mem, len) {
        Ok(name) => name,
        Err(_) => return Errno::Inval,
    };
    let fd = wasi_try!(env.state.fs.get_fd(output));
    if !fd.inner.rights.contains(Rights::FD_WRITE) {
        return Errno::Access;
    }
    let mut tx = match &*fd.inode.read() {
        Kind::PipeTx { tx } => tx.clone(),
        _ => return Errno::Badf,
    };
    let net = env.net().clone();
    let task = env.tasks().task_shared(Box::new(move || {
        Box::pin(async move {
            let result = tokio::select! {
                result = net.resolve(&name,None,None) => result,
                _ = tx.reader_closed() => return,
            };
            let mut reply = Vec::new();
            match result {
                Ok(addrs) if addrs.len() > 65536 => {
                    reply.extend_from_slice(&(Errno::Overflow as u16).to_le_bytes())
                }
                Ok(addrs) => {
                    reply.extend_from_slice(&0u16.to_le_bytes());
                    for addr in addrs {
                        match addr {
                            std::net::IpAddr::V4(v) => {
                                reply.push(4);
                                reply.extend_from_slice(&v.octets());
                            }
                            std::net::IpAddr::V6(v) => {
                                reply.push(6);
                                reply.extend_from_slice(&v.octets());
                            }
                        }
                    }
                }
                Err(err) => {
                    reply.extend_from_slice(&(net_error_into_wasi_err(err) as u16).to_le_bytes())
                }
            }
            let _ = std::io::Write::write_all(&mut tx, &reply);
        })
    }));
    if task.is_err() {
        Errno::Again
    } else {
        Errno::Success
    }
}

/// ### `resolve()`
/// Resolves a hostname and a port to one or more IP addresses.
///
/// Note: This is similar to `getaddrinfo` in POSIX
///
/// When successful, the contents of the output buffer consist of a sequence of
/// IPv4 and/or IPv6 addresses. Each address entry consists of a addr_t object.
/// This function fills the output buffer as much as possible.
///
/// ## Parameters
///
/// * `host` - Host to resolve
/// * `port` - Port hint (zero if no hint is supplied)
/// * `addrs` - The buffer where addresses will be stored
///
/// ## Return
///
/// The number of IP addresses returned during the DNS resolution.
#[instrument(level = "trace", skip_all, fields(host = field::Empty, %port), ret)]
pub fn resolve<M: MemorySize>(
    mut ctx: FunctionEnvMut<'_, WasiEnv>,
    host: WasmPtr<u8, M>,
    host_len: M::Offset,
    port: u16,
    addrs: WasmPtr<__wasi_addr_t, M>,
    naddrs: M::Offset,
    ret_naddrs: WasmPtr<M::Offset, M>,
) -> Result<Errno, WasiError> {
    WasiEnv::do_pending_operations(&mut ctx)?;

    let naddrs: usize = wasi_try_ok!(naddrs.try_into().map_err(|_| Errno::Inval));
    let mut env = ctx.data();
    let host_str = {
        let memory = unsafe { env.memory_view(&ctx) };
        unsafe { get_input_str_ok!(&memory, host, host_len) }
    };
    Span::current().record("host", host_str.as_str());

    let port = if port > 0 { Some(port) } else { None };

    let net = env.net().clone();
    let tasks = env.tasks().clone();
    let found_ips = wasi_try_ok!(__asyncify(&mut ctx, None, async move {
        net.resolve(host_str.as_str(), port, None)
            .await
            .map_err(net_error_into_wasi_err)
    })?);
    env = ctx.data();

    let mut idx = 0;
    let memory = unsafe { env.memory_view(&ctx) };
    let addrs = wasi_try_mem_ok!(addrs.slice(&memory, wasi_try_ok!(to_offset::<M>(naddrs))));
    for found_ip in found_ips.iter().take(naddrs) {
        crate::net::write_ip(&memory, addrs.index(idx).as_ptr::<M>(), *found_ip);
        idx += 1;
    }

    let idx: M::Offset = wasi_try_ok!(idx.try_into().map_err(|_| Errno::Overflow));
    wasi_try_mem_ok!(ret_naddrs.write(&memory, idx));

    Ok(Errno::Success)
}
