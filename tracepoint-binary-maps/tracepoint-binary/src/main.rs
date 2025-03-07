use aya::{maps::HashMap, programs::TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

mod constant;
use crate::constant::EXCLUDE_LIST;

use tracepoint_binary_common::MAX_PATH_LEN;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tracepoint-binary"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut TracePoint = ebpf.program_mut("tracepoint_binary").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let map = ebpf.map_mut("EXCLUDED_CMDS").unwrap();
    let mut excluded_cmds: HashMap<_, [u8; MAX_PATH_LEN], u8> = HashMap::try_from(map)?;
    for cmd in EXCLUDE_LIST.iter() {
        let key = cmd_to_key(cmd);
        excluded_cmds.insert(key, 1, 0)?;
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn cmd_to_key(cmd: &str) -> [u8; MAX_PATH_LEN] {
    let mut key = [0u8; MAX_PATH_LEN];
    let bytes = cmd.as_bytes();
    key[..bytes.len()].copy_from_slice(bytes);
    key
}
