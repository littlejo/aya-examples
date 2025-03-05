use aya_ebpf::{
    macros::map,
    maps::{PerCpuArray, HashMap, ProgramArray},
};

use tracepoint_binary_common::MAX_PATH_LEN;

#[map]
pub static BUF: PerCpuArray<[u8; MAX_PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static EXCLUDED_CMDS: HashMap<[u8; 512], u8> = HashMap::with_max_entries(10, 0);

#[map]
pub static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);
