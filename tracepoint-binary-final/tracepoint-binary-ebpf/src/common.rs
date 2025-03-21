use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, ProgramArray},
    programs::TracePointContext,
};

use aya_log_ebpf::error;

use tracepoint_binary_common::MAX_PATH_LEN;

#[repr(C)]
pub struct ProgramState {
    pub t_enter: u64,
    pub t_exit: u64,
    pub buffer: [u8; MAX_PATH_LEN],
    pub ret: i64,
}

pub const ZEROED_ARRAY: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];

#[map]
pub static PROGRAM: LruHashMap<u32, ProgramState> = LruHashMap::with_max_entries(16, 0);

#[map]
pub static EXCLUDED_CMDS: HashMap<[u8; 512], u8> = HashMap::with_max_entries(10, 0);

#[map]
pub static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[inline(always)]
pub fn try_tail_call(ctx: &TracePointContext, index: u32) {
    let res = unsafe { JUMP_TABLE.tail_call(ctx, index) };
    if res.is_err() {
        error!(ctx, "exit: tail_call failed");
    }
}
