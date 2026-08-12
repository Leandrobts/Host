// PS4 13.52 — slopkit method
// webkitBase = __ps5NativeCtor - OFFSET_wk_host_constructor_candidates

const OFFSET_wk_host_constructor_candidates = [0x36F9E20];

// Preencher os demais quando tiver o dump:
const OFFSET_wk_memset_import = 0x0;         // TODO
const OFFSET_wk___stack_chk_guard_import = 0x0; // TODO
const OFFSET_lc_memset = 0x0;                // TODO
const OFFSET_lk___stack_chk_guard = 0x0;     // TODO
const OFFSET_lk_getpid = 0x00010E4D;         // já tinha

let wk_gadgetmap = {};
let syscall_map = {};
