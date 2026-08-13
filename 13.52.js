// PS4 13.52 — Offsets para slopkit method
// Confirmado via duas runs com ASLR diferente:
//   __ps5NativeCtor=0x8036F9E20 → base=0x800000000
//   __ps5NativeCtor=0x81CBF9E20 → base=0x819500000
// Offset fixo: 0x36F9E20 (~55.5 MB)

const OFFSET_wk_host_constructor_candidates = [
    0x36F9E20   // ← OFFSET CONFIRMADO do __ps5NativeCtor
];

// TODO: preencher quando tiver o dump do eboot.bin
const OFFSET_wk_vtable_first_element = 0x0;
const OFFSET_wk_memset_import = 0x0;
const OFFSET_wk___stack_chk_guard_import = 0x0;
const OFFSET_lc_memset = 0x0;
const OFFSET_lk___stack_chk_guard = 0x0;

const OFFSET_lk_pthread_create_name_np = 0x0;
const OFFSET_lk_pthread_join = 0x0;
const OFFSET_lk_pthread_exit = 0x0;
const OFFSET_lk_scePthreadCreate = 0x0;
const OFFSET_lk_scePthreadJoin = 0x0;
const OFFSET_lk_scePthreadAttrInit = 0x0;
const OFFSET_lk_scePthreadAttrSetstacksize = 0x0;
const OFFSET_lk_scePthreadAttrSetdetachstate = 0x0;
const OFFSET_lk_scePthreadAttrDestroy = 0x0;
const OFFSET_lk_sceKernelSendNotificationRequest = 0x0;
const OFFSET_lk_sysctlbyname = 0x0;
const OFFSET_lk_pthread_create = 0x0;
const OFFSET_lk_getpid = 0x0;
const OFFSET_lk__thread_list = 0x0;
const OFFSET_lk_worker_wait_return = 0x0;
const OFFSET_lk_sleep = 0x0;
const OFFSET_lk_sceKernelGetCurrentCpu = 0x0;
const OFFSET_lk_sceKernelDlsym = 0x0;
const OFFSET_lc_malloc = 0x0;
const OFFSET_lc_free = 0x0;
const OFFSET_lc_memcpy = 0x0;
const OFFSET_lc_strcmp = 0x0;
const OFFSET_lc_memcmp = 0x0;
const OFFSET_lc_vsnprintf = 0x0;
const OFFSET_lc_setjmp = 0x0;
const OFFSET_lc_longjmp = 0x0;
const OFFSET_WORKER_STACK_OFFSET = 0x0;

let wk_gadgetmap = {};
let syscall_map = {};
